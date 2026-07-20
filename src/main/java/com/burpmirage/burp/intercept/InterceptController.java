package com.burpmirage.burp.intercept;

import burp.api.montoya.logging.Logging;
import com.burpmirage.burp.model.ExtensionSettings;
import com.burpmirage.burp.model.InterceptedPacket;
import com.burpmirage.burp.model.PacketDirection;
import com.burpmirage.burp.util.HexUtils;

import java.util.Base64;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

/**
 * Coordinates intercept decisions between Frida bridge and the UI.
 */
public final class InterceptController {
    private final ExtensionSettings settings;
    private final PacketQueue queue;
    private final HistoryStore history;
    private final Logging logging;
    private final ConcurrentHashMap<String, CompletableFuture<BridgeResponse>> waiting = new ConcurrentHashMap<>();

    private volatile Consumer<InterceptedPacket> uiPresenter = p -> {};
    private volatile String attachedProcessName = "";

    public record BridgeResponse(String action, String dataBase64) {
    }

    public InterceptController(
            ExtensionSettings settings,
            PacketQueue queue,
            HistoryStore history,
            Logging logging
    ) {
        this.settings = settings;
        this.queue = queue;
        this.history = history;
        this.logging = logging;
    }

    public void setUiPresenter(Consumer<InterceptedPacket> uiPresenter) {
        this.uiPresenter = uiPresenter != null ? uiPresenter : p -> {};
    }

    public void setAttachedProcessName(String name) {
        this.attachedProcessName = name == null ? "" : name;
    }

    public String attachedProcessName() {
        return attachedProcessName;
    }

    /**
     * Called by BridgeServer when Frida reports a packet.
     * Blocks (via future) until Forward/Drop, or auto-forwards when intercept is off.
     */
    public BridgeResponse handleIncomingPacket(
            String id,
            int pid,
            String direction,
            String api,
            String peer,
            int fd,
            byte[] data
    ) {
        PacketDirection dir = PacketDirection.fromWire(direction);
        if (dir == PacketDirection.SEND && !settings.hookSend()) {
            return new BridgeResponse("forward", Base64.getEncoder().encodeToString(data));
        }
        if (dir == PacketDirection.RECV && !settings.hookRecv()) {
            return new BridgeResponse("forward", Base64.getEncoder().encodeToString(data));
        }
        if (settings.autoForwardEmpty() && (data == null || data.length == 0)) {
            return new BridgeResponse("forward", "");
        }

        InterceptedPacket packet = new InterceptedPacket(
                id,
                null,
                pid,
                attachedProcessName,
                dir,
                api,
                peer,
                fd,
                data
        );

        if (!settings.interceptEnabled()) {
            packet.setStatus(InterceptedPacket.PacketStatus.AUTO);
            history.add(packet);
            return new BridgeResponse("forward", Base64.getEncoder().encodeToString(packet.data()));
        }

        CompletableFuture<BridgeResponse> future = new CompletableFuture<>();
        waiting.put(packet.id(), future);

        queue.enqueue(packet, (decision, maybeModified) -> {
            if (decision.action() == PacketQueue.InterceptDecision.Action.DROP) {
                packet.setStatus(InterceptedPacket.PacketStatus.DROPPED);
                history.add(packet);
                future.complete(new BridgeResponse("drop", ""));
            } else {
                if (maybeModified != null) {
                    packet.setData(maybeModified);
                }
                packet.setStatus(InterceptedPacket.PacketStatus.FORWARDED);
                history.add(packet);
                future.complete(new BridgeResponse(
                        "forward",
                        Base64.getEncoder().encodeToString(packet.data())
                ));
            }
            waiting.remove(packet.id());
        });

        PacketQueue.PendingPacket head = queue.current();
        if (head != null && packet.id().equals(head.packet().id())) {
            try {
                uiPresenter.accept(packet);
            } catch (Exception e) {
                logging.logToError("UI present failed: " + e.getMessage());
            }
        }

        try {
            return future.get(120, TimeUnit.SECONDS);
        } catch (Exception e) {
            waiting.remove(packet.id());
            packet.setStatus(InterceptedPacket.PacketStatus.AUTO);
            history.add(packet);
            logging.logToOutput("Intercept timeout for " + packet.id() + " — auto-forward");
            return new BridgeResponse("forward", Base64.getEncoder().encodeToString(packet.data()));
        }
    }

    public void forwardCurrent(byte[] editedData) {
        PacketQueue.PendingPacket pending = queue.current();
        if (pending == null) {
            return;
        }
        pending.callback().complete(
                new PacketQueue.InterceptDecision(PacketQueue.InterceptDecision.Action.FORWARD, editedData),
                editedData
        );
        queue.advanceAfterDecision();
        presentNext(queue.current());
    }

    public void dropCurrent() {
        PacketQueue.PendingPacket pending = queue.current();
        if (pending == null) {
            return;
        }
        pending.callback().complete(
                new PacketQueue.InterceptDecision(PacketQueue.InterceptDecision.Action.DROP, null),
                null
        );
        queue.advanceAfterDecision();
        presentNext(queue.current());
    }

    private void presentNext(PacketQueue.PendingPacket next) {
        if (next != null) {
            try {
                uiPresenter.accept(next.packet());
            } catch (Exception e) {
                logging.logToError("UI present failed: " + e.getMessage());
            }
        }
    }

    public byte[] applySearchReplace(byte[] data) {
        String search = settings.searchPattern();
        String replace = settings.replacePattern();
        if (search == null || search.isBlank()) {
            return data;
        }
        if (search.matches("(?i)^[0-9a-f\\s]+$") && search.replaceAll("\\s", "").length() >= 2) {
            return HexUtils.replaceHexPattern(data, search, replace);
        }
        return HexUtils.replaceAscii(data, search, replace);
    }

    public PacketQueue queue() {
        return queue;
    }

    public HistoryStore history() {
        return history;
    }
}
