package com.burpmirage.burp.intercept;

import com.burpmirage.burp.model.InterceptedPacket;
import com.burpmirage.burp.model.ExtensionSettings;
import com.burpmirage.burp.util.PacketLogger;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

/**
 * Bounded in-memory history of intercepted packets.
 */
public final class HistoryStore {
    private final ExtensionSettings settings;
    private final PacketLogger logger;
    private final List<InterceptedPacket> packets = new CopyOnWriteArrayList<>();
    private final List<Consumer<InterceptedPacket>> listeners = new CopyOnWriteArrayList<>();

    public HistoryStore(ExtensionSettings settings, PacketLogger logger) {
        this.settings = settings;
        this.logger = logger;
    }

    public void add(InterceptedPacket packet) {
        packets.add(packet);
        trim();
        logger.log(packet);
        for (Consumer<InterceptedPacket> listener : listeners) {
            listener.accept(packet);
        }
    }

    public void clear() {
        packets.clear();
    }

    public List<InterceptedPacket> snapshot() {
        return Collections.unmodifiableList(new ArrayList<>(packets));
    }

    public void addListener(Consumer<InterceptedPacket> listener) {
        listeners.add(listener);
    }

    public void removeListener(Consumer<InterceptedPacket> listener) {
        listeners.remove(listener);
    }

    private void trim() {
        int max = settings.maxHistory();
        while (packets.size() > max) {
            packets.remove(0);
        }
    }
}
