package com.burpmirage.burp.ui;

import com.burpmirage.burp.intercept.HistoryStore;
import com.burpmirage.burp.model.InterceptedPacket;
import com.burpmirage.burp.model.PacketDirection;
import com.burpmirage.burp.nativebridge.BridgeServer;
import com.burpmirage.burp.util.HexUtils;
import com.burpmirage.burp.util.I18n;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JSplitPane;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.FlowLayout;
import java.awt.Font;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Burp-style Repeater: Request | Response side-by-side, Send on the toolbar.
 * Raw TCP pairing (Send → next RECV), not HTTP Content-Length.
 * Shortcut: Ctrl+R (when this tab is active) sends the request.
 */
public final class RepeaterPanel extends JPanel {
    private static final DateTimeFormatter TS =
            DateTimeFormatter.ofPattern("HH:mm:ss.SSS").withZone(ZoneId.systemDefault());

    private final BridgeServer bridge;
    private final HistoryStore history;
    private final HexEditorPanel requestEditor = new HexEditorPanel(true);
    private final HexEditorPanel responseEditor = new HexEditorPanel(true);
    private final JTextField peerField = new JTextField(28);
    private final JCheckBox anyPeer = new JCheckBox(I18n.get("repeater.any_peer"), true);
    private final JLabel status = new JLabel(" ");
    private final JButton sendButton = new JButton(I18n.get("repeater.send"));

    private final AtomicLong awaitUntilMs = new AtomicLong(0);
    private final AtomicReference<String> awaitRequestId = new AtomicReference<>("");
    private final AtomicReference<String> awaitPeer = new AtomicReference<>("");
    private volatile String lastRequestSummary = "";

    public RepeaterPanel(BridgeServer bridge, HistoryStore history) {
        super(new BorderLayout(6, 6));
        this.bridge = bridge;
        this.history = history;
        setBorder(new EmptyBorder(6, 6, 6, 6));

        responseEditor.setEditable(false);

        sendButton.setFont(sendButton.getFont().deriveFont(Font.BOLD));
        sendButton.setBackground(new Color(0xF5, 0xA6, 0x23));
        sendButton.setForeground(Color.BLACK);
        sendButton.setOpaque(true);
        sendButton.setFocusPainted(false);
        sendButton.addActionListener(e -> send());

        JButton clearResp = new JButton(I18n.get("repeater.clear_response"));
        clearResp.addActionListener(e -> {
            responseEditor.clear();
            status.setText(I18n.get("repeater.response_cleared"));
        });

        JPanel toolbar = new JPanel(new BorderLayout(8, 0));
        JPanel left = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        left.add(sendButton);
        left.add(clearResp);
        left.add(new JLabel(I18n.get("repeater.peer_hint")));
        left.add(peerField);
        left.add(anyPeer);
        toolbar.add(left, BorderLayout.WEST);
        toolbar.add(status, BorderLayout.CENTER);

        JPanel reqWrap = new JPanel(new BorderLayout());
        reqWrap.setBorder(new TitledBorder(I18n.get("repeater.request")));
        reqWrap.add(requestEditor, BorderLayout.CENTER);

        JPanel respWrap = new JPanel(new BorderLayout());
        respWrap.setBorder(new TitledBorder(I18n.get("repeater.response")));
        respWrap.add(responseEditor, BorderLayout.CENTER);

        // Burp Repeater layout: Request | Response horizontal
        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, reqWrap, respWrap);
        split.setResizeWeight(0.5);
        split.setDividerLocation(0.5);
        split.setContinuousLayout(true);

        add(toolbar, BorderLayout.NORTH);
        add(split, BorderLayout.CENTER);

        history.addListener(this::onHistoryPacket);
        bridge.setRepeaterResponseListener(this::onFridaRepeaterResponse);
    }

    public void load(InterceptedPacket packet) {
        if (packet == null) {
            return;
        }
        peerField.setText(packet.peer());
        requestEditor.setMeta(I18n.format(
                "repeater.loaded_meta",
                packet.direction().label(),
                packet.apiName(),
                packet.peer(),
                packet.length(),
                shortId(packet.id())
        ));
        requestEditor.setData(packet.data());
        responseEditor.clear();
        status.setText(I18n.get("repeater.loaded_status"));
    }

    /** Public entry for Ctrl+R when Repeater tab is active. */
    public void sendRequest() {
        send();
    }

    private void send() {
        byte[] raw = requestEditor.getData();
        if (raw.length == 0) {
            JOptionPane.showMessageDialog(this, I18n.get("repeater.nothing"), I18n.get("tab.repeater"), JOptionPane.WARNING_MESSAGE);
            return;
        }
        if (!bridge.hasClient()) {
            JOptionPane.showMessageDialog(
                    this,
                    I18n.get("repeater.no_bridge"),
                    I18n.get("tab.repeater"),
                    JOptionPane.WARNING_MESSAGE
            );
            return;
        }

        // Auto-fix Content-Length / frame length before inject (like Burp Forward).
        byte[] data = HexUtils.prepareEditedPacket(raw, raw);
        requestEditor.setData(data);

        String requestId = "R-" + UUID.randomUUID().toString().substring(0, 8);
        String peer = peerField.getText() == null ? "" : peerField.getText().trim();
        responseEditor.clear();
        awaitPeer.set(peer);
        awaitRequestId.set(requestId);
        awaitUntilMs.set(System.currentTimeMillis() + 20_000L);

        lastRequestSummary = I18n.format(
                "repeater.req_summary",
                requestId,
                TS.format(Instant.now()),
                peer.isBlank() ? "(any/last socket)" : peer,
                data.length,
                HexUtils.toAsciiPreview(data, 40)
        );
        requestEditor.setMeta(I18n.format("repeater.sent_meta", requestId));

        boolean ok = bridge.injectSend(data, peer, requestId);
        if (!ok) {
            awaitUntilMs.set(0);
            awaitRequestId.set("");
            status.setText(I18n.get("repeater.inject_failed"));
            return;
        }

        status.setText(I18n.format("repeater.sent_status", requestId, data.length));

        InterceptedPacket replay = InterceptedPacket.create(
                0,
                "repeater",
                PacketDirection.SEND,
                "inject:" + requestId,
                peer,
                -1,
                data
        );
        replay.setStatus(InterceptedPacket.PacketStatus.REPLAYED);
        history.add(replay);
    }

    private void onHistoryPacket(InterceptedPacket packet) {
        if (packet == null || packet.direction() != PacketDirection.RECV) {
            return;
        }
        // Ignore our own replay marker rows
        if ("repeater".equals(packet.processName()) && packet.apiName() != null
                && packet.apiName().startsWith("inject")) {
            return;
        }
        tryCapture(packet.data(), packet.peer(), packet.apiName(), "History");
    }

    private void onFridaRepeaterResponse(byte[] data, String peer, String requestId) {
        String expected = awaitRequestId.get();
        if (requestId != null && !requestId.isBlank() && expected != null && !expected.isBlank()
                && !requestId.equals(expected)) {
            // Different outstanding request — ignore
            return;
        }
        tryCapture(data, peer, "frida", "Frida");
    }

    private void tryCapture(byte[] data, String peer, String api, String source) {
        long until = awaitUntilMs.get();
        if (until == 0 || System.currentTimeMillis() > until) {
            return;
        }
        String expectedPeer = awaitPeer.get();
        if (!anyPeer.isSelected() && !peerMatches(expectedPeer, peer)) {
            SwingUtilities.invokeLater(() ->
                    status.setText(I18n.format("repeater.peer_mismatch", peer, expectedPeer)));
            return;
        }
        if (!awaitUntilMs.compareAndSet(until, 0)) {
            return;
        }
        String reqId = awaitRequestId.getAndSet("");
        byte[] body = data == null ? new byte[0] : Arrays.copyOf(data, data.length);

        String respSummary = I18n.format(
                "repeater.res_summary",
                reqId,
                TS.format(Instant.now()),
                source,
                api == null ? "" : api,
                peer == null ? "" : peer,
                body.length,
                HexUtils.toAsciiPreview(body, 40)
        );

        SwingUtilities.invokeLater(() -> {
            responseEditor.setMeta(respSummary);
            responseEditor.setData(body);
            status.setText(I18n.format("repeater.paired", reqId, body.length, source));
        });

        InterceptedPacket tagged = InterceptedPacket.create(
                0,
                "repeater",
                PacketDirection.RECV,
                "response:" + reqId,
                peer == null ? "" : peer,
                -1,
                body
        );
        tagged.setStatus(InterceptedPacket.PacketStatus.REPLAYED);
        history.add(tagged);
    }

    private static boolean peerMatches(String expected, String actual) {
        if (expected == null || expected.isBlank()) {
            return true;
        }
        if (actual == null || actual.isBlank()) {
            return true;
        }
        String e = expected.trim();
        String a = actual.trim();
        return a.contains(e) || e.contains(a) || a.startsWith(e.split(":")[0]);
    }

    private static String shortId(String id) {
        if (id == null) {
            return "";
        }
        return id.length() <= 12 ? id : id.substring(0, 12);
    }
}
