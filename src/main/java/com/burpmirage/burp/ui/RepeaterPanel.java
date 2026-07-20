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
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import java.awt.BorderLayout;
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
 * Repeater with request/response pairing. Hex-dump-only editors for space.
 * Raw TCP (not HTTP) — response = next RECV after Send.
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
    private final JTextArea pairInfo = new JTextArea(4, 40);

    private final AtomicLong awaitUntilMs = new AtomicLong(0);
    private final AtomicReference<String> awaitRequestId = new AtomicReference<>("");
    private final AtomicReference<String> awaitPeer = new AtomicReference<>("");
    private volatile String lastRequestSummary = "";

    public RepeaterPanel(BridgeServer bridge, HistoryStore history) {
        super(new BorderLayout(8, 8));
        this.bridge = bridge;
        this.history = history;
        setBorder(new EmptyBorder(8, 8, 8, 8));

        responseEditor.setEditable(false);

        pairInfo.setEditable(false);
        pairInfo.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        pairInfo.setBorder(new TitledBorder(I18n.get("repeater.pairing")));
        pairInfo.setText(I18n.get("repeater.pairing.help"));

        JPanel north = new JPanel(new BorderLayout(4, 4));
        JPanel row1 = new JPanel(new FlowLayout(FlowLayout.LEFT));
        row1.add(new JLabel(I18n.get("repeater.peer_hint")));
        row1.add(peerField);
        row1.add(anyPeer);
        JButton go = new JButton(I18n.get("repeater.send"));
        go.addActionListener(e -> send());
        JButton clearResp = new JButton(I18n.get("repeater.clear_response"));
        clearResp.addActionListener(e -> {
            responseEditor.clear();
            updatePairInfo(null, null);
            status.setText(I18n.get("repeater.response_cleared"));
        });
        row1.add(go);
        row1.add(clearResp);
        north.add(row1, BorderLayout.NORTH);
        north.add(status, BorderLayout.CENTER);
        north.add(pairInfo, BorderLayout.SOUTH);

        JPanel reqWrap = new JPanel(new BorderLayout());
        reqWrap.setBorder(new TitledBorder(I18n.get("repeater.request")));
        reqWrap.add(requestEditor, BorderLayout.CENTER);

        JPanel respWrap = new JPanel(new BorderLayout());
        respWrap.setBorder(new TitledBorder(I18n.get("repeater.response")));
        respWrap.add(responseEditor, BorderLayout.CENTER);

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, reqWrap, respWrap);
        split.setResizeWeight(0.5);
        split.setDividerLocation(0.5);

        add(north, BorderLayout.NORTH);
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
        updatePairInfo(null, null);
        status.setText(I18n.get("repeater.loaded_status"));
    }

    private void send() {
        byte[] data = requestEditor.getData();
        if (data.length == 0) {
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
        updatePairInfo(lastRequestSummary, I18n.get("repeater.waiting"));
        requestEditor.setMeta(I18n.format("repeater.sent_meta", requestId));

        boolean ok = bridge.injectSend(data, peer, requestId);
        if (!ok) {
            awaitUntilMs.set(0);
            awaitRequestId.set("");
            status.setText(I18n.get("repeater.inject_failed"));
            updatePairInfo(lastRequestSummary, I18n.get("repeater.failed_inject"));
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
            updatePairInfo(lastRequestSummary, respSummary);
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

    private void updatePairInfo(String req, String res) {
        StringBuilder sb = new StringBuilder();
        sb.append(I18n.get("repeater.pair.request")).append('\n')
                .append(req == null || req.isBlank() ? I18n.get("repeater.pair.none") : req).append('\n');
        sb.append(I18n.get("repeater.pair.response")).append('\n')
                .append(res == null || res.isBlank() ? I18n.get("repeater.pair.none") : res).append('\n');
        sb.append(I18n.get("repeater.pair.footer"));
        pairInfo.setText(sb.toString());
        pairInfo.setCaretPosition(0);
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
