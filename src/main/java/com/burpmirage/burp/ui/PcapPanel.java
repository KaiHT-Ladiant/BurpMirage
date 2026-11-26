package com.burpmirage.burp.ui;

import com.burpmirage.burp.model.InterceptedPacket;
import com.burpmirage.burp.model.PacketDirection;
import com.burpmirage.burp.pcap.PcapReader;
import com.burpmirage.burp.pcap.PcapTcpSegment;
import com.burpmirage.burp.util.ClipboardUtil;
import com.burpmirage.burp.util.HexUtils;
import com.burpmirage.burp.util.I18n;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.ListSelectionModel;
import javax.swing.RowFilter;
import javax.swing.SwingWorker;
import javax.swing.border.EmptyBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.nio.file.Path;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.function.Consumer;
import java.util.function.Function;

/**
 * Import PCAP/PCAPNG → list TCP payloads (plaintext heuristic) → Repeater / History highlight.
 * Analysis aid only; live modification remains Intercept / Repeater via Winsock hooks.
 */
public final class PcapPanel extends JPanel {
    private static final DateTimeFormatter TS =
            DateTimeFormatter.ofPattern("HH:mm:ss.SSS").withZone(ZoneId.systemDefault());
    private static final Color PLAIN_BG = new Color(0xE8, 0xF5, 0xE9);

    private static final int COL_NUM = 0;
    private static final int COL_TIME = 1;
    private static final int COL_FLOW = 2;
    private static final int COL_SRC = 3;
    private static final int COL_DST = 4;
    private static final int COL_LEN = 5;
    private static final int COL_PLAIN = 6;
    private static final int COL_PREVIEW = 7;

    private final DefaultTableModel model;
    private final JTable table;
    private final TableRowSorter<DefaultTableModel> sorter;
    private final HexEditorPanel detail = new HexEditorPanel();
    private final JLabel status = new JLabel(" ");
    private final JTextField filterField = new JTextField(18);
    private final JCheckBox plainOnly = new JCheckBox(I18n.get("pcap.plain_only"), false);
    private final List<PcapTcpSegment> rows = new ArrayList<>();
    private final Consumer<InterceptedPacket> sendToRepeater;
    private final Function<byte[], Integer> highlightInHistory;
    private final Runnable showRepeater;
    private final Runnable showHistory;

    public PcapPanel(
            Consumer<InterceptedPacket> sendToRepeater,
            Function<byte[], Integer> highlightInHistory,
            Runnable showRepeater,
            Runnable showHistory
    ) {
        super(new BorderLayout(8, 8));
        this.sendToRepeater = sendToRepeater != null ? sendToRepeater : p -> {};
        this.highlightInHistory = highlightInHistory != null ? highlightInHistory : b -> 0;
        this.showRepeater = showRepeater != null ? showRepeater : () -> {};
        this.showHistory = showHistory != null ? showHistory : () -> {};
        setBorder(new EmptyBorder(8, 8, 8, 8));

        model = new DefaultTableModel(
                new Object[]{
                        I18n.get("pcap.col.num"),
                        I18n.get("pcap.col.time"),
                        I18n.get("pcap.col.flow"),
                        I18n.get("pcap.col.src"),
                        I18n.get("pcap.col.dst"),
                        I18n.get("pcap.col.len"),
                        I18n.get("pcap.col.plain"),
                        I18n.get("pcap.col.preview")
                },
                0
        ) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }

            @Override
            public Class<?> getColumnClass(int columnIndex) {
                return columnIndex == COL_LEN || columnIndex == COL_NUM ? Integer.class : String.class;
            }
        };
        table = new JTable(model);
        table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        table.setAutoCreateRowSorter(true);
        sorter = new TableRowSorter<>(model);
        table.setRowSorter(sorter);
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                showSelected();
            }
        });
        table.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(
                    JTable t, Object value, boolean isSelected, boolean hasFocus, int row, int column
            ) {
                Component c = super.getTableCellRendererComponent(t, value, isSelected, hasFocus, row, column);
                if (!isSelected) {
                    int modelRow = t.convertRowIndexToModel(row);
                    if (modelRow >= 0 && modelRow < rows.size() && rows.get(modelRow).likelyPlaintext()) {
                        c.setBackground(PLAIN_BG);
                    } else {
                        c.setBackground(t.getBackground());
                    }
                }
                return c;
            }
        });

        detail.setEditable(true);

        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton open = new JButton(I18n.get("pcap.open"));
        open.addActionListener(e -> openFile());
        JButton toRepeater = new JButton(I18n.get("pcap.to_repeater"));
        toRepeater.addActionListener(e -> sendSelectedToRepeater());
        JButton findHist = new JButton(I18n.get("pcap.find_history"));
        findHist.addActionListener(e -> findInHistory());
        JButton clear = new JButton(I18n.get("pcap.clear"));
        clear.addActionListener(e -> clearAll());

        filterField.putClientProperty("JTextField.placeholderText", I18n.get("pcap.filter_hint"));
        DocumentListener filterListener = new DocumentListener() {
            private void upd() {
                applyFilter();
            }

            @Override
            public void insertUpdate(DocumentEvent e) {
                upd();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                upd();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                upd();
            }
        };
        filterField.getDocument().addDocumentListener(filterListener);
        plainOnly.addActionListener(e -> applyFilter());

        toolbar.add(open);
        toolbar.add(toRepeater);
        toolbar.add(findHist);
        toolbar.add(clear);
        toolbar.add(plainOnly);
        toolbar.add(new JLabel(I18n.get("pcap.filter")));
        toolbar.add(filterField);

        JPanel south = new JPanel(new BorderLayout());
        south.add(status, BorderLayout.WEST);
        JLabel help = new JLabel(I18n.get("pcap.help"));
        south.add(help, BorderLayout.EAST);

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(table), detail);
        split.setResizeWeight(0.45);

        add(toolbar, BorderLayout.NORTH);
        add(split, BorderLayout.CENTER);
        add(south, BorderLayout.SOUTH);

        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                maybe(e);
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                maybe(e);
            }

            private void maybe(MouseEvent e) {
                if (!e.isPopupTrigger()) {
                    return;
                }
                int row = table.rowAtPoint(e.getPoint());
                if (row >= 0) {
                    if (!table.isRowSelected(row)) {
                        table.setRowSelectionInterval(row, row);
                    }
                    showPcapContextMenu(e.getComponent(), e.getX(), e.getY());
                }
            }
        });

        status.setText(I18n.get("pcap.ready"));
    }

    private void showPcapContextMenu(Component invoker, int x, int y) {
        PcapTcpSegment primary = selectedSegment();
        JPopupMenu menu = new JPopupMenu();
        String headerText = primary == null
                ? I18n.get("menu.no_selection")
                : (primary.peer() == null || primary.peer().isBlank()
                ? primary.flowKey()
                : primary.peer());
        JMenuItem header = new JMenuItem(headerText);
        header.setEnabled(false);
        menu.add(header);
        menu.addSeparator();

        JMenuItem sendRep = new JMenuItem(I18n.get("menu.send_repeater"));
        sendRep.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_R, InputEvent.CTRL_DOWN_MASK));
        sendRep.setEnabled(primary != null || detail.getData().length > 0);
        sendRep.addActionListener(e -> sendSelectedToRepeater());
        menu.add(sendRep);

        JMenuItem findHist = new JMenuItem(I18n.get("pcap.find_history"));
        findHist.setEnabled(primary != null || detail.getData().length >= 4);
        findHist.addActionListener(e -> findInHistory());
        menu.add(findHist);
        menu.addSeparator();

        JMenu copyMenu = new JMenu(I18n.get("menu.copy"));
        JMenuItem copyPeer = new JMenuItem(I18n.get("menu.copy_peer"));
        copyPeer.setEnabled(primary != null);
        copyPeer.addActionListener(e -> {
            if (primary != null) {
                ClipboardUtil.copyText(primary.peer() == null ? "" : primary.peer());
            }
        });
        JMenuItem copyAscii = new JMenuItem(I18n.get("menu.copy_ascii"));
        copyAscii.setEnabled(primary != null || detail.getData().length > 0);
        copyAscii.addActionListener(e -> {
            byte[] data = detail.getData();
            if ((data == null || data.length == 0) && primary != null) {
                data = primary.payload();
            }
            ClipboardUtil.copyText(HexUtils.decodeForDisplay(data));
        });
        JMenuItem copyHex = new JMenuItem(I18n.get("menu.copy_hex"));
        copyHex.setEnabled(primary != null || detail.getData().length > 0);
        copyHex.addActionListener(e -> {
            byte[] data = detail.getData();
            if ((data == null || data.length == 0) && primary != null) {
                data = primary.payload();
            }
            ClipboardUtil.copyText(ClipboardUtil.toHex(data));
        });
        copyMenu.add(copyPeer);
        copyMenu.add(copyAscii);
        copyMenu.add(copyHex);
        menu.add(copyMenu);

        menu.show(invoker, x, y);
    }

    private void openFile() {
        JFileChooser chooser = new JFileChooser();
        chooser.setFileFilter(new FileNameExtensionFilter(
                "PCAP / PCAPNG", "pcap", "pcapng", "cap"));
        if (chooser.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        Path path = chooser.getSelectedFile().toPath();
        status.setText(I18n.format("pcap.loading", path.getFileName()));
        new SwingWorker<List<PcapTcpSegment>, Void>() {
            private String error;

            @Override
            protected List<PcapTcpSegment> doInBackground() {
                try {
                    return PcapReader.readTcpPayloads(path);
                } catch (Exception ex) {
                    error = ex.getMessage();
                    return List.of();
                }
            }

            @Override
            protected void done() {
                try {
                    List<PcapTcpSegment> segs = get();
                    if (error != null) {
                        status.setText(I18n.format("pcap.error", error));
                        return;
                    }
                    loadSegments(segs);
                    long plain = segs.stream().filter(PcapTcpSegment::likelyPlaintext).count();
                    status.setText(I18n.format(
                            "pcap.loaded",
                            path.getFileName(),
                            segs.size(),
                            plain
                    ));
                } catch (Exception ex) {
                    status.setText(I18n.format("pcap.error", ex.getMessage()));
                }
            }
        }.execute();
    }

    private void loadSegments(List<PcapTcpSegment> segs) {
        rows.clear();
        model.setRowCount(0);
        rows.addAll(segs);
        for (PcapTcpSegment s : segs) {
            model.addRow(new Object[]{
                    s.index() + 1,
                    TS.format(s.timestamp()),
                    s.flowKey(),
                    s.src() + ":" + s.srcPort(),
                    s.dst() + ":" + s.dstPort(),
                    s.length(),
                    s.likelyPlaintext() ? "✓" : "",
                    HexUtils.toAsciiPreview(s.payload(), 48)
            });
        }
        detail.clear();
        applyFilter();
    }

    private void clearAll() {
        rows.clear();
        model.setRowCount(0);
        detail.clear();
        status.setText(I18n.get("pcap.ready"));
    }

    private void applyFilter() {
        String q = filterField.getText() == null ? "" : filterField.getText().trim().toLowerCase(Locale.ROOT);
        boolean onlyPlain = plainOnly.isSelected();
        if (q.isEmpty() && !onlyPlain) {
            sorter.setRowFilter(null);
            return;
        }
        sorter.setRowFilter(new RowFilter<DefaultTableModel, Integer>() {
            @Override
            public boolean include(Entry<? extends DefaultTableModel, ? extends Integer> entry) {
                int modelRow = entry.getIdentifier();
                if (modelRow < 0 || modelRow >= rows.size()) {
                    return false;
                }
                PcapTcpSegment s = rows.get(modelRow);
                if (onlyPlain && !s.likelyPlaintext()) {
                    return false;
                }
                if (q.isEmpty()) {
                    return true;
                }
                String hay = (s.flowKey() + " " + s.src() + " " + s.dst()
                        + " " + HexUtils.toAsciiPreview(s.payload(), 256)).toLowerCase(Locale.ROOT);
                return hay.contains(q);
            }
        });
    }

    private void showSelected() {
        PcapTcpSegment s = selectedSegment();
        if (s == null) {
            return;
        }
        detail.setMeta(I18n.format(
                "pcap.meta",
                s.flowKey(),
                s.src() + ":" + s.srcPort(),
                s.dst() + ":" + s.dstPort(),
                s.length(),
                s.likelyPlaintext() ? "yes" : "no"
        ));
        detail.setData(s.payload());
    }

    private PcapTcpSegment selectedSegment() {
        int viewRow = table.getSelectedRow();
        if (viewRow < 0) {
            return null;
        }
        int modelRow = table.convertRowIndexToModel(viewRow);
        if (modelRow < 0 || modelRow >= rows.size()) {
            return null;
        }
        return rows.get(modelRow);
    }

    private List<PcapTcpSegment> selectedSegments() {
        List<PcapTcpSegment> out = new ArrayList<>();
        for (int viewRow : table.getSelectedRows()) {
            int modelRow = table.convertRowIndexToModel(viewRow);
            if (modelRow >= 0 && modelRow < rows.size()) {
                out.add(rows.get(modelRow));
            }
        }
        return out;
    }

    private void sendSelectedToRepeater() {
        List<PcapTcpSegment> sel = selectedSegments();
        if (sel.isEmpty()) {
            // Allow sending edited hex even if selection is stale
            byte[] edited = detail.getData();
            if (edited.length == 0) {
                status.setText(I18n.get("pcap.nothing_selected"));
                return;
            }
            sendPayload(edited, "pcap", "0.0.0.0:0");
            return;
        }
        for (PcapTcpSegment s : sel) {
            byte[] data = (sel.size() == 1) ? detail.getData() : s.payload();
            if (data.length == 0) {
                data = s.payload();
            }
            sendPayload(data, s.flowKey(), s.peer());
        }
        showRepeater.run();
        status.setText(I18n.format("pcap.sent_repeater", sel.size()));
    }

    private void sendPayload(byte[] data, String api, String peer) {
        InterceptedPacket packet = InterceptedPacket.create(
                -1,
                "pcap",
                PacketDirection.SEND,
                "pcap:" + api,
                peer,
                -1,
                data
        );
        sendToRepeater.accept(packet);
    }

    private void findInHistory() {
        PcapTcpSegment s = selectedSegment();
        byte[] needle = detail.getData();
        if ((needle == null || needle.length == 0) && s != null) {
            needle = s.payload();
        }
        if (needle == null || needle.length < 4) {
            status.setText(I18n.get("pcap.needle_short"));
            return;
        }
        // Cap needle for History scan (avoid huge TCP segments)
        byte[] use = needle.length > 256 ? java.util.Arrays.copyOf(needle, 256) : needle;
        int hits = highlightInHistory.apply(use);
        showHistory.run();
        status.setText(I18n.format("pcap.history_hits", hits));
    }
}
