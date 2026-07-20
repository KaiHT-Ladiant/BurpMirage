package com.burpmirage.burp.ui;

import com.burpmirage.burp.intercept.HistoryStore;
import com.burpmirage.burp.model.InterceptedPacket;
import com.burpmirage.burp.model.PacketDirection;
import com.burpmirage.burp.util.HexUtils;
import com.burpmirage.burp.util.I18n;

import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.RowFilter;
import javax.swing.SwingUtilities;
import javax.swing.border.EmptyBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

/**
 * Packet history with Edited marker, highlight search, request/response pairing,
 * Original/Edited viewer, and column sorting.
 */
public final class HistoryPanel extends JPanel {
    private static final DateTimeFormatter TS =
            DateTimeFormatter.ofPattern("HH:mm:ss.SSS").withZone(ZoneId.systemDefault());

    private static final Color HIGHLIGHT_BG = new Color(0xFF, 0xF3, 0x9A);
    private static final Color PAIR_BG = new Color(0xD6, 0xEA, 0xFF);
    private static final Color EDITED_BG = new Color(0xFF, 0xF3, 0xE0);
    private static final Color EDITED_FG = new Color(0xB0, 0x40, 0x00);

    private static final int COL_NUM = 0;
    private static final int COL_TIME = 1;
    private static final int COL_DIR = 2;
    private static final int COL_PAIR = 3;
    private static final int COL_API = 4;
    private static final int COL_PEER = 5;
    private static final int COL_LEN = 6;
    private static final int COL_EDITED = 7;
    private static final int COL_STATUS = 8;
    private static final int COL_PREVIEW = 9;

    private final DefaultTableModel model;
    private final JTable table;
    private final TableRowSorter<DefaultTableModel> sorter;
    private final HexEditorPanel detail = new HexEditorPanel();
    private final List<InterceptedPacket> rows = new ArrayList<>();
    private final Consumer<InterceptedPacket> sendToRepeater;
    private final HistoryStore history;
    private final JRadioButton viewEdited = new JRadioButton(I18n.get("history.view.edited"), true);
    private final JRadioButton viewOriginal = new JRadioButton(I18n.get("history.view.original"));
    private final JLabel detailMeta = new JLabel(" ");
    private final JTextField highlightField = new JTextField(18);
    private final AtomicInteger pairSeq = new AtomicInteger();
    private String highlightQuery = "";
    private String focusPairId = null;

    public HistoryPanel(HistoryStore history, Consumer<InterceptedPacket> sendToRepeater) {
        super(new BorderLayout(8, 8));
        this.history = history;
        this.sendToRepeater = sendToRepeater != null ? sendToRepeater : p -> {};
        setBorder(new EmptyBorder(8, 8, 8, 8));

        model = new DefaultTableModel(
                new Object[]{
                        I18n.get("history.col.num"),
                        I18n.get("history.col.time"),
                        I18n.get("history.col.dir"),
                        I18n.get("history.col.pair"),
                        I18n.get("history.col.api"),
                        I18n.get("history.col.peer"),
                        I18n.get("history.col.len"),
                        I18n.get("history.col.edited"),
                        I18n.get("history.col.status"),
                        I18n.get("history.col.preview")
                }, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }

            @Override
            public Class<?> getColumnClass(int columnIndex) {
                return switch (columnIndex) {
                    case COL_NUM, COL_LEN -> Integer.class;
                    default -> String.class;
                };
            }
        };
        table = new JTable(model);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setAutoCreateRowSorter(false);
        sorter = new TableRowSorter<>(model);
        sorter.setComparator(COL_NUM, Comparator.comparingInt(o -> (Integer) o));
        sorter.setComparator(COL_LEN, Comparator.comparingInt(o -> (Integer) o));
        sorter.setComparator(COL_TIME, Comparator.naturalOrder());
        table.setRowSorter(sorter);

        table.getColumnModel().getColumn(COL_NUM).setPreferredWidth(45);
        table.getColumnModel().getColumn(COL_TIME).setPreferredWidth(90);
        table.getColumnModel().getColumn(COL_DIR).setPreferredWidth(70);
        table.getColumnModel().getColumn(COL_PAIR).setPreferredWidth(55);
        table.getColumnModel().getColumn(COL_EDITED).setPreferredWidth(55);
        table.getColumnModel().getColumn(COL_STATUS).setPreferredWidth(90);
        table.getColumnModel().getColumn(COL_PREVIEW).setPreferredWidth(260);

        DefaultTableCellRenderer rowPaint = new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(
                    JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                int modelRow = table.convertRowIndexToModel(row);
                InterceptedPacket pkt = modelRow >= 0 && modelRow < rows.size() ? rows.get(modelRow) : null;
                boolean editedCol = column == COL_EDITED
                        && ("✓".equals(String.valueOf(value)) || "Yes".equalsIgnoreCase(String.valueOf(value)));
                if (!isSelected) {
                    if (matchesHighlight(pkt) || matchesHighlightRow(modelRow)) {
                        c.setBackground(HIGHLIGHT_BG);
                        c.setForeground(table.getForeground());
                    } else if (pkt != null && focusPairId != null && focusPairId.equals(pkt.pairId())) {
                        c.setBackground(PAIR_BG);
                        c.setForeground(table.getForeground());
                    } else if (editedCol) {
                        c.setBackground(EDITED_BG);
                        c.setForeground(EDITED_FG);
                    } else {
                        c.setBackground(table.getBackground());
                        c.setForeground(table.getForeground());
                    }
                }
                if (column == COL_EDITED || column == COL_PAIR) {
                    setHorizontalAlignment(CENTER);
                } else {
                    setHorizontalAlignment(LEFT);
                }
                return c;
            }
        };
        for (int c = 0; c < model.getColumnCount(); c++) {
            table.getColumnModel().getColumn(c).setCellRenderer(rowPaint);
        }

        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                InterceptedPacket p = selectedPacket();
                focusPairId = p != null ? p.pairId() : null;
                table.repaint();
                showSelected();
            }
        });

        JPopupMenu historyMenu = new JPopupMenu();
        JMenuItem sendRep = new JMenuItem(I18n.get("history.to_repeater"));
        sendRep.addActionListener(e -> {
            InterceptedPacket p = selectedPacket();
            if (p != null) {
                sendToRepeater.accept(p);
            }
        });
        JMenuItem jumpPair = new JMenuItem(I18n.get("history.jump_pair"));
        jumpPair.addActionListener(e -> jumpToPairMate());
        historyMenu.add(sendRep);
        historyMenu.add(jumpPair);
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
                    table.setRowSelectionInterval(row, row);
                    historyMenu.show(table, e.getX(), e.getY());
                }
            }
        });

        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton clear = new JButton(I18n.get("history.clear"));
        clear.addActionListener(e -> {
            history.clear();
            rows.clear();
            model.setRowCount(0);
            detail.clear();
            detailMeta.setText(" ");
            focusPairId = null;
            pairSeq.set(0);
        });
        JButton toRepeater = new JButton(I18n.get("history.to_repeater"));
        toRepeater.addActionListener(e -> {
            InterceptedPacket p = selectedPacket();
            if (p != null) {
                sendToRepeater.accept(p);
            }
        });
        JButton editedOnly = new JButton(I18n.get("history.edited_only"));
        editedOnly.addActionListener(e ->
                sorter.setRowFilter(RowFilter.regexFilter("✓", COL_EDITED)));
        JButton showAll = new JButton(I18n.get("history.show_all"));
        showAll.addActionListener(e -> sorter.setRowFilter(null));

        highlightField.putClientProperty("JTextField.placeholderText", I18n.get("history.highlight_hint"));
        highlightField.getDocument().addDocumentListener(new DocumentListener() {
            private void upd() {
                highlightQuery = highlightField.getText() == null ? "" : highlightField.getText().trim();
                table.repaint();
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
        });

        toolbar.add(clear);
        toolbar.add(toRepeater);
        toolbar.add(editedOnly);
        toolbar.add(showAll);
        toolbar.add(new JLabel(I18n.get("history.highlight")));
        toolbar.add(highlightField);
        toolbar.add(new JLabel(I18n.get("history.sort_hint")));

        ButtonGroup viewGroup = new ButtonGroup();
        viewGroup.add(viewEdited);
        viewGroup.add(viewOriginal);
        viewEdited.addActionListener(e -> showSelected());
        viewOriginal.addActionListener(e -> showSelected());

        detail.setEditable(false);

        JPanel detailNorth = new JPanel(new BorderLayout(8, 0));
        JPanel viewToggles = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        viewToggles.add(new JLabel(I18n.get("history.view")));
        viewToggles.add(viewEdited);
        viewToggles.add(viewOriginal);
        detailNorth.add(viewToggles, BorderLayout.WEST);
        detailMeta.setBorder(new EmptyBorder(0, 8, 0, 0));
        detailNorth.add(detailMeta, BorderLayout.CENTER);

        JPanel detailWrap = new JPanel(new BorderLayout());
        detailWrap.add(detailNorth, BorderLayout.NORTH);
        detailWrap.add(detail, BorderLayout.CENTER);

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(table), detailWrap);
        split.setResizeWeight(0.45);

        add(toolbar, BorderLayout.NORTH);
        add(split, BorderLayout.CENTER);

        history.addListener(this::append);
    }

    private void append(InterceptedPacket packet) {
        SwingUtilities.invokeLater(() -> {
            assignPair(packet);
            rows.add(packet);
            boolean modified = packet.isModified();
            model.addRow(new Object[]{
                    rows.size(),
                    TS.format(packet.timestamp()),
                    packet.direction().label(),
                    packet.pairId() == null ? "" : packet.pairId(),
                    packet.apiName(),
                    packet.peer(),
                    packet.length(),
                    modified ? "✓" : "",
                    packet.status().name(),
                    (modified ? I18n.format("history.preview.edited", HexUtils.toAsciiPreview(packet.data(), 48))
                            : HexUtils.toAsciiPreview(packet.data(), 48))
            });
            // Refresh pair cell on the matching request row if we just paired a response.
            if (packet.direction() == PacketDirection.RECV && packet.pairId() != null) {
                refreshPairColumn(packet.pairId());
            }
        });
    }

    private void assignPair(InterceptedPacket packet) {
        if (packet.direction() != PacketDirection.RECV || packet.pairId() != null) {
            return;
        }
        for (int i = rows.size() - 1; i >= 0; i--) {
            InterceptedPacket prev = rows.get(i);
            if (prev.direction() != PacketDirection.SEND) {
                continue;
            }
            if (prev.pairId() != null) {
                continue;
            }
            if (!sameChannel(prev, packet)) {
                continue;
            }
            String id = "P" + pairSeq.incrementAndGet();
            prev.setPairId(id);
            packet.setPairId(id);
            return;
        }
    }

    private static boolean sameChannel(InterceptedPacket a, InterceptedPacket b) {
        if (a.socketFd() > 0 && a.socketFd() == b.socketFd()) {
            return true;
        }
        String pa = a.peer() == null ? "" : a.peer().trim();
        String pb = b.peer() == null ? "" : b.peer().trim();
        if (!pa.isEmpty() && pa.equalsIgnoreCase(pb)) {
            return true;
        }
        // Same process fallback when peer/fd unknown
        return a.pid() > 0 && a.pid() == b.pid()
                && a.processName() != null
                && a.processName().equalsIgnoreCase(b.processName());
    }

    private void refreshPairColumn(String pairId) {
        for (int i = 0; i < rows.size(); i++) {
            if (pairId.equals(rows.get(i).pairId())) {
                model.setValueAt(pairId, i, COL_PAIR);
            }
        }
    }

    private void jumpToPairMate() {
        InterceptedPacket p = selectedPacket();
        if (p == null || p.pairId() == null) {
            return;
        }
        for (int i = 0; i < rows.size(); i++) {
            InterceptedPacket other = rows.get(i);
            if (other == p) {
                continue;
            }
            if (p.pairId().equals(other.pairId())) {
                int view = table.convertRowIndexToView(i);
                if (view >= 0) {
                    table.setRowSelectionInterval(view, view);
                    table.scrollRectToVisible(table.getCellRect(view, 0, true));
                }
                return;
            }
        }
    }

    private boolean matchesHighlight(InterceptedPacket pkt) {
        if (highlightQuery == null || highlightQuery.isBlank() || pkt == null) {
            return false;
        }
        String q = highlightQuery.toLowerCase(Locale.ROOT);
        String preview = HexUtils.toAsciiPreview(pkt.data(), 200).toLowerCase(Locale.ROOT);
        String peer = pkt.peer() == null ? "" : pkt.peer().toLowerCase(Locale.ROOT);
        String api = pkt.apiName() == null ? "" : pkt.apiName().toLowerCase(Locale.ROOT);
        String pair = pkt.pairId() == null ? "" : pkt.pairId().toLowerCase(Locale.ROOT);
        return preview.contains(q) || peer.contains(q) || api.contains(q) || pair.contains(q);
    }

    private boolean matchesHighlightRow(int modelRow) {
        if (highlightQuery == null || highlightQuery.isBlank() || modelRow < 0) {
            return false;
        }
        String q = highlightQuery.toLowerCase(Locale.ROOT);
        for (int c = 0; c < model.getColumnCount(); c++) {
            Object v = model.getValueAt(modelRow, c);
            if (v != null && v.toString().toLowerCase(Locale.ROOT).contains(q)) {
                return true;
            }
        }
        return false;
    }

    private InterceptedPacket selectedPacket() {
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

    private void showSelected() {
        InterceptedPacket p = selectedPacket();
        if (p == null) {
            detail.clear();
            detailMeta.setText(" ");
            return;
        }
        boolean showOriginal = viewOriginal.isSelected();
        if (!p.isModified()) {
            viewEdited.setSelected(true);
            showOriginal = false;
        }
        byte[] shown = showOriginal ? p.originalData() : p.data();
        String which = showOriginal ? "ORIGINAL" : (p.isModified() ? "EDITED" : "as sent");
        String pairInfo = p.pairId() == null
                ? I18n.get("history.pair.none")
                : I18n.format("history.pair.of", p.pairId(), pairMateLabel(p));
        String meta = I18n.format(
                "history.meta",
                which,
                p.direction().label(),
                p.peer(),
                p.status().name(),
                p.isModified(),
                p.originalData().length,
                p.data().length
        ) + " | " + pairInfo;
        detailMeta.setText(meta);
        detailMeta.setToolTipText(meta);
        detail.setMeta(I18n.format("history.detail", which, p.direction().label(), p.peer()));
        detail.setData(shown);

        viewOriginal.setEnabled(p.isModified());
        viewEdited.setEnabled(true);
    }

    private String pairMateLabel(InterceptedPacket p) {
        for (InterceptedPacket other : rows) {
            if (other == p || other.pairId() == null || !other.pairId().equals(p.pairId())) {
                continue;
            }
            return other.direction().label() + " #" + (rows.indexOf(other) + 1);
        }
        return "?";
    }
}
