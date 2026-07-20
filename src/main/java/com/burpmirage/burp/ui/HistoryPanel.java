package com.burpmirage.burp.ui;

import com.burpmirage.burp.intercept.HistoryStore;
import com.burpmirage.burp.model.InterceptedPacket;
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
import javax.swing.ListSelectionModel;
import javax.swing.RowFilter;
import javax.swing.SwingUtilities;
import javax.swing.border.EmptyBorder;
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
import java.util.function.Consumer;

/**
 * Packet history with Edited marker, Original/Edited viewer, and column sorting.
 */
public final class HistoryPanel extends JPanel {
    private static final DateTimeFormatter TS =
            DateTimeFormatter.ofPattern("HH:mm:ss.SSS").withZone(ZoneId.systemDefault());

    private static final int COL_NUM = 0;
    private static final int COL_TIME = 1;
    private static final int COL_DIR = 2;
    private static final int COL_API = 3;
    private static final int COL_PEER = 4;
    private static final int COL_LEN = 5;
    private static final int COL_EDITED = 6;
    private static final int COL_STATUS = 7;
    private static final int COL_PREVIEW = 8;

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
        table.getColumnModel().getColumn(COL_EDITED).setPreferredWidth(55);
        table.getColumnModel().getColumn(COL_STATUS).setPreferredWidth(90);
        table.getColumnModel().getColumn(COL_PREVIEW).setPreferredWidth(280);

        table.getColumnModel().getColumn(COL_EDITED).setCellRenderer(new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(
                    JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                boolean edited = "✓".equals(String.valueOf(value)) || "Yes".equalsIgnoreCase(String.valueOf(value));
                if (!isSelected) {
                    c.setForeground(edited ? new Color(0xB0, 0x40, 0x00) : table.getForeground());
                    c.setBackground(edited ? new Color(0xFF, 0xF3, 0xE0) : table.getBackground());
                }
                setHorizontalAlignment(CENTER);
                return c;
            }
        });

        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
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
        historyMenu.add(sendRep);
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

        toolbar.add(clear);
        toolbar.add(toRepeater);
        toolbar.add(editedOnly);
        toolbar.add(showAll);
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
            rows.add(packet);
            boolean modified = packet.isModified();
            model.addRow(new Object[]{
                    rows.size(),
                    TS.format(packet.timestamp()),
                    packet.direction().label(),
                    packet.apiName(),
                    packet.peer(),
                    packet.length(),
                    modified ? "✓" : "",
                    packet.status().name(),
                    (modified ? I18n.format("history.preview.edited", HexUtils.toAsciiPreview(packet.data(), 48))
                            : HexUtils.toAsciiPreview(packet.data(), 48))
            });
        });
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
        String meta = I18n.format(
                "history.meta",
                which,
                p.direction().label(),
                p.peer(),
                p.status().name(),
                p.isModified(),
                p.originalData().length,
                p.data().length
        );
        detailMeta.setText(meta);
        detailMeta.setToolTipText(meta);
        // Don't duplicate long meta into HexEditor info row (causes overlap)
        detail.setMeta(I18n.format("history.detail", which, p.direction().label(), p.peer()));
        detail.setData(shown);

        viewOriginal.setEnabled(p.isModified());
        viewEdited.setEnabled(true);
    }
}
