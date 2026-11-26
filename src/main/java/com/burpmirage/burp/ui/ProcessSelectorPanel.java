package com.burpmirage.burp.ui;

import com.burpmirage.burp.model.ProcessCaptureGroup;
import com.burpmirage.burp.model.ProcessInfo;
import com.burpmirage.burp.nativebridge.FridaController;
import com.burpmirage.burp.nativebridge.ProcessEnumerator;
import com.burpmirage.burp.util.I18n;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.RowFilter;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableColumn;
import javax.swing.table.TableRowSorter;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;

/**
 * Process list + Inject & Hook controls.
 */
public final class ProcessSelectorPanel extends JPanel {
    private final ProcessEnumerator enumerator = new ProcessEnumerator();
    private final FridaController fridaController;
    private final DefaultTableModel model;
    private final JTable table;
    private final TableRowSorter<DefaultTableModel> sorter;
    private final JTextField filterField = new JTextField(24);
    private final JLabel statusLabel = new JLabel(I18n.get("process.ready"));
    private final Consumer<ProcessInfo> onAttached;

    private List<ProcessInfo> cache = List.of();

    public ProcessSelectorPanel(FridaController fridaController, Consumer<ProcessInfo> onAttached) {
        super(new BorderLayout(8, 8));
        this.fridaController = fridaController;
        this.onAttached = onAttached != null ? onAttached : p -> {};
        setBorder(new EmptyBorder(8, 8, 8, 8));

        model = new DefaultTableModel(
                new Object[]{
                        I18n.get("process.col.check"),
                        I18n.get("process.col.pid"),
                        I18n.get("process.col.name"),
                        I18n.get("process.col.role"),
                        I18n.get("process.col.user"),
                        I18n.get("process.col.path")
                }, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return column == 0; // checkbox only — reliable multi-select inside Burp
            }

            @Override
            public Class<?> getColumnClass(int columnIndex) {
                if (columnIndex == 0) {
                    return Boolean.class;
                }
                if (columnIndex == 1) {
                    return Integer.class;
                }
                return String.class;
            }
        };
        table = new JTable(model);
        // Burp often eats Ctrl+click; keep Swing multi-select + checkbox column.
        table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        table.setRowSelectionAllowed(true);
        table.setColumnSelectionAllowed(false);
        table.setCellSelectionEnabled(false);
        sorter = new TableRowSorter<>(model);
        table.setRowSorter(sorter);
        TableColumn checkCol = table.getColumnModel().getColumn(0);
        checkCol.setPreferredWidth(36);
        checkCol.setMaxWidth(44);
        checkCol.setMinWidth(32);
        table.getColumnModel().getColumn(1).setPreferredWidth(70);
        table.getColumnModel().getColumn(2).setPreferredWidth(130);
        table.getColumnModel().getColumn(3).setPreferredWidth(140);
        table.getColumnModel().getColumn(4).setPreferredWidth(90);
        table.getColumnModel().getColumn(5).setPreferredWidth(380);
        // Space / click-toggle helpers when Burp steals Ctrl+click.
        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                if (!SwingUtilities.isLeftMouseButton(e)) {
                    return;
                }
                int viewRow = table.rowAtPoint(e.getPoint());
                int viewCol = table.columnAtPoint(e.getPoint());
                if (viewRow < 0) {
                    return;
                }
                // Clicking checkbox column: let default editor run.
                if (viewCol == 0) {
                    return;
                }
                // Ctrl/Cmd+click: toggle checkbox (Burp-safe multi-select).
                if (e.isControlDown() || e.isMetaDown()) {
                    int modelRow = table.convertRowIndexToModel(viewRow);
                    boolean on = Boolean.TRUE.equals(model.getValueAt(modelRow, 0));
                    model.setValueAt(!on, modelRow, 0);
                    if (!on) {
                        table.addRowSelectionInterval(viewRow, viewRow);
                    } else {
                        table.removeRowSelectionInterval(viewRow, viewRow);
                    }
                }
            }
        });
        table.addMouseMotionListener(new java.awt.event.MouseMotionAdapter() {
            @Override
            public void mouseMoved(java.awt.event.MouseEvent e) {
                int viewRow = table.rowAtPoint(e.getPoint());
                if (viewRow < 0) {
                    table.setToolTipText(I18n.get("process.role_hint"));
                    return;
                }
                int modelRow = table.convertRowIndexToModel(viewRow);
                int pid = (Integer) model.getValueAt(modelRow, 1);
                ProcessInfo info = cache.stream().filter(p -> p.pid() == pid).findFirst().orElse(null);
                if (info == null || info.displayCommandLine().isBlank()) {
                    table.setToolTipText(I18n.get("process.role_hint"));
                    return;
                }
                String tip = info.roleDisplay() + "  |  " + info.displayCommandLine();
                table.setToolTipText(tip.length() > 500 ? tip.substring(0, 500) + "…" : tip);
            }
        });

        JPanel north = new JPanel(new BorderLayout(8, 0));
        JPanel filters = new JPanel(new FlowLayout(FlowLayout.LEFT));
        filters.add(new JLabel(I18n.get("process.filter")));
        filters.add(filterField);
        JButton refresh = new JButton(I18n.get("process.refresh"));
        refresh.addActionListener(e -> refreshProcesses());
        filters.add(refresh);
        north.add(filters, BorderLayout.WEST);

        JPanel actions = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton injectGroup = new JButton(I18n.get("process.inject_group"));
        injectGroup.setToolTipText(I18n.get("process.inject_group_tip"));
        injectGroup.addActionListener(e -> injectSelected(true));
        JButton injectOne = new JButton(I18n.get("process.inject_one"));
        injectOne.setToolTipText(I18n.get("process.inject_one_tip"));
        injectOne.addActionListener(e -> injectSelected(false));
        JButton detach = new JButton(I18n.get("process.detach"));
        detach.addActionListener(e -> {
            statusLabel.setText(I18n.get("process.detached") + "…");
            new SwingWorker<Void, Void>() {
                @Override
                protected Void doInBackground() {
                    fridaController.detach();
                    return null;
                }

                @Override
                protected void done() {
                    statusLabel.setText(I18n.get("process.detached"));
                }
            }.execute();
        });
        actions.add(injectGroup);
        actions.add(injectOne);
        actions.add(detach);
        north.add(actions, BorderLayout.EAST);

        filterField.getDocument().addDocumentListener(new SimpleDocumentListener(this::applyFilter));

        JPanel south = new JPanel(new BorderLayout(4, 2));
        JLabel hint = new JLabel(I18n.get("process.role_hint"));
        south.add(hint, BorderLayout.NORTH);
        statusLabel.setPreferredSize(new Dimension(100, 20));
        south.add(statusLabel, BorderLayout.SOUTH);

        add(north, BorderLayout.NORTH);
        add(new JScrollPane(table), BorderLayout.CENTER);
        add(south, BorderLayout.SOUTH);

        fridaController.setStatusListener(msg ->
                javax.swing.SwingUtilities.invokeLater(() -> statusLabel.setText(msg)));

        refreshProcesses();
    }

    private void refreshProcesses() {
        statusLabel.setText(I18n.get("process.scanning"));
        new SwingWorker<List<ProcessInfo>, Void>() {
            @Override
            protected List<ProcessInfo> doInBackground() {
                return enumerator.listProcesses();
            }

            @Override
            protected void done() {
                try {
                    cache = get();
                    model.setRowCount(0);
                    for (ProcessInfo p : cache) {
                        model.addRow(new Object[]{
                                Boolean.FALSE,
                                p.pid(),
                                p.name(),
                                p.roleDisplay(),
                                p.user(),
                                p.displayPath()
                        });
                    }
                    statusLabel.setText(I18n.format("process.count", cache.size()));
                    applyFilter();
                } catch (Exception e) {
                    statusLabel.setText(I18n.format("process.failed", e.getMessage()));
                }
            }
        }.execute();
    }

    private void applyFilter() {
        String q = filterField.getText();
        if (q == null || q.isBlank()) {
            sorter.setRowFilter(null);
        } else {
            String needle = q.toLowerCase(java.util.Locale.ROOT);
            sorter.setRowFilter(new RowFilter<>() {
                @Override
                public boolean include(Entry<? extends DefaultTableModel, ? extends Integer> entry) {
                    int modelRow = entry.getIdentifier();
                    int pid = (Integer) model.getValueAt(modelRow, 1);
                    ProcessInfo info = cache.stream().filter(p -> p.pid() == pid).findFirst().orElse(null);
                    if (info != null) {
                        String hay = (info.name() + ' ' + info.role() + ' ' + info.user()
                                + ' ' + info.displayPath() + ' ' + info.displayCommandLine()
                                + ' ' + info.pid()).toLowerCase(java.util.Locale.ROOT);
                        return hay.contains(needle);
                    }
                    for (int i = 0; i < entry.getValueCount(); i++) {
                        Object v = entry.getValue(i);
                        if (v != null && String.valueOf(v).toLowerCase(java.util.Locale.ROOT).contains(needle)) {
                            return true;
                        }
                    }
                    return false;
                }
            });
        }
    }

    private void injectSelected(boolean group) {
        List<ProcessInfo> selected = resolveSelectedProcesses();
        if (selected.isEmpty()) {
            JOptionPane.showMessageDialog(this, I18n.get("process.select_first"), I18n.get("app.name"), JOptionPane.WARNING_MESSAGE);
            return;
        }

        ProcessInfo seed = selected.get(0);
        List<ProcessInfo> targets;
        if (!group) {
            targets = List.copyOf(selected);
        } else if (selected.size() > 1) {
            // Explicit multi-select: use those PIDs, still pull in ★ siblings of the same image.
            Map<Integer, ProcessInfo> uniq = new LinkedHashMap<>();
            for (ProcessInfo s : selected) {
                uniq.put(s.pid(), s);
                for (ProcessInfo rel : ProcessCaptureGroup.related(s, cache)) {
                    uniq.putIfAbsent(rel.pid(), rel);
                }
            }
            targets = List.copyOf(uniq.values());
        } else {
            targets = ProcessCaptureGroup.related(seed, cache);
        }
        if (targets.isEmpty()) {
            targets = List.of(seed);
        }

        String pidList = targets.stream()
                .map(p -> p.pid() + (p.role().isBlank() ? "" : "/" + p.role()))
                .reduce((a, b) -> a + ", " + b)
                .orElse(Integer.toString(seed.pid()));

        int confirm = JOptionPane.showConfirmDialog(
                this,
                I18n.format("process.confirm_inject", targets.size(), pidList),
                I18n.get("app.name"),
                JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.QUESTION_MESSAGE
        );
        if (confirm != JOptionPane.OK_OPTION) {
            return;
        }

        statusLabel.setText(I18n.format("process.injecting_group", targets.size(), pidList));
        List<ProcessInfo> finalTargets = targets;
        new SwingWorker<Void, Void>() {
            @Override
            protected Void doInBackground() throws Exception {
                fridaController.injectAndHook(finalTargets);
                return null;
            }

            @Override
            protected void done() {
                try {
                    get();
                    onAttached.accept(seed);
                    if (finalTargets.size() == 1) {
                        String role = seed.role();
                        if (!role.isBlank()) {
                            statusLabel.setText(I18n.format("process.hooked_role", seed.name(), seed.pid(), role));
                        } else {
                            statusLabel.setText(I18n.format("process.hooked", seed.name(), seed.pid()));
                        }
                    } else {
                        statusLabel.setText(I18n.format("process.hooked_group", finalTargets.size(), pidList));
                    }
                } catch (Exception e) {
                    statusLabel.setText(I18n.get("process.inject_failed"));
                    JOptionPane.showMessageDialog(
                            ProcessSelectorPanel.this,
                            I18n.format("process.inject_error", e.getMessage()),
                            I18n.get("app.name"),
                            JOptionPane.ERROR_MESSAGE
                    );
                }
            }
        }.execute();
    }

    /**
     * Prefer checkbox column (works inside Burp). Fall back to highlighted rows
     * (Shift-drag / Ctrl+click when the host does not steal modifiers).
     */
    private List<ProcessInfo> resolveSelectedProcesses() {
        Set<Integer> modelRows = new LinkedHashSet<>();
        for (int i = 0; i < model.getRowCount(); i++) {
            if (Boolean.TRUE.equals(model.getValueAt(i, 0))) {
                modelRows.add(i);
            }
        }
        if (modelRows.isEmpty()) {
            for (int viewRow : table.getSelectedRows()) {
                modelRows.add(table.convertRowIndexToModel(viewRow));
            }
        }
        List<ProcessInfo> selected = new ArrayList<>();
        for (int modelRow : modelRows) {
            int pid = (Integer) model.getValueAt(modelRow, 1);
            ProcessInfo info = cache.stream().filter(p -> p.pid() == pid).findFirst().orElse(null);
            if (info == null) {
                info = new ProcessInfo(
                        pid,
                        String.valueOf(model.getValueAt(modelRow, 2)),
                        String.valueOf(model.getValueAt(modelRow, 5)),
                        String.valueOf(model.getValueAt(modelRow, 4)),
                        ""
                );
            }
            selected.add(info);
        }
        return selected;
    }
}
