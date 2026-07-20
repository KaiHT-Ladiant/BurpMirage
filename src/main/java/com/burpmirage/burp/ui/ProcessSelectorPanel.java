package com.burpmirage.burp.ui;

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
import javax.swing.SwingWorker;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.util.List;
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

        model = new DefaultTableModel(new Object[]{"PID", "Name", "User", "Path"}, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }

            @Override
            public Class<?> getColumnClass(int columnIndex) {
                return columnIndex == 0 ? Integer.class : String.class;
            }
        };
        table = new JTable(model);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setAutoCreateRowSorter(true);
        sorter = new TableRowSorter<>(model);
        table.setRowSorter(sorter);
        table.getColumnModel().getColumn(0).setPreferredWidth(70);
        table.getColumnModel().getColumn(1).setPreferredWidth(140);
        table.getColumnModel().getColumn(2).setPreferredWidth(100);
        table.getColumnModel().getColumn(3).setPreferredWidth(420);

        JPanel north = new JPanel(new BorderLayout(8, 0));
        JPanel filters = new JPanel(new FlowLayout(FlowLayout.LEFT));
        filters.add(new JLabel(I18n.get("process.filter")));
        filters.add(filterField);
        JButton refresh = new JButton(I18n.get("process.refresh"));
        refresh.addActionListener(e -> refreshProcesses());
        filters.add(refresh);
        north.add(filters, BorderLayout.WEST);

        JPanel actions = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton inject = new JButton(I18n.get("process.inject"));
        inject.addActionListener(e -> injectSelected());
        JButton detach = new JButton(I18n.get("process.detach"));
        detach.addActionListener(e -> {
            fridaController.detach();
            statusLabel.setText(I18n.get("process.detached"));
        });
        actions.add(inject);
        actions.add(detach);
        north.add(actions, BorderLayout.EAST);

        filterField.getDocument().addDocumentListener(new SimpleDocumentListener(this::applyFilter));

        add(north, BorderLayout.NORTH);
        add(new JScrollPane(table), BorderLayout.CENTER);
        statusLabel.setPreferredSize(new Dimension(100, 20));
        add(statusLabel, BorderLayout.SOUTH);

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
                        model.addRow(new Object[]{p.pid(), p.name(), p.user(), p.displayPath()});
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
            sorter.setRowFilter(RowFilter.regexFilter("(?i)" + java.util.regex.Pattern.quote(q)));
        }
    }

    private void injectSelected() {
        int viewRow = table.getSelectedRow();
        if (viewRow < 0) {
            JOptionPane.showMessageDialog(this, I18n.get("process.select_first"), I18n.get("app.name"), JOptionPane.WARNING_MESSAGE);
            return;
        }
        int modelRow = table.convertRowIndexToModel(viewRow);
        int pid = (Integer) model.getValueAt(modelRow, 0);
        ProcessInfo info = cache.stream().filter(p -> p.pid() == pid).findFirst().orElse(null);
        if (info == null) {
            info = new ProcessInfo(pid, String.valueOf(model.getValueAt(modelRow, 1)),
                    String.valueOf(model.getValueAt(modelRow, 3)),
                    String.valueOf(model.getValueAt(modelRow, 2)));
        }

        ProcessInfo target = info;
        statusLabel.setText(I18n.get("process.injecting"));
        new SwingWorker<Void, Void>() {
            @Override
            protected Void doInBackground() throws Exception {
                fridaController.injectAndHook(target);
                return null;
            }

            @Override
            protected void done() {
                try {
                    get();
                    onAttached.accept(target);
                    statusLabel.setText(I18n.format("process.hooked", target.name(), target.pid()));
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
}
