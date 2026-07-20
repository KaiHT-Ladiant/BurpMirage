package com.burpmirage.burp.ui;

import com.burpmirage.burp.model.ExtensionSettings;
import com.burpmirage.burp.nativebridge.BridgeServer;
import com.burpmirage.burp.util.I18n;
import com.burpmirage.burp.util.PacketLogger;
import com.burpmirage.burp.util.PythonDetector;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JSpinner;
import javax.swing.JTextField;
import javax.swing.SpinnerNumberModel;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import java.awt.BorderLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.nio.file.Path;

/**
 * Extension settings: bridge port, Frida/Python paths, hooks, logging.
 */
public final class SettingsPanel extends JPanel {
    private final ExtensionSettings settings;
    private final BridgeServer bridge;
    private final PacketLogger logger;

    private final JSpinner portSpinner;
    private final JTextField fridaPath = new JTextField(28);
    private final JTextField pythonPath = new JTextField(28);
    private final JTextField bridgeExe = new JTextField(28);
    private final JTextField searchField = new JTextField(20);
    private final JTextField replaceField = new JTextField(20);
    private final JTextField logPath = new JTextField(28);
    private final JCheckBox hookSend = new JCheckBox(I18n.get("settings.hook_send"));
    private final JCheckBox hookRecv = new JCheckBox(I18n.get("settings.hook_recv"));
    private final JCheckBox autoEmpty = new JCheckBox(I18n.get("settings.auto_empty"));
    private final JSpinner historySpinner;
    private final JLabel bridgeStatus = new JLabel(" ");

    public SettingsPanel(ExtensionSettings settings, BridgeServer bridge, PacketLogger logger) {
        super(new BorderLayout(8, 8));
        this.settings = settings;
        this.bridge = bridge;
        this.logger = logger;
        setBorder(new EmptyBorder(8, 8, 8, 8));

        portSpinner = new JSpinner(new SpinnerNumberModel(settings.bridgePort(), 1024, 65535, 1));
        historySpinner = new JSpinner(new SpinnerNumberModel(settings.maxHistory(), 100, 100000, 100));

        JPanel form = new JPanel(new GridBagLayout());
        form.setBorder(new TitledBorder(I18n.get("settings.conn")));
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(4, 4, 4, 4);
        c.anchor = GridBagConstraints.WEST;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.weightx = 1;

        int row = 0;
        row = addRow(form, c, row, I18n.get("settings.bridge_port"), portSpinner);
        row = addRow(form, c, row, I18n.get("settings.bridge_exe"), bridgeExe);
        row = addRow(form, c, row, I18n.get("settings.python_path"), pythonPath);
        row = addRow(form, c, row, I18n.get("settings.frida_cli"), fridaPath);
        row = addRow(form, c, row, I18n.get("settings.max_history"), historySpinner);

        c.gridx = 1;
        c.gridy = row;
        form.add(new JLabel(I18n.get("settings.bridge_exe_hint")), c);
        row++;

        fridaPath.setText(settings.fridaPath());
        bridgeExe.setText(settings.bridgeExePath());
        settings.resolvePythonIfNeeded();
        pythonPath.setText(settings.pythonPath());
        searchField.setText(settings.searchPattern());
        replaceField.setText(settings.replacePattern());
        if (settings.logFile() != null) {
            logPath.setText(settings.logFile().toString());
        }
        hookSend.setSelected(settings.hookSend());
        hookRecv.setSelected(settings.hookRecv());
        autoEmpty.setSelected(settings.autoForwardEmpty());

        JPanel hooks = new JPanel(new GridBagLayout());
        hooks.setBorder(new TitledBorder(I18n.get("settings.hooks")));
        GridBagConstraints h = new GridBagConstraints();
        h.insets = new Insets(4, 4, 4, 4);
        h.anchor = GridBagConstraints.WEST;
        h.gridx = 0;
        h.gridy = 0;
        hooks.add(hookSend, h);
        h.gridy = 1;
        hooks.add(hookRecv, h);
        h.gridy = 2;
        hooks.add(autoEmpty, h);
        h.gridy = 3;
        hooks.add(new JLabel(I18n.get("settings.recv_note")), h);
        h.gridy = 4;
        hooks.add(new JLabel(I18n.get("settings.find")), h);
        h.gridy = 5;
        h.fill = GridBagConstraints.HORIZONTAL;
        h.weightx = 1;
        hooks.add(searchField, h);
        h.gridy = 6;
        hooks.add(new JLabel(I18n.get("settings.replace")), h);
        h.gridy = 7;
        hooks.add(replaceField, h);

        JPanel logPanel = new JPanel(new GridBagLayout());
        logPanel.setBorder(new TitledBorder(I18n.get("settings.logging")));
        GridBagConstraints l = new GridBagConstraints();
        l.insets = new Insets(4, 4, 4, 4);
        l.anchor = GridBagConstraints.WEST;
        l.fill = GridBagConstraints.HORIZONTAL;
        l.weightx = 1;
        l.gridx = 0;
        l.gridy = 0;
        logPanel.add(logPath, l);
        JButton browse = new JButton(I18n.get("settings.browse"));
        browse.addActionListener(e -> chooseLog());
        l.gridx = 1;
        l.weightx = 0;
        logPanel.add(browse, l);

        JPanel actions = new JPanel();
        JButton save = new JButton(I18n.get("settings.save"));
        JButton browseExe = new JButton(I18n.get("settings.browse_exe"));
        browseExe.addActionListener(e -> chooseBridgeExe());
        JButton detectPy = new JButton(I18n.get("settings.detect_py"));
        JButton startBridge = new JButton(I18n.get("settings.start_bridge"));
        JButton stopBridge = new JButton(I18n.get("settings.stop_bridge"));
        save.addActionListener(e -> saveSettings());
        detectPy.addActionListener(e -> {
            String found = PythonDetector.detectPythonWithFrida();
            if (found != null) {
                pythonPath.setText(found);
                settings.setPythonPath(found);
                settings.save();
                JOptionPane.showMessageDialog(this,
                        I18n.format("settings.py_found", found),
                        I18n.get("app.name"), JOptionPane.INFORMATION_MESSAGE);
            } else {
                JOptionPane.showMessageDialog(this,
                        PythonDetector.diagnosis(),
                        I18n.get("app.name"), JOptionPane.ERROR_MESSAGE);
            }
        });
        startBridge.addActionListener(e -> startBridge());
        stopBridge.addActionListener(e -> {
            bridge.stop();
            bridgeStatus.setText(I18n.get("settings.bridge_stopped"));
        });
        actions.add(save);
        actions.add(browseExe);
        actions.add(detectPy);
        actions.add(startBridge);
        actions.add(stopBridge);
        actions.add(bridgeStatus);

        JPanel center = new JPanel(new BorderLayout(8, 8));
        center.add(form, BorderLayout.NORTH);
        center.add(hooks, BorderLayout.CENTER);
        center.add(logPanel, BorderLayout.SOUTH);

        add(center, BorderLayout.CENTER);
        add(actions, BorderLayout.SOUTH);

        bridge.setStatusListener(msg ->
                javax.swing.SwingUtilities.invokeLater(() -> bridgeStatus.setText(msg)));
    }

    private int addRow(JPanel form, GridBagConstraints c, int row, String label, java.awt.Component field) {
        c.gridx = 0;
        c.gridy = row;
        c.weightx = 0;
        form.add(new JLabel(label), c);
        c.gridx = 1;
        c.weightx = 1;
        form.add(field, c);
        return row + 1;
    }

    private void chooseBridgeExe() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle(I18n.get("settings.bridge_exe"));
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            bridgeExe.setText(chooser.getSelectedFile().getAbsolutePath());
        }
    }

    private void chooseLog() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle(I18n.get("settings.log_dialog"));
        if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            logPath.setText(chooser.getSelectedFile().getAbsolutePath());
        }
    }

    private void saveSettings() {
        settings.setBridgePort((Integer) portSpinner.getValue());
        settings.setFridaPath(fridaPath.getText());
        settings.setPythonPath(pythonPath.getText());
        settings.setBridgeExePath(bridgeExe.getText());
        settings.setMaxHistory((Integer) historySpinner.getValue());
        settings.setHookSend(hookSend.isSelected());
        settings.setHookRecv(hookRecv.isSelected());
        settings.setAutoForwardEmpty(autoEmpty.isSelected());
        settings.setSearchPattern(searchField.getText());
        settings.setReplacePattern(replaceField.getText());
        String lp = logPath.getText();
        if (lp != null && !lp.isBlank()) {
            settings.setLogFile(Path.of(lp));
            try {
                logger.setPath(settings.logFile());
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, I18n.format("settings.log_error", ex.getMessage()));
            }
        }
        settings.save();
        bridge.pushConfig();
        JOptionPane.showMessageDialog(this, I18n.get("settings.saved"), I18n.get("app.name"), JOptionPane.INFORMATION_MESSAGE);
    }

    private void startBridge() {
        try {
            settings.setBridgePort((Integer) portSpinner.getValue());
            if (bridge.isRunning()) {
                bridge.stop();
            }
            bridge.start();
            bridgeStatus.setText(I18n.format("settings.listening", settings.bridgePort()));
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, I18n.format("settings.bridge_error", e.getMessage()));
        }
    }
}
