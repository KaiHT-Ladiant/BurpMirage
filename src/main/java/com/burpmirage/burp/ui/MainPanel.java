package com.burpmirage.burp.ui;

import com.burpmirage.burp.intercept.InterceptController;
import com.burpmirage.burp.model.ExtensionSettings;
import com.burpmirage.burp.nativebridge.BridgeServer;
import com.burpmirage.burp.nativebridge.FridaController;
import com.burpmirage.burp.util.I18n;
import com.burpmirage.burp.util.PacketLogger;

import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import java.awt.BorderLayout;

/**
 * Root suite-tab UI hosting Process / Intercept / History / Repeater / Settings.
 */
public final class MainPanel extends JPanel {
    private final JTabbedPane tabs = new JTabbedPane();

    public MainPanel(
            ExtensionSettings settings,
            InterceptController controller,
            BridgeServer bridge,
            FridaController frida,
            PacketLogger logger
    ) {
        super(new BorderLayout());

        RepeaterPanel repeaterPanel = new RepeaterPanel(bridge, controller.history());

        ProcessSelectorPanel processes = new ProcessSelectorPanel(frida, process -> {
            controller.setAttachedProcessName(process.name());
            tabs.setSelectedIndex(1);
        });

        InterceptorPanel interceptor = new InterceptorPanel(
                controller,
                settings,
                packet -> {
                    repeaterPanel.load(packet);
                    tabs.setSelectedIndex(3);
                }
        );

        HistoryPanel history = new HistoryPanel(controller.history(), packet -> {
            repeaterPanel.load(packet);
            tabs.setSelectedIndex(3);
        });
        SettingsPanel settingsPanel = new SettingsPanel(settings, bridge, logger);

        tabs.addTab(I18n.get("tab.process"), processes);
        tabs.addTab(I18n.get("tab.intercept"), interceptor);
        tabs.addTab(I18n.get("tab.history"), history);
        tabs.addTab(I18n.get("tab.repeater"), repeaterPanel);
        tabs.addTab(I18n.get("tab.settings"), settingsPanel);

        add(tabs, BorderLayout.CENTER);
    }

    public JTabbedPane tabs() {
        return tabs;
    }
}
