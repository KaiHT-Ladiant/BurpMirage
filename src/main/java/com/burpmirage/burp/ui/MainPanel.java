package com.burpmirage.burp.ui;

import com.burpmirage.burp.intercept.InterceptController;
import com.burpmirage.burp.model.ExtensionSettings;
import com.burpmirage.burp.nativebridge.BridgeServer;
import com.burpmirage.burp.nativebridge.FridaController;
import com.burpmirage.burp.util.I18n;
import com.burpmirage.burp.util.PacketLogger;

import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.KeyEventDispatcher;
import java.awt.KeyboardFocusManager;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

/**
 * Root suite-tab UI hosting Process / Intercept / History / PCAP / Repeater / Settings.
 * Suite-wide shortcuts (when focus is inside BurpMirage):
 *   Ctrl+T — Intercept ON/OFF
 *   Ctrl+R — Send to Repeater (Intercept/History) or Send (Repeater tab)
 */
public final class MainPanel extends JPanel {
    private final JTabbedPane tabs = new JTabbedPane();
    private final InterceptorPanel interceptor;
    private final HistoryPanel history;
    private final RepeaterPanel repeaterPanel;
    private final KeyEventDispatcher shortcutDispatcher;

    public MainPanel(
            ExtensionSettings settings,
            InterceptController controller,
            BridgeServer bridge,
            FridaController frida,
            PacketLogger logger
    ) {
        super(new BorderLayout());

        repeaterPanel = new RepeaterPanel(bridge, controller.history());

        ProcessSelectorPanel processes = new ProcessSelectorPanel(frida, process -> {
            controller.setAttachedProcessName(process.name());
            tabs.setSelectedIndex(1);
        });

        interceptor = new InterceptorPanel(
                controller,
                settings,
                packet -> {
                    repeaterPanel.load(packet);
                    tabs.setSelectedComponent(repeaterPanel);
                }
        );

        history = new HistoryPanel(controller.history(), packet -> {
            repeaterPanel.load(packet);
            tabs.setSelectedComponent(repeaterPanel);
        });

        PcapPanel pcap = new PcapPanel(
                packet -> {
                    repeaterPanel.load(packet);
                    tabs.setSelectedComponent(repeaterPanel);
                },
                history::highlightContaining,
                () -> tabs.setSelectedComponent(repeaterPanel),
                () -> tabs.setSelectedComponent(history)
        );

        SettingsPanel settingsPanel = new SettingsPanel(settings, bridge, logger);

        tabs.addTab(I18n.get("tab.process"), processes);
        tabs.addTab(I18n.get("tab.intercept"), interceptor);
        tabs.addTab(I18n.get("tab.history"), history);
        tabs.addTab(I18n.get("tab.pcap"), pcap);
        tabs.addTab(I18n.get("tab.repeater"), repeaterPanel);
        tabs.addTab(I18n.get("tab.settings"), settingsPanel);

        add(tabs, BorderLayout.CENTER);

        shortcutDispatcher = this::dispatchShortcut;
        KeyboardFocusManager.getCurrentKeyboardFocusManager()
                .addKeyEventDispatcher(shortcutDispatcher);
    }

    public JTabbedPane tabs() {
        return tabs;
    }

    private boolean dispatchShortcut(KeyEvent e) {
        if (e.getID() != KeyEvent.KEY_PRESSED) {
            return false;
        }
        if (!isShowing()) {
            return false;
        }
        Component focus = KeyboardFocusManager.getCurrentKeyboardFocusManager().getFocusOwner();
        if (focus == null || !SwingUtilities.isDescendingFrom(focus, this)) {
            return false;
        }
        boolean ctrl = (e.getModifiersEx() & InputEvent.CTRL_DOWN_MASK) != 0;
        boolean shift = (e.getModifiersEx() & InputEvent.SHIFT_DOWN_MASK) != 0;
        boolean alt = (e.getModifiersEx() & InputEvent.ALT_DOWN_MASK) != 0;
        if (!ctrl || alt) {
            return false;
        }
        int code = e.getKeyCode();

        // Ctrl+T — Intercept ON/OFF (BurpMirage-wide)
        if (code == KeyEvent.VK_T && !shift) {
            SwingUtilities.invokeLater(interceptor::toggleIntercept);
            e.consume();
            return true;
        }

        // Ctrl+R — Send to Repeater, or Send on Repeater tab
        if (code == KeyEvent.VK_R && !shift) {
            Component selected = tabs.getSelectedComponent();
            SwingUtilities.invokeLater(() -> {
                if (selected == repeaterPanel) {
                    repeaterPanel.sendRequest();
                } else if (selected == interceptor) {
                    interceptor.sendCurrentToRepeater();
                } else if (selected == history) {
                    history.sendSelectedToRepeater();
                } else {
                    // Other tabs: prefer intercept packet, else history selection
                    if (!interceptor.sendCurrentToRepeater()) {
                        history.sendSelectedToRepeater();
                    }
                }
            });
            e.consume();
            return true;
        }

        return false;
    }
}
