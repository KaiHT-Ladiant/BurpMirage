package com.burpmirage.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.UserInterface;
import com.burpmirage.burp.intercept.HistoryStore;
import com.burpmirage.burp.intercept.InterceptController;
import com.burpmirage.burp.intercept.PacketQueue;
import com.burpmirage.burp.model.ExtensionSettings;
import com.burpmirage.burp.nativebridge.BridgeServer;
import com.burpmirage.burp.nativebridge.FridaController;
import com.burpmirage.burp.ui.MainPanel;
import com.burpmirage.burp.util.I18n;
import com.burpmirage.burp.util.PacketLogger;

/**
 * BurpMirage — Burp Suite extension entry point (Montoya API).
 *
 * Architecture:
 *   Burp UI (this extension)
 *        ↕ TCP JSON-lines (127.0.0.1)
 *   Python Frida host (frida_bridge.py)
 *        ↕ Frida
 *   Target process (ws2_32 send/recv hooks)
 */
public final class BurpMirageExtension implements BurpExtension {
    private BridgeServer bridge;
    private FridaController frida;
    private PacketLogger logger;

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("BurpMirage");
        api.logging().logToOutput(I18n.get("ext.init"));

        ExtensionSettings settings = new ExtensionSettings();
        settings.load();

        logger = new PacketLogger();
        if (settings.logFile() != null) {
            try {
                logger.setPath(settings.logFile());
            } catch (Exception e) {
                api.logging().logToError(I18n.format("ext.log_open_error", e.getMessage()));
            }
        }

        PacketQueue queue = new PacketQueue();
        HistoryStore history = new HistoryStore(settings, logger);
        InterceptController controller = new InterceptController(settings, queue, history, api.logging());

        bridge = new BridgeServer(settings, controller, api.logging());
        frida = new FridaController(settings, api.logging());
        frida.setBridgeServer(bridge);

        try {
            bridge.start();
        } catch (Exception e) {
            api.logging().logToError(I18n.format("ext.bridge_error", settings.bridgePort(), e.getMessage()));
        }

        UserInterface ui = api.userInterface();
        MainPanel panel = new MainPanel(settings, controller, bridge, frida, logger);
        ui.registerSuiteTab("BurpMirage", panel);

        api.extension().registerUnloadingHandler(() -> {
            api.logging().logToOutput(I18n.get("ext.unloading"));
            if (frida != null) {
                frida.close();
            }
            if (bridge != null) {
                bridge.close();
            }
            if (logger != null) {
                logger.close();
            }
        });

        api.logging().logToOutput(I18n.format("ext.ready", settings.bridgePort()));
    }
}
