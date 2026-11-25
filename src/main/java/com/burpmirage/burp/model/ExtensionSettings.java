package com.burpmirage.burp.model;

import java.nio.file.Path;
import java.util.prefs.Preferences;

/**
 * Persistent and runtime settings for the extension.
 */
public final class ExtensionSettings {
    private static final String PREF_NODE = "com.burpmirage.burp";

    private int bridgePort = 27042;
    private boolean interceptEnabled = false;
    private boolean hookSend = true;
    private boolean hookRecv = true;
    private boolean autoForwardEmpty = true;
    private int maxHistory = 5000;
    private String fridaPath = "frida";
    private String pythonPath = "python";
    private String bridgeExePath = "";
    private String searchPattern = "";
    private String replacePattern = "";
    private Path logFile;
    /** Mode A: force WinHTTP/WinInet named proxy to Burp. */
    private boolean modeProxyForce = true;
    /** Mode B: Winsock send/recv intercept (Mirage). */
    private boolean modeSocketMirage = true;
    /** Mode C: TLS cert unpin (Chromium/BoringSSL + Schannel) for Burp MITM. */
    private boolean modeTlsUnpin = true;
    private String burpProxyHost = "127.0.0.1";
    private int burpProxyPort = 8800;

    public int bridgePort() {
        return bridgePort;
    }

    public void setBridgePort(int bridgePort) {
        this.bridgePort = bridgePort;
    }

    public boolean interceptEnabled() {
        return interceptEnabled;
    }

    public void setInterceptEnabled(boolean interceptEnabled) {
        this.interceptEnabled = interceptEnabled;
    }

    public boolean hookSend() {
        return hookSend;
    }

    public void setHookSend(boolean hookSend) {
        this.hookSend = hookSend;
    }

    public boolean hookRecv() {
        return hookRecv;
    }

    public void setHookRecv(boolean hookRecv) {
        this.hookRecv = hookRecv;
    }

    public boolean autoForwardEmpty() {
        return autoForwardEmpty;
    }

    public void setAutoForwardEmpty(boolean autoForwardEmpty) {
        this.autoForwardEmpty = autoForwardEmpty;
    }

    public int maxHistory() {
        return maxHistory;
    }

    public void setMaxHistory(int maxHistory) {
        this.maxHistory = Math.max(100, maxHistory);
    }

    public String fridaPath() {
        return fridaPath;
    }

    public void setFridaPath(String fridaPath) {
        this.fridaPath = fridaPath == null || fridaPath.isBlank() ? "frida" : fridaPath.trim();
    }

    public String pythonPath() {
        return pythonPath;
    }

    public void setPythonPath(String pythonPath) {
        this.pythonPath = pythonPath == null || pythonPath.isBlank() ? "python" : pythonPath.trim();
    }

    public String bridgeExePath() {
        return bridgeExePath;
    }

    public void setBridgeExePath(String bridgeExePath) {
        this.bridgeExePath = bridgeExePath == null ? "" : bridgeExePath.trim();
    }

    public String searchPattern() {
        return searchPattern;
    }

    public void setSearchPattern(String searchPattern) {
        this.searchPattern = searchPattern == null ? "" : searchPattern;
    }

    public String replacePattern() {
        return replacePattern;
    }

    public void setReplacePattern(String replacePattern) {
        this.replacePattern = replacePattern == null ? "" : replacePattern;
    }

    public Path logFile() {
        return logFile;
    }

    public void setLogFile(Path logFile) {
        this.logFile = logFile;
    }


    public boolean modeProxyForce() {
        return modeProxyForce;
    }

    public void setModeProxyForce(boolean modeProxyForce) {
        this.modeProxyForce = modeProxyForce;
    }

    public boolean modeSocketMirage() {
        return modeSocketMirage;
    }

    public void setModeSocketMirage(boolean modeSocketMirage) {
        this.modeSocketMirage = modeSocketMirage;
    }

    public boolean modeTlsUnpin() {
        return modeTlsUnpin;
    }

    public void setModeTlsUnpin(boolean modeTlsUnpin) {
        this.modeTlsUnpin = modeTlsUnpin;
    }

    public String burpProxyHost() {
        return burpProxyHost;
    }

    public void setBurpProxyHost(String burpProxyHost) {
        this.burpProxyHost = burpProxyHost == null || burpProxyHost.isBlank()
                ? "127.0.0.1" : burpProxyHost.trim();
    }

    public int burpProxyPort() {
        return burpProxyPort;
    }

    public void setBurpProxyPort(int burpProxyPort) {
        this.burpProxyPort = Math.max(1, Math.min(65535, burpProxyPort));
    }

    public void load() {
        Preferences p = Preferences.userRoot().node(PREF_NODE);
        bridgePort = p.getInt("bridgePort", 27042);
        interceptEnabled = p.getBoolean("interceptEnabled", true);
        hookSend = p.getBoolean("hookSend", true);
        hookRecv = p.getBoolean("hookRecv", true);
        autoForwardEmpty = p.getBoolean("autoForwardEmpty", true);
        maxHistory = p.getInt("maxHistory", 5000);
        fridaPath = p.get("fridaPath", "frida");
        pythonPath = p.get("pythonPath", "python");
        bridgeExePath = p.get("bridgeExePath", "");
        modeProxyForce = p.getBoolean("modeProxyForce", true);
        modeSocketMirage = p.getBoolean("modeSocketMirage", true);
        modeTlsUnpin = p.getBoolean("modeTlsUnpin", true);
        burpProxyHost = p.get("burpProxyHost", "127.0.0.1");
        burpProxyPort = p.getInt("burpProxyPort", 8800);
        String log = p.get("logFile", "");
        if (!log.isBlank()) {
            logFile = Path.of(log);
        }
        // Auto-fix Python that actually has the frida module when default/broken.
        resolvePythonIfNeeded();
    }

    /**
     * If configured python cannot import frida, try to detect a working interpreter.
     */
    public void resolvePythonIfNeeded() {
        if (com.burpmirage.burp.util.PythonDetector.hasFrida(pythonPath)) {
            return;
        }
        String detected = com.burpmirage.burp.util.PythonDetector.detectPythonWithFrida();
        if (detected != null) {
            pythonPath = detected;
            Preferences.userRoot().node(PREF_NODE).put("pythonPath", pythonPath);
        }
    }

    public void save() {
        Preferences p = Preferences.userRoot().node(PREF_NODE);
        p.putInt("bridgePort", bridgePort);
        p.putBoolean("interceptEnabled", interceptEnabled);
        p.putBoolean("hookSend", hookSend);
        p.putBoolean("hookRecv", hookRecv);
        p.putBoolean("autoForwardEmpty", autoForwardEmpty);
        p.putInt("maxHistory", maxHistory);
        p.put("fridaPath", fridaPath);
        p.put("pythonPath", pythonPath);
        p.put("bridgeExePath", bridgeExePath);
        p.putBoolean("modeProxyForce", modeProxyForce);
        p.putBoolean("modeSocketMirage", modeSocketMirage);
        p.putBoolean("modeTlsUnpin", modeTlsUnpin);
        p.put("burpProxyHost", burpProxyHost);
        p.putInt("burpProxyPort", burpProxyPort);
        p.put("logFile", logFile == null ? "" : logFile.toString());
    }
}
