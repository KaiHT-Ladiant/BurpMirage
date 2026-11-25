package com.burpmirage.burp.model;

import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Derives a short Chromium/CEF/Electron-style process role from the command line
 * ({@code --type=} / {@code --utility-sub-type=}).
 */
public final class ProcessRole {
    private static final Pattern TYPE = Pattern.compile(
            "--type(?:=|\\s+)(\"[^\"]+\"|\\S+)", Pattern.CASE_INSENSITIVE);
    private static final Pattern UTILITY_SUB = Pattern.compile(
            "--utility-sub-type(?:=|\\s+)(\"[^\"]+\"|\\S+)", Pattern.CASE_INSENSITIVE);

    private ProcessRole() {
    }

    /**
     * @return short role label, or empty if unknown / not a multi-process Chromium-style app
     */
    public static String fromCommandLine(String commandLine) {
        if (commandLine == null || commandLine.isBlank()) {
            return "";
        }
        String sub = stripQuotes(match(UTILITY_SUB, commandLine));
        String type = stripQuotes(match(TYPE, commandLine));

        if (sub != null && !sub.isBlank()) {
            String pretty = prettySubType(sub);
            if (!pretty.isBlank()) {
                return pretty;
            }
        }

        if (type != null && !type.isBlank()) {
            return prettyType(type);
        }

        // Browser/Main process usually has no --type= (siblings do).
        if (looksLikeChromiumFamily(commandLine)) {
            return "Main";
        }
        return "";
    }

    /**
     * Roles that often carry app traffic in Chromium/Electron multi-process apps.
     * Not a guarantee — live TCP ownership ({@code ★}) is the stronger signal.
     */
    public static boolean inCaptureGroup(String role) {
        if (role == null || role.isBlank()) {
            return false;
        }
        String r = role.toLowerCase(Locale.ROOT);
        return r.equals("main")
                || r.equals("browser")
                || r.equals("renderer")
                || r.contains("networkservice")
                || r.equals("network")
                || r.equals("utility");
    }

    /** @deprecated use {@link #inCaptureGroup(String)} */
    public static boolean recommendedForHttp(String role) {
        return inCaptureGroup(role);
    }

    /** Lower is higher priority when sorting a capture group. */
    public static int capturePriority(String role) {
        if (role == null || role.isBlank()) {
            return 50;
        }
        String r = role.toLowerCase(Locale.ROOT);
        if (r.equals("renderer")) {
            return 10;
        }
        if (r.contains("network")) {
            return 20;
        }
        if (r.equals("main") || r.equals("browser")) {
            return 30;
        }
        if (r.equals("utility")) {
            return 40;
        }
        return 60;
    }

    public static String display(String role) {
        return display(role, 0);
    }

    /**
     * {@code ★} = owns live TCP sockets (inject here / include in group).
     * {@code ·} = typical Chromium capture-group role without current sockets.
     */
    public static String display(String role, int tcpSocketCount) {
        String base = (role == null || role.isBlank()) ? "—" : role;
        if (tcpSocketCount > 0) {
            return base + " ★";
        }
        if (inCaptureGroup(role)) {
            return base + " ·";
        }
        return base;
    }

    private static String prettySubType(String sub) {
        String s = sub.trim();
        // network.mojom.NetworkService → NetworkService
        int dot = s.lastIndexOf('.');
        if (dot >= 0 && dot < s.length() - 1) {
            s = s.substring(dot + 1);
        }
        if (s.toLowerCase(Locale.ROOT).contains("network")) {
            return "NetworkService";
        }
        if (s.toLowerCase(Locale.ROOT).contains("storage")) {
            return "StorageService";
        }
        if (s.toLowerCase(Locale.ROOT).contains("proxy")) {
            return "ProxyResolver";
        }
        if (s.isEmpty()) {
            return "";
        }
        return Character.toUpperCase(s.charAt(0)) + s.substring(1);
    }

    private static String prettyType(String type) {
        String t = type.trim().toLowerCase(Locale.ROOT);
        return switch (t) {
            case "browser" -> "Main";
            case "renderer" -> "Renderer";
            case "gpu-process", "gpu" -> "GPU";
            case "utility" -> "Utility";
            case "crashpad-handler", "crashpad" -> "Crashpad";
            case "ppapi", "ppapi-broker" -> "PPAPI";
            case "zygote" -> "Zygote";
            default -> {
                if (t.isEmpty()) {
                    yield "";
                }
                yield Character.toUpperCase(type.trim().charAt(0)) + type.trim().substring(1);
            }
        };
    }

    private static boolean looksLikeChromiumFamily(String cmd) {
        String c = cmd.toLowerCase(Locale.ROOT);
        return c.contains("--mojo-platform-channel-handle")
                || c.contains("--field-trial-handle")
                || c.contains("--launch-time-ticks")
                || c.contains("--enable-features=")
                || c.contains("--disable-features=")
                || c.contains("--visited-link-salt")
                || c.contains("chrome_elf");
    }

    private static String match(Pattern p, String text) {
        Matcher m = p.matcher(text);
        if (m.find()) {
            return m.group(1);
        }
        return null;
    }

    private static String stripQuotes(String s) {
        if (s == null) {
            return null;
        }
        String t = s.trim();
        if (t.length() >= 2 && t.startsWith("\"") && t.endsWith("\"")) {
            return t.substring(1, t.length() - 1);
        }
        return t;
    }
}
