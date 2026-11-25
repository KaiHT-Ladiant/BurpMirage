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

    /** True when this role is the usual place to catch HTTP/TLS. */
    public static boolean recommendedForHttp(String role) {
        if (role == null || role.isBlank()) {
            return false;
        }
        String r = role.toLowerCase(Locale.ROOT);
        return r.equals("main")
                || r.equals("browser")
                || r.contains("networkservice")
                || r.equals("network");
    }

    public static String display(String role) {
        if (role == null || role.isBlank()) {
            return "—";
        }
        if (recommendedForHttp(role)) {
            return role + " ★";
        }
        return role;
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
