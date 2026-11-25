package com.burpmirage.burp.nativebridge;

import com.burpmirage.burp.model.ProcessInfo;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Enumerates running Windows processes via PowerShell / tasklist.
 */
public final class ProcessEnumerator {
    private static final Pattern CSV_SPLIT = Pattern.compile(",(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)");

    public List<ProcessInfo> listProcesses() {
        List<ProcessInfo> viaPs = listViaPowerShell();
        List<ProcessInfo> base = !viaPs.isEmpty() ? viaPs : listViaTasklist();
        return enrichTcpOwnership(base);
    }

    /** Mark processes that currently own Established/Listen TCP sockets (★ in UI). */
    private static List<ProcessInfo> enrichTcpOwnership(List<ProcessInfo> input) {
        Map<Integer, Integer> counts = countTcpByPid();
        if (counts.isEmpty()) {
            return input;
        }
        List<ProcessInfo> out = new ArrayList<>(input.size());
        for (ProcessInfo p : input) {
            Integer n = counts.get(p.pid());
            out.add(n == null || n == 0 ? p : p.withTcpSocketCount(n));
        }
        return out;
    }

    private static Map<Integer, Integer> countTcpByPid() {
        // netstat is more reliable from Burp's JVM (Get-NetTCPConnection often needs elevation).
        Map<Integer, Integer> viaNetstat = countTcpByPidNetstat();
        if (!viaNetstat.isEmpty()) {
            return viaNetstat;
        }
        return countTcpByPidPowerShell();
    }

    private static Map<Integer, Integer> countTcpByPidNetstat() {
        Map<Integer, Integer> counts = new LinkedHashMap<>();
        try {
            ProcessBuilder pb = new ProcessBuilder("netstat.exe", "-ano", "-p", "tcp");
            pb.redirectErrorStream(true);
            Process process = pb.start();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream(), windowsConsoleCharset()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    String t = line.trim();
                    if (t.isEmpty()) {
                        continue;
                    }
                    String upper = t.toUpperCase(Locale.ROOT);
                    // TCP  1.2.3.4:443  5.6.7.8:12345  ESTABLISHED  22044
                    if (!upper.startsWith("TCP")) {
                        continue;
                    }
                    if (!upper.contains("ESTABLISHED") && !upper.contains("LISTENING") && !upper.contains("LISTEN")) {
                        continue;
                    }
                    String[] parts = t.split("\\s+");
                    if (parts.length < 5) {
                        continue;
                    }
                    int pid = parseInt(parts[parts.length - 1]);
                    if (pid > 0) {
                        counts.merge(pid, 1, Integer::sum);
                    }
                }
            }
            process.waitFor();
        } catch (Exception ignored) {
            return Map.of();
        }
        return counts;
    }

    private static Map<Integer, Integer> countTcpByPidPowerShell() {
        Map<Integer, Integer> counts = new LinkedHashMap<>();
        try {
            ProcessBuilder pb = new ProcessBuilder(
                    "powershell.exe",
                    "-NoProfile",
                    "-Command",
                    "Get-NetTCPConnection -State Established,Listen -ErrorAction SilentlyContinue | "
                            + "Group-Object OwningProcess | "
                            + "ForEach-Object { '{0},{1}' -f $_.Name, $_.Count }"
            );
            pb.redirectErrorStream(true);
            Process process = pb.start();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    String[] parts = line.trim().split(",");
                    if (parts.length < 2) {
                        continue;
                    }
                    int pid = parseInt(parts[0]);
                    int n = parseInt(parts[1]);
                    if (pid > 0 && n > 0) {
                        counts.put(pid, n);
                    }
                }
            }
            process.waitFor();
        } catch (Exception ignored) {
            return Map.of();
        }
        return counts;
    }

    private List<ProcessInfo> listViaPowerShell() {
        List<ProcessInfo> result = new ArrayList<>();
        try {
            ProcessBuilder pb = new ProcessBuilder(
                    "powershell.exe",
                    "-NoProfile",
                    "-Command",
                    "Get-CimInstance Win32_Process | " +
                            "Select-Object ProcessId,Name,ExecutablePath,CommandLine," +
                            " @{N='User';E={try{$_.GetOwner().User}catch{''}}} | " +
                            "ConvertTo-Csv -NoTypeInformation"
            );
            pb.redirectErrorStream(true);
            Process process = pb.start();
            Charset cs = windowsConsoleCharset();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream(), cs))) {
                String header = reader.readLine();
                if (header == null) {
                    return result;
                }
                String line;
                while ((line = reader.readLine()) != null) {
                    String[] cols = CSV_SPLIT.split(line, -1);
                    if (cols.length < 3) {
                        continue;
                    }
                    int pid = parseInt(unquote(cols[0]));
                    String name = unquote(cols[1]);
                    String path = unquote(cols[2]);
                    String commandLine = cols.length > 3 ? unquote(cols[3]) : "";
                    String user = cols.length > 4 ? unquote(cols[4]) : "";
                    if (pid > 0 && !name.isBlank()) {
                        result.add(new ProcessInfo(pid, name, path, user, commandLine));
                    }
                }
            }
            process.waitFor();
        } catch (Exception ignored) {
            return List.of();
        }
        List<ProcessInfo> enriched = enrichChromiumMainRoles(result);
        enriched.sort(Comparator.comparing(ProcessInfo::name, String.CASE_INSENSITIVE_ORDER)
                .thenComparing(ProcessInfo::role, String.CASE_INSENSITIVE_ORDER)
                .thenComparingInt(ProcessInfo::pid));
        return enriched;
    }

    /**
     * Electron/Chromium browser process often has a bare cmdline (exe only, no {@code --type=}).
     * When siblings of the same path use {@code --type=}, label the bare one as Main.
     */
    private static List<ProcessInfo> enrichChromiumMainRoles(List<ProcessInfo> input) {
        Map<String, List<ProcessInfo>> byKey = new LinkedHashMap<>();
        for (ProcessInfo p : input) {
            String key = (p.path() != null && !p.path().isBlank())
                    ? p.path().toLowerCase(Locale.ROOT)
                    : p.name().toLowerCase(Locale.ROOT);
            byKey.computeIfAbsent(key, k -> new ArrayList<>()).add(p);
        }
        List<ProcessInfo> out = new ArrayList<>(input.size());
        for (List<ProcessInfo> group : byKey.values()) {
            boolean hasTypedChild = false;
            for (ProcessInfo p : group) {
                String cmd = p.displayCommandLine();
                if (cmd.contains("--type=") || cmd.contains("--utility-sub-type=")) {
                    hasTypedChild = true;
                    break;
                }
            }
            for (ProcessInfo p : group) {
                if (hasTypedChild && p.role().isBlank()) {
                    String cmd = p.displayCommandLine();
                    if (!cmd.contains("--type=") && !cmd.contains("--utility-sub-type=")) {
                        out.add(p.withRoleOverride("Main"));
                        continue;
                    }
                }
                out.add(p);
            }
        }
        return out;
    }

    private List<ProcessInfo> listViaTasklist() {
        Map<Integer, ProcessInfo> map = new LinkedHashMap<>();
        try {
            ProcessBuilder pb = new ProcessBuilder("tasklist.exe", "/FO", "CSV", "/NH", "/V");
            pb.redirectErrorStream(true);
            Process process = pb.start();
            Charset cs = windowsConsoleCharset();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream(), cs))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    String[] cols = CSV_SPLIT.split(line, -1);
                    if (cols.length < 2) {
                        continue;
                    }
                    String name = unquote(cols[0]);
                    int pid = parseInt(unquote(cols[1]));
                    String user = cols.length > 6 ? unquote(cols[6]) : "";
                    if (pid > 0) {
                        map.put(pid, new ProcessInfo(pid, name, "", user, ""));
                    }
                }
            }
            process.waitFor();
        } catch (Exception ignored) {
            return List.of();
        }
        List<ProcessInfo> list = new ArrayList<>(map.values());
        list.sort(Comparator.comparing(ProcessInfo::name, String.CASE_INSENSITIVE_ORDER));
        return list;
    }

    public List<ProcessInfo> filter(List<ProcessInfo> all, String query) {
        if (query == null || query.isBlank()) {
            return all;
        }
        String q = query.toLowerCase(Locale.ROOT);
        List<ProcessInfo> filtered = new ArrayList<>();
        for (ProcessInfo p : all) {
            if (p.name().toLowerCase(Locale.ROOT).contains(q)
                    || Integer.toString(p.pid()).contains(q)
                    || p.displayPath().toLowerCase(Locale.ROOT).contains(q)
                    || p.role().toLowerCase(Locale.ROOT).contains(q)
                    || p.displayCommandLine().toLowerCase(Locale.ROOT).contains(q)) {
                filtered.add(p);
            }
        }
        return filtered;
    }

    private static Charset windowsConsoleCharset() {
        try {
            return Charset.forName("MS949");
        } catch (Exception e) {
            return StandardCharsets.UTF_8;
        }
    }

    private static String unquote(String s) {
        if (s == null) {
            return "";
        }
        String t = s.trim();
        if (t.startsWith("\"") && t.endsWith("\"") && t.length() >= 2) {
            t = t.substring(1, t.length() - 1);
        }
        return t.replace("\"\"", "\"");
    }

    private static int parseInt(String s) {
        try {
            Matcher m = Pattern.compile("\\d+").matcher(s);
            if (m.find()) {
                return Integer.parseInt(m.group());
            }
        } catch (NumberFormatException ignored) {
        }
        return -1;
    }
}
