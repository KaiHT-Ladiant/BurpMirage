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
        if (!viaPs.isEmpty()) {
            return viaPs;
        }
        return listViaTasklist();
    }

    private List<ProcessInfo> listViaPowerShell() {
        List<ProcessInfo> result = new ArrayList<>();
        try {
            ProcessBuilder pb = new ProcessBuilder(
                    "powershell.exe",
                    "-NoProfile",
                    "-Command",
                    "Get-CimInstance Win32_Process | " +
                            "Select-Object ProcessId,Name,ExecutablePath, @{N='User';E={try{$_.GetOwner().User}catch{''}}} | " +
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
                    String user = cols.length > 3 ? unquote(cols[3]) : "";
                    if (pid > 0 && !name.isBlank()) {
                        result.add(new ProcessInfo(pid, name, path, user));
                    }
                }
            }
            process.waitFor();
        } catch (Exception ignored) {
            return List.of();
        }
        result.sort(Comparator.comparing(ProcessInfo::name, String.CASE_INSENSITIVE_ORDER)
                .thenComparingInt(ProcessInfo::pid));
        return result;
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
                        map.put(pid, new ProcessInfo(pid, name, "", user));
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
                    || p.displayPath().toLowerCase(Locale.ROOT).contains(q)) {
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
