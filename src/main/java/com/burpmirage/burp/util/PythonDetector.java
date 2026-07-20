package com.burpmirage.burp.util;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * Finds a Python interpreter that can {@code import frida}.
 */
public final class PythonDetector {
    private PythonDetector() {
    }

    public static String detectPythonWithFrida() {
        for (String candidate : candidates()) {
            if (hasFrida(candidate)) {
                return candidate;
            }
        }
        return null;
    }

    public static boolean hasFrida(String pythonExecutable) {
        if (pythonExecutable == null || pythonExecutable.isBlank()) {
            return false;
        }
        try {
            ProcessBuilder pb = new ProcessBuilder(
                    pythonExecutable,
                    "-c",
                    "import frida; print(frida.__version__)"
            );
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out;
            try (BufferedReader r = new BufferedReader(
                    new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
                out = r.readLine();
            }
            boolean finished = p.waitFor(8, TimeUnit.SECONDS);
            if (!finished) {
                p.destroyForcibly();
                return false;
            }
            return p.exitValue() == 0 && out != null && !out.isBlank();
        } catch (Exception e) {
            return false;
        }
    }

    public static List<String> candidates() {
        Set<String> out = new LinkedHashSet<>();
        String localApp = System.getenv("LOCALAPPDATA");
        String userProfile = System.getenv("USERPROFILE");
        String programFiles = System.getenv("ProgramFiles");

        if (localApp != null) {
            addIfExists(out, Path.of(localApp, "Python", "pythoncore-3.14-64", "python.exe"));
            addIfExists(out, Path.of(localApp, "Python", "pythoncore-3.13-64", "python.exe"));
            addIfExists(out, Path.of(localApp, "Python", "pythoncore-3.12-64", "python.exe"));
            addIfExists(out, Path.of(localApp, "Python", "pythoncore-3.11-64", "python.exe"));
            Path programs = Path.of(localApp, "Programs", "Python");
            if (Files.isDirectory(programs)) {
                // Prefer newer installs: Python314, Python313, ...
                try (var stream = Files.list(programs)) {
                    stream.filter(Files::isDirectory)
                            .sorted((a, b) -> b.getFileName().toString()
                                    .compareToIgnoreCase(a.getFileName().toString()))
                            .forEach(dir -> addIfExists(out, dir.resolve("python.exe")));
                } catch (Exception ignored) {
                }
            }
        }
        if (userProfile != null) {
            addIfExists(out, Path.of(userProfile, "AppData", "Local", "Programs", "Python", "Python314", "python.exe"));
            addIfExists(out, Path.of(userProfile, "AppData", "Local", "Programs", "Python", "Python313", "python.exe"));
            addIfExists(out, Path.of(userProfile, "AppData", "Local", "Programs", "Python", "Python312", "python.exe"));
            addIfExists(out, Path.of(userProfile, "AppData", "Local", "Programs", "Python", "Python311", "python.exe"));
            addIfExists(out, Path.of(userProfile, "miniconda3", "python.exe"));
            addIfExists(out, Path.of(userProfile, "anaconda3", "python.exe"));
        }
        if (programFiles != null) {
            addIfExists(out, Path.of(programFiles, "Python312", "python.exe"));
            addIfExists(out, Path.of(programFiles, "Python311", "python.exe"));
        }

        List<String> result = new ArrayList<>();
        for (String c : out) {
            if (c != null && !c.isBlank()) {
                result.add(c);
            }
        }
        // Bare names last — Burp GUI often lacks the same PATH as PowerShell (exit 9009)
        result.add("py");
        result.add("python");
        result.add("python3");
        return result;
    }

    private static void addIfExists(Set<String> out, Path path) {
        if (path != null && Files.isRegularFile(path)) {
            out.add(path.toAbsolutePath().toString());
        }
    }

    public static String diagnosis() {
        StringBuilder sb = new StringBuilder();
        sb.append(I18n.get("python.checked"));
        for (String c : candidates()) {
            boolean ok = hasFrida(c);
            sb.append("  ").append(ok ? I18n.get("python.ok") : I18n.get("python.miss")).append(c);
            if (c.toLowerCase(Locale.ROOT).contains("windowsapps")) {
                sb.append(I18n.get("python.stub"));
            }
            sb.append('\n');
            if (ok) {
                sb.append(I18n.format("python.use_path", c));
                return sb.toString();
            }
        }
        sb.append(I18n.get("python.not_found"));
        return sb.toString();
    }
}
