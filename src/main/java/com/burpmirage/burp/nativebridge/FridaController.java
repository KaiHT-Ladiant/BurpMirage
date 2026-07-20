package com.burpmirage.burp.nativebridge;

import burp.api.montoya.logging.Logging;
import com.burpmirage.burp.model.ExtensionSettings;
import com.burpmirage.burp.model.ProcessInfo;
import com.burpmirage.burp.util.I18n;
import com.burpmirage.burp.util.PythonDetector;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

/**
 * Launches the Python Frida host that attaches to a target process and
 * speaks JSON-lines with {@link BridgeServer}.
 */
public final class FridaController implements AutoCloseable {
    private final ExtensionSettings settings;
    private final Logging logging;
    private final ExecutorService ioPool = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r, "BurpMirage-frida-io");
        t.setDaemon(true);
        return t;
    });

    private final AtomicReference<Process> hostProcess = new AtomicReference<>();
    private final AtomicReference<ProcessInfo> attached = new AtomicReference<>();
    private Path workDir;
    private volatile Consumer<String> statusListener = s -> {};

    public FridaController(ExtensionSettings settings, Logging logging) {
        this.settings = settings;
        this.logging = logging;
    }

    public void setStatusListener(Consumer<String> statusListener) {
        this.statusListener = statusListener != null ? statusListener : s -> {};
    }

    public ProcessInfo attachedProcess() {
        return attached.get();
    }

    public boolean isAttached() {
        Process p = hostProcess.get();
        return p != null && p.isAlive();
    }

    public synchronized void injectAndHook(ProcessInfo process) throws IOException, InterruptedException {
        detach();

        ensureScriptsExtracted();

        Path hooksJs = workDir.resolve("hooks.js");
        Path bridgeExe = resolveBridgeExe();

        String python = settings.pythonPath();
        List<String> cmd = new ArrayList<>();
        if (bridgeExe != null) {
            // Standalone bundle: frida is embedded, no Python / pip required.
            cmd.add(bridgeExe.toAbsolutePath().toString());
            status("Using standalone bridge: " + bridgeExe.toAbsolutePath());
        } else {
            settings.resolvePythonIfNeeded();
            python = settings.pythonPath();
            if (!PythonDetector.hasFrida(python)) {
                throw new IOException(
                        "No standalone bridge (burpmirage-bridge.exe) found and Python has no frida module: "
                                + python + "\n\n"
                                + "Fix either way:\n"
                                + "  A) Download burpmirage-bridge.exe from Releases and set it in "
                                + "Settings \u2192 Bridge EXE path (no Python needed), or\n"
                                + "  B) Install frida for Python:\n\n"
                                + PythonDetector.diagnosis()
                );
            }
            Path bridgePy = workDir.resolve("frida_bridge.py");
            cmd.add(python);
            cmd.add(bridgePy.toAbsolutePath().toString());
        }
        cmd.add("--pid");
        cmd.add(Integer.toString(process.pid()));
        cmd.add("--host");
        cmd.add("127.0.0.1");
        cmd.add("--port");
        cmd.add(Integer.toString(settings.bridgePort()));
        cmd.add("--script");
        cmd.add(hooksJs.toAbsolutePath().toString());

        logging.logToOutput("[BurpMirage] Launch: " + String.join(" ", cmd));

        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);
        pb.directory(workDir.toFile());
        Map<String, String> env = pb.environment();
        env.put("PYTHONUNBUFFERED", "1");
        env.put("PYTHONIOENCODING", "utf-8");
        Process proc = pb.start();
        hostProcess.set(proc);
        attached.set(process);
        status("Injecting into " + process.name() + " (" + process.pid() + ") using " + python);

        CountDownLatch ready = new CountDownLatch(1);
        AtomicBoolean success = new AtomicBoolean(false);
        List<String> lines = new CopyOnWriteArrayList<>();

        ioPool.submit(() -> {
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(proc.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    lines.add(line);
                    logging.logToOutput("[FridaHost] " + line);
                    statusListener.accept(line);
                    String lower = line.toLowerCase();
                    if (lower.contains("hooked pid") || lower.contains("connected to burp bridge")
                            || lower.contains("winsock hooks installed")
                            || lower.contains("attached to pid")) {
                        success.set(true);
                        ready.countDown();
                    }
                    if (lower.contains("error:") || lower.contains("module not found")
                            || lower.contains("could not connect")
                            || lower.contains("unable to access process")
                            || lower.contains("access denied")
                            || lower.contains("failed to attach")) {
                        ready.countDown();
                    }
                }
            } catch (IOException e) {
                logging.logToError("Frida host IO: " + e.getMessage());
                ready.countDown();
            }
        });

        ioPool.submit(() -> {
            try {
                int code = proc.waitFor();
                status("Frida host exited (code=" + code + ")");
                hostProcess.compareAndSet(proc, null);
                ready.countDown();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                ready.countDown();
            }
        });

        boolean signaled = ready.await(20, TimeUnit.SECONDS);
        if (!proc.isAlive()) {
            int code;
            try {
                code = proc.exitValue();
            } catch (IllegalThreadStateException e) {
                code = -1;
            }
            String tail = String.join("\n", lines.size() > 20
                    ? lines.subList(lines.size() - 20, lines.size()) : lines);
            hostProcess.compareAndSet(proc, null);
            attached.set(null);
            if (code == 9009) {
                throw new IOException(I18n.format("frida.error.python9009", python, tail.isBlank() ? "(empty)" : tail));
            }
            throw new IOException(I18n.format(
                    "frida.error.exit",
                    code,
                    python,
                    tail.isBlank() ? "(empty)" : tail
            ));
        }
        if (!signaled || !success.get()) {
            // Still alive but no ready signal — warn but allow (hooks may install late)
            status(I18n.format("frida.status.waiting", process.name()));
        } else {
            status(I18n.format("frida.status.hooked", process.name(), process.pid()));
        }
    }

    public synchronized void detach() {
        Process proc = hostProcess.getAndSet(null);
        attached.set(null);
        if (proc != null && proc.isAlive()) {
            proc.destroy();
            try {
                if (!proc.waitFor(2, TimeUnit.SECONDS)) {
                    proc.destroyForcibly();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                proc.destroyForcibly();
            }
            status("Detached Frida host");
        }
    }

    private synchronized void ensureScriptsExtracted() throws IOException {
        if (workDir == null) {
            workDir = Files.createTempDirectory("BurpMirage-frida-");
            workDir.toFile().deleteOnExit();
        }
        copyResource("/frida/frida_bridge.py", workDir.resolve("frida_bridge.py"));
        copyResource("/frida/hooks.js", workDir.resolve("hooks.js"));
    }

    /**
     * Locate a standalone bridge executable (frida bundled, no Python needed).
     * Order: explicit Settings path → next to the extension JAR → bundled in JAR.
     * Returns {@code null} when none is available (caller falls back to Python).
     */
    private Path resolveBridgeExe() {
        String configured = settings.bridgeExePath();
        if (configured != null && !configured.isBlank()) {
            Path p = Path.of(configured.trim());
            if (Files.isRegularFile(p)) {
                return p;
            }
            status("Configured Bridge EXE not found: " + configured);
        }

        String exeName = "burpmirage-bridge.exe";
        try {
            Path jar = Path.of(FridaController.class.getProtectionDomain()
                    .getCodeSource().getLocation().toURI());
            Path dir = Files.isDirectory(jar) ? jar : jar.getParent();
            if (dir != null) {
                Path beside = dir.resolve(exeName);
                if (Files.isRegularFile(beside)) {
                    return beside;
                }
            }
        } catch (Exception ignored) {
        }

        // Optional: exe bundled inside the JAR under /frida/.
        try (InputStream in = FridaController.class.getResourceAsStream("/frida/" + exeName)) {
            if (in != null) {
                if (workDir == null) {
                    workDir = Files.createTempDirectory("BurpMirage-frida-");
                    workDir.toFile().deleteOnExit();
                }
                Path out = workDir.resolve(exeName);
                Files.copy(in, out, StandardCopyOption.REPLACE_EXISTING);
                out.toFile().setExecutable(true);
                return out;
            }
        } catch (IOException ignored) {
        }
        return null;
    }

    private void copyResource(String resource, Path target) throws IOException {
        try (InputStream in = FridaController.class.getResourceAsStream(resource)) {
            if (in == null) {
                throw new IOException("Missing classpath resource: " + resource);
            }
            Files.copy(in, target, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private void status(String msg) {
        logging.logToOutput("[BurpMirage] " + msg);
        statusListener.accept(msg);
    }

    public Path workDir() {
        return workDir;
    }

    @Override
    public void close() {
        detach();
        ioPool.shutdownNow();
    }
}
