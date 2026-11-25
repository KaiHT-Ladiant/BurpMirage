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
    /** Extra hosts when group-inject fans out one standalone bridge per PID. */
    private final List<Process> extraHosts = new CopyOnWriteArrayList<>();
    private final AtomicReference<ProcessInfo> attached = new AtomicReference<>();
    private final AtomicReference<List<ProcessInfo>> attachedGroup =
            new AtomicReference<>(List.of());
    private volatile BridgeServer bridgeServer;
    private Path workDir;
    private volatile Consumer<String> statusListener = s -> {};

    public FridaController(ExtensionSettings settings, Logging logging) {
        this.settings = settings;
        this.logging = logging;
    }

    public void setBridgeServer(BridgeServer bridgeServer) {
        this.bridgeServer = bridgeServer;
    }

    public void setStatusListener(Consumer<String> statusListener) {
        this.statusListener = statusListener != null ? statusListener : s -> {};
    }

    public ProcessInfo attachedProcess() {
        return attached.get();
    }

    public List<ProcessInfo> attachedGroup() {
        return attachedGroup.get();
    }

    public boolean isAttached() {
        Process p = hostProcess.get();
        if (p != null && p.isAlive()) {
            return true;
        }
        for (Process extra : extraHosts) {
            if (extra != null && extra.isAlive()) {
                return true;
            }
        }
        return false;
    }

    public synchronized void injectAndHook(ProcessInfo process) throws IOException, InterruptedException {
        injectAndHook(List.of(process));
    }

    public synchronized void injectAndHook(List<ProcessInfo> processes)
            throws IOException, InterruptedException {
        if (processes == null || processes.isEmpty()) {
            throw new IOException("No processes to inject");
        }
        detach();

        ensureBridgeListening();
        ensureScriptsExtracted();

        Path hooksJs = workDir.resolve("hooks.js");
        Path bridgeExe = resolveBridgeExe();
        boolean multi = processes.size() > 1;

        StringBuilder pidCsv = new StringBuilder();
        for (int i = 0; i < processes.size(); i++) {
            if (i > 0) {
                pidCsv.append(',');
            }
            pidCsv.append(processes.get(i).pid());
        }

        settings.resolvePythonIfNeeded();
        String python = settings.pythonPath();
        boolean pythonOk = PythonDetector.hasFrida(python);

        // Prefer standalone fan-out for multi-PID (Python --pids often hangs on Electron attach).
        if (multi && bridgeExe != null) {
            startStandaloneFanout(bridgeExe, hooksJs, processes, pidCsv.toString());
            return;
        }

        List<String> cmd = new ArrayList<>();
        if (bridgeExe != null) {
            cmd.add(bridgeExe.toAbsolutePath().toString());
            status("Using standalone bridge: " + bridgeExe.toAbsolutePath());
        } else {
            if (!pythonOk) {
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
            if (multi) {
                status("Using Python multi-attach bridge for " + processes.size() + " PIDs");
            }
        }
        if (multi) {
            cmd.add("--pids");
            cmd.add(pidCsv.toString());
        } else {
            cmd.add("--pid");
            cmd.add(Integer.toString(processes.get(0).pid()));
        }
        cmd.add("--host");
        cmd.add("127.0.0.1");
        cmd.add("--port");
        cmd.add(Integer.toString(settings.bridgePort()));
        cmd.add("--script");
        cmd.add(hooksJs.toAbsolutePath().toString());

        logging.logToOutput("[BurpMirage] Launch: " + String.join(" ", cmd));
        Process proc = startHostProcess(cmd);
        hostProcess.set(proc);
        watchHost(proc, processes, pidCsv.toString(), python);
    }

    /**
     * Older burpmirage-bridge.exe is single-PID; group inject starts one host per target.
     * BridgeServer already accepts multiple Frida TCP clients.
     */
    private void startStandaloneFanout(
            Path bridgeExe,
            Path hooksJs,
            List<ProcessInfo> processes,
            String pidCsv
    ) throws IOException, InterruptedException {
        status("Group inject via " + processes.size()
                + " standalone bridge hosts (one PID each): " + pidCsv);
        List<Process> started = new ArrayList<>();
        CountDownLatch ready = new CountDownLatch(1);
        AtomicBoolean success = new AtomicBoolean(false);
        List<String> lines = new CopyOnWriteArrayList<>();

        for (ProcessInfo p : processes) {
            List<String> cmd = List.of(
                    bridgeExe.toAbsolutePath().toString(),
                    "--pid", Integer.toString(p.pid()),
                    "--host", "127.0.0.1",
                    "--port", Integer.toString(settings.bridgePort()),
                    "--script", hooksJs.toAbsolutePath().toString()
            );
            logging.logToOutput("[BurpMirage] Launch: " + String.join(" ", cmd));
            Process proc = startHostProcess(cmd);
            started.add(proc);
            ioPool.submit(() -> drainHostOutput(proc, lines, ready, success));
            ioPool.submit(() -> awaitHostExit(proc, ready));
        }

        hostProcess.set(started.get(0));
        for (int i = 1; i < started.size(); i++) {
            extraHosts.add(started.get(i));
        }
        ProcessInfo primary = processes.get(0);
        attached.set(primary);
        attachedGroup.set(List.copyOf(processes));

        boolean signaled = ready.await(25, TimeUnit.SECONDS);
        boolean anyAlive = started.stream().anyMatch(Process::isAlive);
        if (!anyAlive) {
            attached.set(null);
            attachedGroup.set(List.of());
            hostProcess.set(null);
            extraHosts.clear();
            String tail = String.join("\n", lines.size() > 30
                    ? lines.subList(lines.size() - 30, lines.size()) : lines);
            throw new IOException(I18n.format(
                    "frida.error.exit",
                    -1,
                    bridgeExe.toAbsolutePath(),
                    tail.isBlank() ? "(empty)" : tail
            ));
        }
        if (!signaled || !success.get()) {
            status(I18n.format("frida.status.waiting", primary.name()));
        } else {
            status(I18n.format("frida.status.hooked_group", processes.size(), pidCsv));
        }
    }

    private Process startHostProcess(List<String> cmd) throws IOException {
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);
        pb.directory(workDir.toFile());
        Map<String, String> env = pb.environment();
        env.put("PYTHONUNBUFFERED", "1");
        env.put("PYTHONIOENCODING", "utf-8");
        return pb.start();
    }

    private void watchHost(Process proc, List<ProcessInfo> processes, String pidCsv, String python)
            throws IOException, InterruptedException {
        ProcessInfo primary = processes.get(0);
        attached.set(primary);
        attachedGroup.set(List.copyOf(processes));
        status("Injecting into " + processes.size() + " process(es): " + pidCsv);

        CountDownLatch ready = new CountDownLatch(1);
        AtomicBoolean success = new AtomicBoolean(false);
        List<String> lines = new CopyOnWriteArrayList<>();

        ioPool.submit(() -> drainHostOutput(proc, lines, ready, success));
        ioPool.submit(() -> awaitHostExit(proc, ready));

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
            attachedGroup.set(List.of());
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
            status(I18n.format("frida.status.waiting", primary.name()));
        } else if (processes.size() == 1) {
            status(I18n.format("frida.status.hooked", primary.name(), primary.pid()));
        } else {
            status(I18n.format("frida.status.hooked_group", processes.size(), pidCsv));
        }
    }

    private void drainHostOutput(
            Process proc,
            List<String> lines,
            CountDownLatch ready,
            AtomicBoolean success
    ) {
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(proc.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                lines.add(line);
                logging.logToOutput("[FridaHost] " + line);
                statusListener.accept(line);
                String lower = line.toLowerCase();
                if (lower.contains("hooked pid") || lower.contains("hooked pids")
                        || lower.contains("connected to burp bridge")
                        || lower.contains("winsock hooks installed")
                        || lower.contains("writefile/readfile hooks")
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
    }

    private void awaitHostExit(Process proc, CountDownLatch ready) {
        try {
            int code = proc.waitFor();
            status("Frida host exited (code=" + code + ")");
            hostProcess.compareAndSet(proc, null);
            extraHosts.remove(proc);
            ready.countDown();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            ready.countDown();
        }
    }

    public synchronized void detach() {
        attached.set(null);
        attachedGroup.set(List.of());
        List<Process> all = new ArrayList<>();
        Process primary = hostProcess.getAndSet(null);
        if (primary != null) {
            all.add(primary);
        }
        all.addAll(extraHosts);
        extraHosts.clear();

        // 1) Burp → bridge JSON detach (unload + session.detach + exit)
        boolean sent = false;
        BridgeServer bridge = bridgeServer;
        if (bridge != null && bridge.hasClient()) {
            sent = bridge.requestDetach();
            if (sent) {
                status("Detach command sent — waiting for Frida host to exit");
                try {
                    Thread.sleep(400);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            // 2) Close TCP so hosts without detach handler still run finally-cleanup.
            if (all.stream().anyMatch(Process::isAlive)) {
                bridge.disconnectClient();
            }
        }

        boolean anyAlive = false;
        for (Process proc : all) {
            if (proc == null || !proc.isAlive()) {
                continue;
            }
            anyAlive = true;
            try {
                if (!proc.waitFor(8, TimeUnit.SECONDS)) {
                    status("Graceful detach timed out — forcing Frida host exit");
                    proc.destroy();
                    if (!proc.waitFor(2, TimeUnit.SECONDS)) {
                        proc.destroyForcibly();
                    }
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                proc.destroyForcibly();
            }
        }
        if (anyAlive) {
            status("Detached Frida host(s)");
        } else if (!sent) {
            status("Detached (no Frida host process)");
        } else {
            status("Detached Frida host (session unloaded)");
        }
    }

    private void ensureBridgeListening() throws IOException {
        BridgeServer bridge = bridgeServer;
        if (bridge == null) {
            throw new IOException("BridgeServer is not set — reload the BurpMirage extension");
        }
        bridge.ensureListening();
        if (!bridge.isListening()) {
            throw new IOException(
                    "BurpMirage bridge is not listening on 127.0.0.1:" + settings.bridgePort()
                            + ".\nOpen Settings → Start Bridge, or reload the extension.\n"
                            + "Frida host error 'Could not connect to Burp bridge: timed out' means this."
            );
        }
        status("Bridge OK on 127.0.0.1:" + settings.bridgePort());
    }

    private synchronized void ensureScriptsExtracted() throws IOException {
        if (workDir == null) {
            workDir = Files.createTempDirectory("BurpMirage-frida-");
            workDir.toFile().deleteOnExit();
        }
        copyResource("/frida/frida_bridge.py", workDir.resolve("frida_bridge.py"));
        writeHooksWithConfig(workDir.resolve("hooks.js"));
    }

    /** Extract hooks.js and prepend Mode A/B + Burp proxy settings (works with standalone bridge exe). */
    private void writeHooksWithConfig(Path target) throws IOException {
        String base;
        try (InputStream in = FridaController.class.getResourceAsStream("/frida/hooks.js")) {
            if (in == null) {
                throw new IOException("Missing classpath resource: /frida/hooks.js");
            }
            base = new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
        String host = settings.burpProxyHost().replace("\\", "\\\\").replace("'", "");
        String preamble = ""
                + "var __BM_MODE_PROXY = " + settings.modeProxyForce() + ";\n"
                + "var __BM_MODE_SOCKET = " + settings.modeSocketMirage() + ";\n"
                + "var __BM_MODE_TLS_UNPIN = " + settings.modeTlsUnpin() + ";\n"
                + "var __BM_PROXY_HOST = '" + host + "';\n"
                + "var __BM_PROXY_PORT = " + settings.burpProxyPort() + ";\n";
        Files.writeString(target, preamble + base, StandardCharsets.UTF_8);
        status("hooks.js modes: proxy=" + settings.modeProxyForce()
                + " socket=" + settings.modeSocketMirage()
                + " tlsUnpin=" + settings.modeTlsUnpin()
                + " burp=" + settings.burpProxyHost() + ":" + settings.burpProxyPort());
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
