package com.burpmirage.burp.nativebridge;

import burp.api.montoya.logging.Logging;
import com.burpmirage.burp.intercept.InterceptController;
import com.burpmirage.burp.model.ExtensionSettings;
import com.burpmirage.burp.util.I18n;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

/**
 * Local TCP JSON-lines bridge between Frida Python host and the Burp extension.
 *
 * Protocol (one JSON object per line):
 *   client → server: {"type":"packet","id":"...","pid":1,"direction":"send","api":"send","peer":"x:y","fd":3,"data":"<b64>"}
 *   server → client: {"id":"...","action":"forward|drop","data":"<b64>"}
 *   client → server: {"type":"hello","pid":1}
 *   client → server: {"type":"event","message":"..."}
 *   server → client: {"type":"inject","data":"<b64>","peer":"optional"}  (Repeater send)
 */
public final class BridgeServer implements AutoCloseable {
    private final ExtensionSettings settings;
    private final InterceptController controller;
    private final Logging logging;
    private final Gson gson = new Gson();
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final ExecutorService acceptPool = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "BurpMirage-bridge-accept");
        t.setDaemon(true);
        return t;
    });
    private final ExecutorService clientPool = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r, "BurpMirage-bridge-client");
        t.setDaemon(true);
        return t;
    });

    private ServerSocket serverSocket;
    private volatile BufferedWriter activeWriter;
    private volatile Consumer<String> statusListener = s -> {};
    private volatile Consumer3 repeaterResponseListener = (d, p, r) -> {};

    @FunctionalInterface
    public interface Consumer3 {
        void accept(byte[] data, String peer, String requestId);
    }

    public BridgeServer(ExtensionSettings settings, InterceptController controller, Logging logging) {
        this.settings = settings;
        this.controller = controller;
        this.logging = logging;
    }

    public void setStatusListener(Consumer<String> statusListener) {
        this.statusListener = statusListener != null ? statusListener : s -> {};
    }

    public void setRepeaterResponseListener(Consumer3 listener) {
        this.repeaterResponseListener = listener != null ? listener : (d, p, r) -> {};
    }

    public synchronized void start() throws IOException {
        if (running.get()) {
            return;
        }
        serverSocket = new ServerSocket(settings.bridgePort(), 50, InetAddress.getByName("127.0.0.1"));
        running.set(true);
        status(I18n.format("bridge.listening", settings.bridgePort()));
        acceptPool.submit(this::acceptLoop);
    }

    public synchronized void stop() {
        running.set(false);
        try {
            if (serverSocket != null) {
                serverSocket.close();
            }
        } catch (IOException ignored) {
        }
        activeWriter = null;
        status("Bridge stopped");
    }

    public boolean isRunning() {
        return running.get();
    }

    public boolean hasClient() {
        return activeWriter != null;
    }

    /**
     * Ask the hooked process to write arbitrary bytes (Repeater).
     */
    public boolean injectSend(byte[] data, String peerHint) {
        return injectSend(data, peerHint, null);
    }

    public boolean injectSend(byte[] data, String peerHint, String requestId) {
        BufferedWriter w = activeWriter;
        if (w == null) {
            return false;
        }
        JsonObject msg = new JsonObject();
        msg.addProperty("type", "inject");
        msg.addProperty("data", Base64.getEncoder().encodeToString(data));
        msg.addProperty("waitResponse", true);
        if (peerHint != null) {
            msg.addProperty("peer", peerHint);
        }
        if (requestId != null) {
            msg.addProperty("requestId", requestId);
        }
        return writeLine(w, gson.toJson(msg));
    }

    public void pushConfig() {
        BufferedWriter w = activeWriter;
        if (w == null) {
            return;
        }
        JsonObject msg = new JsonObject();
        msg.addProperty("type", "config");
        msg.addProperty("intercept", settings.interceptEnabled());
        msg.addProperty("hookSend", settings.hookSend());
        msg.addProperty("hookRecv", settings.hookRecv());
        writeLine(w, gson.toJson(msg));
    }

    private void acceptLoop() {
        while (running.get()) {
            try {
                Socket socket = serverSocket.accept();
                socket.setTcpNoDelay(true);
                clientPool.submit(() -> handleClient(socket));
            } catch (IOException e) {
                if (running.get()) {
                    logging.logToError("Bridge accept error: " + e.getMessage());
                }
            }
        }
    }

    private void handleClient(Socket socket) {
        status("Frida bridge connected from " + socket.getRemoteSocketAddress());
        try (
                BufferedReader reader = new BufferedReader(
                        new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
                BufferedWriter writer = new BufferedWriter(
                        new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8))
        ) {
            activeWriter = writer;
            pushConfig();
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.isBlank()) {
                    continue;
                }
                try {
                    handleMessage(line, writer);
                } catch (Exception ex) {
                    logging.logToError("Bridge message error: " + ex.getMessage());
                }
            }
        } catch (IOException e) {
            logging.logToOutput("Bridge client disconnected: " + e.getMessage());
        } finally {
            if (activeWriter != null) {
                activeWriter = null;
            }
            try {
                socket.close();
            } catch (IOException ignored) {
            }
            status("Frida bridge disconnected");
        }
    }

    private void handleMessage(String line, BufferedWriter writer) {
        JsonObject obj = JsonParser.parseString(line).getAsJsonObject();
        String type = obj.has("type") ? obj.get("type").getAsString() : "packet";

        switch (type) {
            case "hello" -> {
                int pid = obj.has("pid") ? obj.get("pid").getAsInt() : -1;
                status("Hello from Frida host (pid target=" + pid + ")");
            }
            case "event" -> {
                String message = obj.has("message") ? obj.get("message").getAsString() : "";
                logging.logToOutput("[Frida] " + message);
            }
            case "pong" -> logging.logToOutput("[Frida] pong");
            case "repeater_response" -> {
                byte[] data = Base64.getDecoder().decode(
                        obj.has("data") ? obj.get("data").getAsString() : ""
                );
                String peer = obj.has("peer") ? obj.get("peer").getAsString() : "";
                String requestId = obj.has("requestId") ? obj.get("requestId").getAsString() : "";
                logging.logToOutput("[BurpMirage] Repeater response " + data.length
                        + " bytes req=" + requestId + " from " + peer);
                repeaterResponseListener.accept(data, peer, requestId);
            }
            case "packet" -> {
                String id = obj.get("id").getAsString();
                int pid = obj.get("pid").getAsInt();
                String direction = obj.get("direction").getAsString();
                String api = obj.has("api") ? obj.get("api").getAsString() : "";
                String peer = obj.has("peer") ? obj.get("peer").getAsString() : "";
                int fd = obj.has("fd") ? obj.get("fd").getAsInt() : -1;
                byte[] data = Base64.getDecoder().decode(
                        obj.has("data") ? obj.get("data").getAsString() : ""
                );

                // Do not block the TCP reader on Intercept UI — reply on a worker thread.
                clientPool.submit(() -> {
                    try {
                        InterceptController.BridgeResponse response =
                                controller.handleIncomingPacket(id, pid, direction, api, peer, fd, data);
                        JsonObject reply = new JsonObject();
                        reply.addProperty("id", id);
                        reply.addProperty("action", response.action());
                        reply.addProperty("data", response.dataBase64() == null ? "" : response.dataBase64());
                        writeLine(writer, gson.toJson(reply));
                    } catch (Exception e) {
                        logging.logToError("Packet worker error: " + e.getMessage());
                        JsonObject reply = new JsonObject();
                        reply.addProperty("id", id);
                        reply.addProperty("action", "forward");
                        reply.addProperty("data", Base64.getEncoder().encodeToString(data));
                        writeLine(writer, gson.toJson(reply));
                    }
                });
            }
            default -> logging.logToOutput("Unknown bridge type: " + type);
        }
    }

    private boolean writeLine(BufferedWriter writer, String json) {
        try {
            synchronized (writer) {
                writer.write(json);
                writer.newLine();
                writer.flush();
            }
            return true;
        } catch (IOException e) {
            logging.logToError("Bridge write failed: " + e.getMessage());
            return false;
        }
    }

    private void status(String msg) {
        logging.logToOutput("[BurpMirage] " + msg);
        statusListener.accept(msg);
    }

    @Override
    public void close() {
        stop();
        acceptPool.shutdownNow();
        clientPool.shutdownNow();
    }
}
