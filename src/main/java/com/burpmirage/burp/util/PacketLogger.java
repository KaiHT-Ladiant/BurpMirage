package com.burpmirage.burp.util;

import com.burpmirage.burp.model.InterceptedPacket;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Append-only packet logger.
 */
public final class PacketLogger implements AutoCloseable {
    private static final DateTimeFormatter TS =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS").withZone(ZoneId.systemDefault());

    private final ReentrantLock lock = new ReentrantLock();
    private Path path;
    private BufferedWriter writer;

    public synchronized void setPath(Path path) throws IOException {
        closeQuietly();
        this.path = path;
        if (path != null) {
            if (path.getParent() != null) {
                Files.createDirectories(path.getParent());
            }
            writer = Files.newBufferedWriter(
                    path,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.WRITE,
                    StandardOpenOption.APPEND
            );
        }
    }

    public Path path() {
        return path;
    }

    public void log(InterceptedPacket packet) {
        if (writer == null || packet == null) {
            return;
        }
        lock.lock();
        try {
            writer.write(TS.format(packet.timestamp()));
            writer.write('\t');
            writer.write(packet.direction().name());
            writer.write('\t');
            writer.write(packet.processName());
            writer.write('/');
            writer.write(Integer.toString(packet.pid()));
            writer.write('\t');
            writer.write(packet.peer());
            writer.write('\t');
            writer.write(Integer.toString(packet.length()));
            writer.write('\t');
            writer.write(packet.status().name());
            writer.write('\t');
            writer.write(Base64.getEncoder().encodeToString(packet.data()));
            writer.newLine();
            writer.flush();
        } catch (IOException ignored) {
            // logging must not break intercept flow
        } finally {
            lock.unlock();
        }
    }

    private void closeQuietly() {
        if (writer != null) {
            try {
                writer.close();
            } catch (IOException ignored) {
            }
            writer = null;
        }
    }

    @Override
    public void close() {
        closeQuietly();
    }
}
