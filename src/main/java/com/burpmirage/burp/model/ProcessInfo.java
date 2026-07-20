package com.burpmirage.burp.model;

/**
 * Snapshot of a running Windows process.
 */
public record ProcessInfo(int pid, String name, String path, String user) {
    @Override
    public String toString() {
        return name + " [" + pid + "]";
    }

    public String displayPath() {
        return path == null || path.isBlank() ? "(unknown)" : path;
    }
}
