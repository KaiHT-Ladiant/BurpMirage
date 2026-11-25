package com.burpmirage.burp.model;

/**
 * Snapshot of a running Windows process.
 */
public record ProcessInfo(int pid, String name, String path, String user, String commandLine) {
    public ProcessInfo(int pid, String name, String path, String user) {
        this(pid, name, path, user, "");
    }

    @Override
    public String toString() {
        String role = role();
        if (!role.isBlank()) {
            return name + " [" + pid + "] " + role;
        }
        return name + " [" + pid + "]";
    }

    public String displayPath() {
        return path == null || path.isBlank() ? "(unknown)" : path;
    }

    public String role() {
        return ProcessRole.fromCommandLine(commandLine);
    }

    public String roleDisplay() {
        return ProcessRole.display(role());
    }

    public String displayCommandLine() {
        return commandLine == null || commandLine.isBlank() ? "" : commandLine;
    }
}
