package com.burpmirage.burp.model;

/**
 * Snapshot of a running Windows process.
 */
public record ProcessInfo(int pid, String name, String path, String user, String commandLine, String roleOverride) {
    public ProcessInfo(int pid, String name, String path, String user) {
        this(pid, name, path, user, "", "");
    }

    public ProcessInfo(int pid, String name, String path, String user, String commandLine) {
        this(pid, name, path, user, commandLine, "");
    }

    public ProcessInfo withRoleOverride(String role) {
        return new ProcessInfo(pid, name, path, user, commandLine, role == null ? "" : role);
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
        if (roleOverride != null && !roleOverride.isBlank()) {
            return roleOverride;
        }
        return ProcessRole.fromCommandLine(commandLine);
    }

    public String roleDisplay() {
        return ProcessRole.display(role());
    }

    public String displayCommandLine() {
        return commandLine == null || commandLine.isBlank() ? "" : commandLine;
    }
}
