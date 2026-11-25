package com.burpmirage.burp.model;

/**
 * Snapshot of a running Windows process.
 */
public record ProcessInfo(
        int pid,
        String name,
        String path,
        String user,
        String commandLine,
        String roleOverride,
        int tcpSocketCount
) {
    public ProcessInfo(int pid, String name, String path, String user) {
        this(pid, name, path, user, "", "", 0);
    }

    public ProcessInfo(int pid, String name, String path, String user, String commandLine) {
        this(pid, name, path, user, commandLine, "", 0);
    }

    public ProcessInfo(int pid, String name, String path, String user, String commandLine, String roleOverride) {
        this(pid, name, path, user, commandLine, roleOverride, 0);
    }

    public ProcessInfo withRoleOverride(String role) {
        return new ProcessInfo(pid, name, path, user, commandLine, role == null ? "" : role, tcpSocketCount);
    }

    public ProcessInfo withTcpSocketCount(int count) {
        return new ProcessInfo(pid, name, path, user, commandLine, roleOverride, Math.max(0, count));
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
        return ProcessRole.display(role(), tcpSocketCount);
    }

    public String displayCommandLine() {
        return commandLine == null || commandLine.isBlank() ? "" : commandLine;
    }
}
