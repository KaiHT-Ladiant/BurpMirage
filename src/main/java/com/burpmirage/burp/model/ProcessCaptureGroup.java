package com.burpmirage.burp.model;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Picks which sibling processes to hook together.
 * <p>
 * Chromium/Electron may put sockets on Renderer, NetworkService, and/or Main —
 * a single-PID inject is often empty. Same-image grouping fixes that class of misses.
 */
public final class ProcessCaptureGroup {
    private static final int MAX_GROUP = 12;

    private ProcessCaptureGroup() {
    }

    public static String imageKey(ProcessInfo p) {
        if (p.path() != null && !p.path().isBlank()) {
            return p.path().toLowerCase(Locale.ROOT);
        }
        return p.name() == null ? "" : p.name().toLowerCase(Locale.ROOT);
    }

    public static boolean isChromiumFamily(List<ProcessInfo> sameImage) {
        for (ProcessInfo p : sameImage) {
            String cmd = p.displayCommandLine();
            if (cmd.contains("--type=") || cmd.contains("--utility-sub-type=")) {
                return true;
            }
            String role = p.role();
            if (ProcessRole.inCaptureGroup(role)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Related processes that should be hooked together for capture coverage.
     */
    public static List<ProcessInfo> related(ProcessInfo seed, List<ProcessInfo> all) {
        if (seed == null || all == null || all.isEmpty()) {
            return List.of();
        }
        String key = imageKey(seed);
        List<ProcessInfo> same = new ArrayList<>();
        for (ProcessInfo p : all) {
            if (key.equals(imageKey(p))) {
                same.add(p);
            }
        }
        if (same.isEmpty()) {
            return List.of(seed);
        }

        boolean chromium = isChromiumFamily(same);
        List<ProcessInfo> picked = new ArrayList<>();
        for (ProcessInfo p : same) {
            if (p.tcpSocketCount() > 0) {
                picked.add(p);
                continue;
            }
            if (!chromium) {
                continue;
            }
            if (ProcessRole.inCaptureGroup(p.role()) || p.role().isBlank()) {
                // blank role among chromium siblings was labeled Main by enumerator
                picked.add(p);
            }
        }

        if (picked.isEmpty()) {
            // Non-chromium same image: hook seed + any with sockets, else all (capped)
            picked.add(seed);
            for (ProcessInfo p : same) {
                if (p.pid() == seed.pid()) {
                    continue;
                }
                if (p.tcpSocketCount() > 0) {
                    picked.add(p);
                }
            }
            if (picked.size() == 1 && same.size() > 1) {
                picked.clear();
                picked.addAll(same);
            }
        }

        // Prefer live socket owners first, then role priority
        picked.sort(Comparator
                .comparingInt(ProcessInfo::tcpSocketCount).reversed()
                .thenComparingInt(p -> ProcessRole.capturePriority(p.role()))
                .thenComparingInt(ProcessInfo::pid));

        if (picked.size() > MAX_GROUP) {
            return List.copyOf(picked.subList(0, MAX_GROUP));
        }
        // Dedup by pid while preserving order
        Map<Integer, ProcessInfo> uniq = new LinkedHashMap<>();
        for (ProcessInfo p : picked) {
            uniq.putIfAbsent(p.pid(), p);
        }
        return List.copyOf(uniq.values());
    }
}
