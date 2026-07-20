package com.burpmirage.burp.util;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Hex / ASCII helpers for binary packet editing.
 */
public final class HexUtils {
    private static final HexFormat HEX = HexFormat.of().withUpperCase();

    private HexUtils() {
    }

    public static String toHexDump(byte[] data) {
        if (data == null || data.length == 0) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < data.length; i += 16) {
            sb.append(String.format("%08X  ", i));
            StringBuilder ascii = new StringBuilder();
            for (int j = 0; j < 16; j++) {
                if (i + j < data.length) {
                    int b = data[i + j] & 0xFF;
                    sb.append(String.format("%02X ", b));
                    ascii.append(b >= 0x20 && b < 0x7F ? (char) b : '.');
                } else {
                    sb.append("   ");
                    ascii.append(' ');
                }
                if (j == 7) {
                    sb.append(' ');
                }
            }
            sb.append(" |").append(ascii).append("|\n");
        }
        return sb.toString();
    }

    public static String toContinuousHex(byte[] data) {
        if (data == null) {
            return "";
        }
        return HEX.formatHex(data);
    }

    public static byte[] fromContinuousHex(String hex) {
        if (hex == null || hex.isBlank()) {
            return new byte[0];
        }
        String cleaned = hex.replaceAll("[^0-9A-Fa-f]", "");
        if ((cleaned.length() & 1) == 1) {
            cleaned = "0" + cleaned;
        }
        return HEX.parseHex(cleaned);
    }

    /**
     * Parses a human-edited hex dump (offsets / ASCII column optional).
     * <p>
     * ASCII column is introduced by the literal separator {@code " |"} after the hex
     * bytes (see {@link #toHexDump}). The closing {@code '|'} is optional. This avoids
     * treating payload bytes that are themselves {@code '|'} (0x7C) as delimiters —
     * which previously dropped ASCII edits on lines starting with {@code '|'} (e.g. SQL).
     * Printable ASCII-column characters override the corresponding hex bytes;
     * {@code '.'} keeps the hex byte (non-printable placeholder).
     */
    public static byte[] fromHexDump(String dump) {
        if (dump == null || dump.isBlank()) {
            return new byte[0];
        }
        String trimmed = dump.trim();
        if (!trimmed.contains("\n") && trimmed.matches("(?i)^[0-9a-f\\s]+$")) {
            return fromContinuousHex(trimmed);
        }

        List<Byte> bytes = new ArrayList<>();
        Pattern hexByte = Pattern.compile("\\b([0-9A-Fa-f]{2})\\b");
        for (String line : dump.split("\\R")) {
            if (line.isBlank()) {
                continue;
            }
            // Drop leading offset (e.g. "00000050  ")
            String content = line.replaceFirst("^\\s*[0-9A-Fa-f]{4,8}\\s+", "");

            String asciiPart = null;
            String hexPart = content;
            // Separator used by toHexDump: " |" immediately before the ASCII column.
            int sep = content.indexOf(" |");
            if (sep >= 0) {
                hexPart = content.substring(0, sep);
                String rest = content.substring(sep + 2); // after " |"
                if (!rest.isEmpty() && rest.charAt(rest.length() - 1) == '|') {
                    asciiPart = rest.substring(0, rest.length() - 1);
                } else {
                    asciiPart = rest;
                }
            }

            List<Byte> lineBytes = new ArrayList<>();
            Matcher m = hexByte.matcher(hexPart);
            while (m.find()) {
                lineBytes.add((byte) Integer.parseInt(m.group(1), 16));
            }
            if (asciiPart != null && !lineBytes.isEmpty()) {
                // Overwrite mode: ASCII column is 1:1 with hex bytes on this line.
                // Shorter ASCII (user deleted chars) → remaining bytes become 0x00 (not "keep old hex").
                // '.' keeps existing hex only when that hex was already non-printable; otherwise '.' is 0x2E.
                // For explicit clear-to-null, prefer deleting (shorter column) or editing HEX to 00.
                for (int i = 0; i < lineBytes.size(); i++) {
                    if (i >= asciiPart.length()) {
                        lineBytes.set(i, (byte) 0);
                        continue;
                    }
                    char c = asciiPart.charAt(i);
                    int prev = lineBytes.get(i) & 0xFF;
                    if (c == '.' && (prev < 0x20 || prev >= 0x7F)) {
                        // placeholder for existing non-printable — keep hex
                        continue;
                    }
                    lineBytes.set(i, (byte) (c & 0xFF));
                }
            }
            bytes.addAll(lineBytes);
        }
        byte[] out = new byte[bytes.size()];
        for (int i = 0; i < bytes.size(); i++) {
            out[i] = bytes.get(i);
        }
        return out;
    }

    /**
     * Parse hex-dump hex columns only (ignore ASCII column). Used when the user is
     * editing HEX digits so the ASCII column cannot overwrite their changes.
     */
    public static byte[] fromHexDumpHexOnly(String dump) {
        if (dump == null || dump.isBlank()) {
            return new byte[0];
        }
        String trimmed = dump.trim();
        if (!trimmed.contains("\n") && trimmed.matches("(?i)^[0-9a-f\\s]+$")) {
            return fromContinuousHex(trimmed);
        }
        List<Byte> bytes = new ArrayList<>();
        Pattern hexByte = Pattern.compile("\\b([0-9A-Fa-f]{2})\\b");
        for (String line : dump.split("\\R")) {
            if (line.isBlank()) {
                continue;
            }
            String content = line.replaceFirst("^\\s*[0-9A-Fa-f]{4,8}\\s+", "");
            int sep = content.indexOf(" |");
            String hexPart = sep >= 0 ? content.substring(0, sep) : content;
            Matcher m = hexByte.matcher(hexPart);
            while (m.find()) {
                bytes.add((byte) Integer.parseInt(m.group(1), 16));
            }
        }
        byte[] out = new byte[bytes.size()];
        for (int i = 0; i < bytes.size(); i++) {
            out[i] = bytes.get(i);
        }
        return out;
    }

    /** True if caret sits in the ASCII column of a hex-dump line ({@code " |...|"}). */
    public static boolean isDumpCaretInAsciiColumn(String dump, int caret) {
        if (dump == null || caret < 0) {
            return false;
        }
        int safe = Math.min(caret, dump.length());
        int lineStart = dump.lastIndexOf('\n', Math.max(0, safe - 1)) + 1;
        int lineEnd = dump.indexOf('\n', safe);
        if (lineEnd < 0) {
            lineEnd = dump.length();
        }
        String line = dump.substring(lineStart, lineEnd);
        int sep = line.indexOf(" |");
        if (sep < 0) {
            return false;
        }
        int asciiStart = lineStart + sep + 2;
        return safe >= asciiStart;
    }

    public static String toAsciiPreview(byte[] data, int max) {
        if (data == null) {
            return "";
        }
        int n = Math.min(data.length, max);
        StringBuilder sb = new StringBuilder(n);
        for (int i = 0; i < n; i++) {
            int b = data[i] & 0xFF;
            sb.append(b >= 0x20 && b < 0x7F ? (char) b : '.');
        }
        if (data.length > max) {
            sb.append("…");
        }
        return sb.toString();
    }

    public static byte[] replaceAscii(byte[] data, String search, String replace) {
        if (data == null || search == null || search.isEmpty()) {
            return data == null ? new byte[0] : data.clone();
        }
        String hay = new String(data, StandardCharsets.ISO_8859_1);
        String replaced = hay.replace(search, replace == null ? "" : replace);
        return replaced.getBytes(StandardCharsets.ISO_8859_1);
    }

    public static byte[] replaceHexPattern(byte[] data, String searchHex, String replaceHex) {
        byte[] needle = fromContinuousHex(searchHex);
        byte[] replacement = fromContinuousHex(replaceHex);
        if (needle.length == 0 || data == null) {
            return data == null ? new byte[0] : data.clone();
        }
        List<Byte> out = new ArrayList<>(data.length);
        int i = 0;
        while (i < data.length) {
            if (i + needle.length <= data.length && matchesAt(data, i, needle)) {
                for (byte b : replacement) {
                    out.add(b);
                }
                i += needle.length;
            } else {
                out.add(data[i]);
                i++;
            }
        }
        byte[] result = new byte[out.size()];
        for (int j = 0; j < out.size(); j++) {
            result[j] = out.get(j);
        }
        return result;
    }

    private static boolean matchesAt(byte[] data, int offset, byte[] needle) {
        for (int i = 0; i < needle.length; i++) {
            if (data[offset + i] != needle[i]) {
                return false;
            }
        }
        return true;
    }

    public static boolean containsIgnoreCase(byte[] data, String asciiNeedle) {
        if (data == null || asciiNeedle == null || asciiNeedle.isEmpty()) {
            return false;
        }
        String hay = new String(data, StandardCharsets.ISO_8859_1).toLowerCase(Locale.ROOT);
        return hay.contains(asciiNeedle.toLowerCase(Locale.ROOT));
    }

    /**
     * Force {@code input} to exactly {@code length} bytes (truncate or pad with {@code 0x00}).
     * Used for in-place Winsock hooks that cannot grow the original buffer.
     */
    public static byte[] fitLength(byte[] input, int length) {
        if (length < 0) {
            return input == null ? new byte[0] : input.clone();
        }
        byte[] out = new byte[length];
        if (input == null || input.length == 0 || length == 0) {
            return out;
        }
        System.arraycopy(input, 0, out, 0, Math.min(input.length, length));
        return out;
    }

    /**
     * Fit to original capacity, sync length fields into HEX, ready for UI / delivery prep.
     */
    public static byte[] applyLogicalLength(byte[] original, byte[] edited) {
        if (original == null) {
            original = new byte[0];
        }
        if (edited == null) {
            edited = new byte[0];
        }
        byte[] fitted = fitLength(edited, original.length);
        byte[] synced = syncLengthPrefixes(original, fitted);
        return syncLeadingFrameLength(original, synced);
    }

    /**
     * Wire length to hand to Winsock ({@code send}/{@code recv} len) after logical edits.
     * Prefers a leading frame-length field; otherwise trims trailing {@code 0x00} introduced
     * by shortening content; never exceeds buffer capacity.
     */
    public static int logicalWireLength(byte[] original, byte[] prepared) {
        if (prepared == null || prepared.length == 0) {
            return 0;
        }
        int fromFrame = inferWireLengthFromLeadingFields(prepared);
        if (fromFrame > 0 && fromFrame <= prepared.length) {
            return fromFrame;
        }
        if (original == null || original.length != prepared.length) {
            return prepared.length;
        }
        if (Arrays.equals(original, prepared)) {
            return prepared.length;
        }
        int contentEnd = endExcludingTrailingZeros(prepared);
        int origEnd = endExcludingTrailingZeros(original);
        // Shortened payload left trailing 0x00 padding inside the locked buffer.
        if (contentEnd > 0 && contentEnd < prepared.length && contentEnd <= origEnd
                && trailingZerosOnly(prepared, contentEnd)) {
            return Math.max(contentEnd, 1);
        }
        return prepared.length;
    }

    /** Truncate {@code prepared} to {@link #logicalWireLength}. */
    public static byte[] forWireDelivery(byte[] original, byte[] prepared) {
        if (prepared == null) {
            return new byte[0];
        }
        byte[] synced = prepared;
        if (original != null && original.length == prepared.length) {
            synced = applyLogicalLength(original, prepared);
        }
        int n = logicalWireLength(original == null ? synced : original, synced);
        if (n >= synced.length) {
            return synced;
        }
        return Arrays.copyOf(synced, Math.max(n, 0));
    }

    /**
     * After an in-place string edit (same total buffer size), update length prefixes that
     * previously matched the old printable-run length so TCP/binary framing stays consistent.
     * Supports 1 / 2 / 4-byte little- and big-endian fields appearing before each changed run.
     */
    public static byte[] syncLengthPrefixes(byte[] before, byte[] after) {
        if (before == null || after == null || before.length != after.length || before.length == 0) {
            return after == null ? new byte[0] : after.clone();
        }
        if (Arrays.equals(before, after)) {
            return after.clone();
        }
        byte[] out = after.clone();
        int i = 0;
        while (i < before.length) {
            if (before[i] == after[i]) {
                i++;
                continue;
            }
            int runStart = i;
            // Expand left to the start of the printable run in the original buffer.
            while (runStart > 0 && before[runStart - 1] != 0 && isPrintable(before[runStart - 1])) {
                runStart--;
            }

            int oldEnd = runStart;
            while (oldEnd < before.length && before[oldEnd] != 0 && isPrintable(before[oldEnd])) {
                oldEnd++;
            }
            int oldLen = oldEnd - runStart;
            if (oldLen < 2) {
                int j = i;
                while (j < before.length && before[j] != after[j]) {
                    j++;
                }
                i = Math.max(j, i + 1);
                continue;
            }

            int newEnd = runStart;
            while (newEnd < out.length && out[newEnd] != 0 && isPrintable(out[newEnd])) {
                newEnd++;
            }
            int newLen = newEnd - runStart;
            if (newLen != oldLen) {
                patchLengthFields(out, runStart, oldLen, newLen);
            }
            i = Math.max(oldEnd, i + 1);
        }
        return out;
    }

    /**
     * If a leading u8/u16/u32 field encoded the old total (or total−header) frame size,
     * rewrite it to the new logical content end so HEX reflects the delivery length.
     */
    static byte[] syncLeadingFrameLength(byte[] original, byte[] synced) {
        if (original == null || synced == null || original.length != synced.length || synced.length == 0) {
            return synced == null ? new byte[0] : synced.clone();
        }
        int oldTotal = original.length;
        int newTotal = endExcludingTrailingZeros(synced);
        if (newTotal <= 0 || newTotal >= oldTotal) {
            // Still try when content end equals full buffer but payload length field changed.
            newTotal = synced.length;
        }
        if (newTotal == oldTotal && Arrays.equals(original, synced)) {
            return synced;
        }
        int contentEnd = Math.min(Math.max(endExcludingTrailingZeros(synced), 1), synced.length);
        byte[] out = synced.clone();
        // Candidates the leading field might have stored for the original packet.
        int[] oldCandidates = {
                oldTotal,
                oldTotal - 1,
                oldTotal - 2,
                oldTotal - 4,
                endExcludingTrailingZeros(original)
        };
        int[] newCandidates = {
                contentEnd,
                contentEnd - 1,
                contentEnd - 2,
                contentEnd - 4,
                contentEnd
        };
        for (int i = 0; i < oldCandidates.length; i++) {
            int oldV = oldCandidates[i];
            int newV = newCandidates[Math.min(i, newCandidates.length - 1)];
            if (oldV <= 0 || newV <= 0 || newV > synced.length) {
                continue;
            }
            if (tryWriteLengthAt(out, 0, oldV, newV)) {
                return out;
            }
        }
        return out;
    }

    private static boolean tryWriteLengthAt(byte[] data, int pos, int oldLen, int newLen) {
        if (pos < 0 || data == null) {
            return false;
        }
        if (pos < data.length && (data[pos] & 0xFF) == oldLen && newLen <= 0xFF) {
            data[pos] = (byte) newLen;
            return true;
        }
        if (pos + 1 < data.length) {
            int le = (data[pos] & 0xFF) | ((data[pos + 1] & 0xFF) << 8);
            int be = ((data[pos] & 0xFF) << 8) | (data[pos + 1] & 0xFF);
            if (le == oldLen && newLen <= 0xFFFF) {
                data[pos] = (byte) (newLen & 0xFF);
                data[pos + 1] = (byte) ((newLen >> 8) & 0xFF);
                return true;
            }
            if (be == oldLen && newLen <= 0xFFFF) {
                data[pos] = (byte) ((newLen >> 8) & 0xFF);
                data[pos + 1] = (byte) (newLen & 0xFF);
                return true;
            }
        }
        if (pos + 3 < data.length) {
            long le = (data[pos] & 0xFFL)
                    | ((data[pos + 1] & 0xFFL) << 8)
                    | ((data[pos + 2] & 0xFFL) << 16)
                    | ((data[pos + 3] & 0xFFL) << 24);
            long be = ((data[pos] & 0xFFL) << 24)
                    | ((data[pos + 1] & 0xFFL) << 16)
                    | ((data[pos + 2] & 0xFFL) << 8)
                    | (data[pos + 3] & 0xFFL);
            if (le == oldLen) {
                data[pos] = (byte) (newLen & 0xFF);
                data[pos + 1] = (byte) ((newLen >> 8) & 0xFF);
                data[pos + 2] = (byte) ((newLen >> 16) & 0xFF);
                data[pos + 3] = (byte) ((newLen >> 24) & 0xFF);
                return true;
            }
            if (be == oldLen) {
                data[pos] = (byte) ((newLen >> 24) & 0xFF);
                data[pos + 1] = (byte) ((newLen >> 16) & 0xFF);
                data[pos + 2] = (byte) ((newLen >> 8) & 0xFF);
                data[pos + 3] = (byte) (newLen & 0xFF);
                return true;
            }
        }
        return false;
    }

    /**
     * Infer total wire bytes from a leading length field (len / len+hdr).
     */
    static int inferWireLengthFromLeadingFields(byte[] data) {
        if (data == null || data.length == 0) {
            return -1;
        }
        // u8
        int u8 = data[0] & 0xFF;
        if (u8 > 0 && u8 <= data.length && (u8 == data.length || u8 + 1 == data.length)) {
            return u8 == data.length ? u8 : u8 + 1;
        }
        if (data.length >= 2) {
            int le = (data[0] & 0xFF) | ((data[1] & 0xFF) << 8);
            int be = ((data[0] & 0xFF) << 8) | (data[1] & 0xFF);
            for (int v : new int[]{le, be}) {
                if (v > 0 && v <= data.length && (v == data.length || v + 2 == data.length)) {
                    return v == data.length ? v : v + 2;
                }
            }
        }
        if (data.length >= 4) {
            long le = (data[0] & 0xFFL)
                    | ((data[1] & 0xFFL) << 8)
                    | ((data[2] & 0xFFL) << 16)
                    | ((data[3] & 0xFFL) << 24);
            long be = ((data[0] & 0xFFL) << 24)
                    | ((data[1] & 0xFFL) << 16)
                    | ((data[2] & 0xFFL) << 8)
                    | (data[3] & 0xFFL);
            for (long v : new long[]{le, be}) {
                if (v > 0 && v <= data.length && (v == data.length || v + 4 == data.length)) {
                    return (int) (v == data.length ? v : v + 4);
                }
            }
        }
        // After sync, field may describe content end (not full padded buffer).
        if (data.length >= 2) {
            int le = (data[0] & 0xFF) | ((data[1] & 0xFF) << 8);
            int be = ((data[0] & 0xFF) << 8) | (data[1] & 0xFF);
            int content = endExcludingTrailingZeros(data);
            for (int v : new int[]{le, be}) {
                if (v > 0 && v <= data.length && (v == content || v + 2 == content)) {
                    return v == content ? v : v + 2;
                }
            }
        }
        return -1;
    }

    private static int endExcludingTrailingZeros(byte[] data) {
        if (data == null || data.length == 0) {
            return 0;
        }
        int i = data.length - 1;
        while (i >= 0 && data[i] == 0) {
            i--;
        }
        return i + 1;
    }

    private static boolean trailingZerosOnly(byte[] data, int from) {
        if (data == null || from < 0) {
            return false;
        }
        for (int i = from; i < data.length; i++) {
            if (data[i] != 0) {
                return false;
            }
        }
        return from < data.length;
    }

    private static boolean isPrintable(byte b) {
        int v = b & 0xFF;
        return v >= 0x20 && v < 0x7F;
    }

    /**
     * Patch the length field closest to {@code runStart} among u8 / u16 / u32 LE|BE
     * that currently equals {@code oldLen}.
     */
    private static void patchLengthFields(byte[] data, int runStart, int oldLen, int newLen) {
        if (oldLen <= 0 || newLen < 0 || newLen > 0xFFFFFFFFL || runStart <= 0) {
            return;
        }
        int bestPos = -1;
        int bestWidth = 0;
        boolean bestBe = false;
        int bestDist = Integer.MAX_VALUE;

        for (int pos = runStart - 1; pos >= 0; pos--) {
            int dist = runStart - pos;
            if ((data[pos] & 0xFF) == oldLen && newLen <= 0xFF && dist < bestDist) {
                bestPos = pos;
                bestWidth = 1;
                bestBe = false;
                bestDist = dist;
            }
        }
        for (int pos = runStart - 2; pos >= 0; pos--) {
            int dist = runStart - pos;
            int le = (data[pos] & 0xFF) | ((data[pos + 1] & 0xFF) << 8);
            int be = ((data[pos] & 0xFF) << 8) | (data[pos + 1] & 0xFF);
            if (le == oldLen && newLen <= 0xFFFF && dist < bestDist) {
                bestPos = pos;
                bestWidth = 2;
                bestBe = false;
                bestDist = dist;
            }
            if (be == oldLen && newLen <= 0xFFFF && dist < bestDist) {
                bestPos = pos;
                bestWidth = 2;
                bestBe = true;
                bestDist = dist;
            }
        }
        for (int pos = runStart - 4; pos >= 0; pos--) {
            int dist = runStart - pos;
            long le = (data[pos] & 0xFFL)
                    | ((data[pos + 1] & 0xFFL) << 8)
                    | ((data[pos + 2] & 0xFFL) << 16)
                    | ((data[pos + 3] & 0xFFL) << 24);
            long be = ((data[pos] & 0xFFL) << 24)
                    | ((data[pos + 1] & 0xFFL) << 16)
                    | ((data[pos + 2] & 0xFFL) << 8)
                    | (data[pos + 3] & 0xFFL);
            if (le == oldLen && dist < bestDist) {
                bestPos = pos;
                bestWidth = 4;
                bestBe = false;
                bestDist = dist;
            }
            if (be == oldLen && dist < bestDist) {
                bestPos = pos;
                bestWidth = 4;
                bestBe = true;
                bestDist = dist;
            }
        }
        if (bestPos < 0) {
            return;
        }
        if (bestWidth == 1) {
            data[bestPos] = (byte) newLen;
        } else if (bestWidth == 2) {
            if (bestBe) {
                data[bestPos] = (byte) ((newLen >> 8) & 0xFF);
                data[bestPos + 1] = (byte) (newLen & 0xFF);
            } else {
                data[bestPos] = (byte) (newLen & 0xFF);
                data[bestPos + 1] = (byte) ((newLen >> 8) & 0xFF);
            }
        } else {
            if (bestBe) {
                data[bestPos] = (byte) ((newLen >> 24) & 0xFF);
                data[bestPos + 1] = (byte) ((newLen >> 16) & 0xFF);
                data[bestPos + 2] = (byte) ((newLen >> 8) & 0xFF);
                data[bestPos + 3] = (byte) (newLen & 0xFF);
            } else {
                data[bestPos] = (byte) (newLen & 0xFF);
                data[bestPos + 1] = (byte) ((newLen >> 8) & 0xFF);
                data[bestPos + 2] = (byte) ((newLen >> 16) & 0xFF);
                data[bestPos + 3] = (byte) ((newLen >> 24) & 0xFF);
            }
        }
    }
}
