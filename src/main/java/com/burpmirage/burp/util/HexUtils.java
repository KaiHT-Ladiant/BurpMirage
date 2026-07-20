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
                int n = Math.min(asciiPart.length(), lineBytes.size());
                for (int i = 0; i < n; i++) {
                    char c = asciiPart.charAt(i);
                    // '.' in dump means "non-printable placeholder" — keep hex byte
                    if (c != '.') {
                        lineBytes.set(i, (byte) (c & 0xFF));
                    }
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

    private static boolean isPrintable(byte b) {
        int v = b & 0xFF;
        return v >= 0x20 && v < 0x7F;
    }

    /**
     * Patch u8 / u16 / u32 LE+BE fields in {@code [0, runStart)} that equal {@code oldLen}.
     */
    private static void patchLengthFields(byte[] data, int runStart, int oldLen, int newLen) {
        if (oldLen <= 0 || newLen < 0 || newLen > 0xFFFFFFFFL) {
            return;
        }
        // Prefer fields closest to the string (scan backwards).
        for (int pos = runStart - 1; pos >= 0; pos--) {
            // uint8
            if ((data[pos] & 0xFF) == oldLen && newLen <= 0xFF) {
                data[pos] = (byte) newLen;
                return;
            }
        }
        for (int pos = runStart - 2; pos >= 0; pos--) {
            int le = (data[pos] & 0xFF) | ((data[pos + 1] & 0xFF) << 8);
            int be = ((data[pos] & 0xFF) << 8) | (data[pos + 1] & 0xFF);
            if (le == oldLen && newLen <= 0xFFFF) {
                data[pos] = (byte) (newLen & 0xFF);
                data[pos + 1] = (byte) ((newLen >> 8) & 0xFF);
                return;
            }
            if (be == oldLen && newLen <= 0xFFFF) {
                data[pos] = (byte) ((newLen >> 8) & 0xFF);
                data[pos + 1] = (byte) (newLen & 0xFF);
                return;
            }
        }
        for (int pos = runStart - 4; pos >= 0; pos--) {
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
                return;
            }
            if (be == oldLen) {
                data[pos] = (byte) ((newLen >> 24) & 0xFF);
                data[pos + 1] = (byte) ((newLen >> 16) & 0xFF);
                data[pos + 2] = (byte) ((newLen >> 8) & 0xFF);
                data[pos + 3] = (byte) (newLen & 0xFF);
                return;
            }
        }
    }
}
