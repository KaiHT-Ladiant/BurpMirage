package com.burpmirage.burp.util;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
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
     * When an ASCII column is present ({@code |....|}), printable characters there
     * override the corresponding hex bytes so string edits in the dump are applied.
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
            String asciiPart = null;
            String content = line;
            int pipe = line.indexOf('|');
            if (pipe >= 0) {
                content = line.substring(0, pipe);
                int pipe2 = line.indexOf('|', pipe + 1);
                if (pipe2 > pipe) {
                    asciiPart = line.substring(pipe + 1, pipe2);
                } else {
                    asciiPart = line.substring(pipe + 1);
                }
            }
            content = content.replaceFirst("^\\s*[0-9A-Fa-f]{4,8}\\s+", "");
            List<Byte> lineBytes = new ArrayList<>();
            Matcher m = hexByte.matcher(content);
            while (m.find()) {
                lineBytes.add((byte) Integer.parseInt(m.group(1), 16));
            }
            if (asciiPart != null) {
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
}
