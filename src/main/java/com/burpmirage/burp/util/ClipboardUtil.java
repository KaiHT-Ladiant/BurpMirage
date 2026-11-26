package com.burpmirage.burp.util;

import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;

/** Tiny clipboard helper for context-menu copy actions. */
public final class ClipboardUtil {
    private ClipboardUtil() {
    }

    public static void copyText(String text) {
        if (text == null) {
            text = "";
        }
        Toolkit.getDefaultToolkit()
                .getSystemClipboard()
                .setContents(new StringSelection(text), null);
    }

    public static String toHex(byte[] data) {
        if (data == null || data.length == 0) {
            return "";
        }
        StringBuilder sb = new StringBuilder(data.length * 3);
        for (int i = 0; i < data.length; i++) {
            if (i > 0) {
                sb.append(' ');
            }
            sb.append(String.format("%02x", data[i] & 0xff));
        }
        return sb.toString();
    }
}
