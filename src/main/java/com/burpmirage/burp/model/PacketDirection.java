package com.burpmirage.burp.model;

import com.burpmirage.burp.util.I18n;

/**
 * Direction of the hooked Winsock call relative to the target process.
 */
public enum PacketDirection {
    SEND,
    RECV;

    public String label() {
        return I18n.get("direction." + name().toLowerCase());
    }

    public static PacketDirection fromWire(String value) {
        if (value == null) {
            return SEND;
        }
        return switch (value.toLowerCase()) {
            case "recv", "wsarecv", "read" -> RECV;
            default -> SEND;
        };
    }
}
