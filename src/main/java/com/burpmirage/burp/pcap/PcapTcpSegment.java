package com.burpmirage.burp.pcap;

import java.time.Instant;
import java.util.Arrays;

/**
 * One TCP segment with a non-empty application payload extracted from a PCAP.
 */
public final class PcapTcpSegment {
    private final int index;
    private final Instant timestamp;
    private final String src;
    private final String dst;
    private final int srcPort;
    private final int dstPort;
    private final long seq;
    private final byte[] payload;
    private final boolean likelyPlaintext;

    public PcapTcpSegment(
            int index,
            Instant timestamp,
            String src,
            String dst,
            int srcPort,
            int dstPort,
            long seq,
            byte[] payload,
            boolean likelyPlaintext
    ) {
        this.index = index;
        this.timestamp = timestamp != null ? timestamp : Instant.EPOCH;
        this.src = src != null ? src : "";
        this.dst = dst != null ? dst : "";
        this.srcPort = srcPort;
        this.dstPort = dstPort;
        this.seq = seq;
        this.payload = payload != null ? Arrays.copyOf(payload, payload.length) : new byte[0];
        this.likelyPlaintext = likelyPlaintext;
    }

    public int index() {
        return index;
    }

    public Instant timestamp() {
        return timestamp;
    }

    public String src() {
        return src;
    }

    public String dst() {
        return dst;
    }

    public int srcPort() {
        return srcPort;
    }

    public int dstPort() {
        return dstPort;
    }

    public long seq() {
        return seq;
    }

    public byte[] payload() {
        return Arrays.copyOf(payload, payload.length);
    }

    public int length() {
        return payload.length;
    }

    public boolean likelyPlaintext() {
        return likelyPlaintext;
    }

    public String peer() {
        return dst + ":" + dstPort;
    }

    public String flowKey() {
        String a = src + ":" + srcPort;
        String b = dst + ":" + dstPort;
        return a.compareTo(b) <= 0 ? a + " <-> " + b : b + " <-> " + a;
    }
}
