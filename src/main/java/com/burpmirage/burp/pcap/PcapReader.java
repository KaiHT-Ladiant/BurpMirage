package com.burpmirage.burp.pcap;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Lightweight PCAP / PCAPNG reader focused on TCP application payloads.
 * No native libpcap dependency — classic Ethernet / Linux SLL / raw IPv4.
 */
public final class PcapReader {
    private static final int LINKTYPE_ETHERNET = 1;
    private static final int LINKTYPE_RAW = 101;
    private static final int LINKTYPE_LINUX_SLL = 113;
    private static final int LINKTYPE_IPV4 = 228;
    private static final int LINKTYPE_IPV6 = 229;

    private PcapReader() {
    }

    public static List<PcapTcpSegment> readTcpPayloads(Path path) throws IOException {
        byte[] all = Files.readAllBytes(path);
        if (all.length < 24) {
            throw new IOException("File too small to be a capture");
        }
        int magicBe = u32(all, 0, false); /* big-endian magic */
        if (magicBe == 0x0A0D0D0A) {
            return readPcapNg(all);
        }
        return readClassicPcap(all);
    }

    private static List<PcapTcpSegment> readClassicPcap(byte[] all) throws IOException {
        int magicBe = u32(all, 0, false); /* big-endian magic */
        boolean le;
        boolean nanos;
        if (magicBe == 0xA1B2C3D4) {
            le = false;
            nanos = false;
        } else if (magicBe == 0xD4C3B2A1) {
            le = true;
            nanos = false;
        } else if (magicBe == 0xA1B23C4D) {
            le = false;
            nanos = true;
        } else if (magicBe == 0x4D3CB2A1) {
            le = true;
            nanos = true;
        } else {
            throw new IOException(String.format(
                    "Unsupported PCAP magic 0x%08X (use .pcap or .pcapng)", magicBe));
        }
        int linkType = u32(all, 20, le);

        List<PcapTcpSegment> out = new ArrayList<>();
        int offset = 24;
        int index = 0;
        while (offset + 16 <= all.length) {
            long tsSec = u32(all, offset, le) & 0xFFFFFFFFL;
            long tsFrac = u32(all, offset + 4, le) & 0xFFFFFFFFL;
            int inclLen = u32(all, offset + 8, le);
            offset += 16;
            if (inclLen < 0 || offset + inclLen > all.length) {
                break;
            }
            Instant ts = nanos
                    ? Instant.ofEpochSecond(tsSec, tsFrac)
                    : Instant.ofEpochSecond(tsSec, tsFrac * 1000L);
            extractFromFrame(out, index++, ts, linkType, all, offset, inclLen);
            offset += inclLen;
        }
        return out;
    }

    private static List<PcapTcpSegment> readPcapNg(byte[] all) throws IOException {
        List<PcapTcpSegment> out = new ArrayList<>();
        int linkType = LINKTYPE_ETHERNET;
        boolean le = true;
        int offset = 0;
        int index = 0;

        while (offset + 8 <= all.length) {
            int blockTypeBe = u32(all, offset, false);
            if (offset == 0 && blockTypeBe == 0x0A0D0D0A) {
                if (offset + 16 > all.length) {
                    break;
                }
                int bom = u32(all, offset + 8, false);
                le = bom != 0x1A2B3C4D;
                int totalLen = u32(all, offset + 4, le);
                if (totalLen < 12 || offset + totalLen > all.length) {
                    break;
                }
                offset += totalLen;
                continue;
            }

            int blockType = u32(all, offset, le);
            int totalLen = u32(all, offset + 4, le);
            if (totalLen < 12 || offset + totalLen > all.length) {
                break;
            }

            if (blockType == 0x00000001) { // Interface Description
                linkType = u16(all, offset + 8, le);
            } else if (blockType == 0x00000006) { // Enhanced Packet
                if (totalLen >= 32) {
                    long tsHigh = u32(all, offset + 12, le) & 0xFFFFFFFFL;
                    long tsLow = u32(all, offset + 16, le) & 0xFFFFFFFFL;
                    int caplen = u32(all, offset + 20, le);
                    long tsUs = (tsHigh << 32) | tsLow;
                    Instant ts = Instant.ofEpochSecond(tsUs / 1_000_000L, (tsUs % 1_000_000L) * 1000L);
                    int dataOff = offset + 28;
                    if (caplen > 0 && dataOff + caplen <= offset + totalLen - 4) {
                        extractFromFrame(out, index++, ts, linkType, all, dataOff, caplen);
                    }
                }
            } else if (blockType == 0x00000002) { // Simple Packet
                if (totalLen >= 16) {
                    int origLen = u32(all, offset + 8, le);
                    int dataLen = Math.min(origLen, totalLen - 16);
                    if (dataLen > 0) {
                        extractFromFrame(out, index++, Instant.EPOCH, linkType, all, offset + 12, dataLen);
                    }
                }
            }
            offset += totalLen;
        }
        return out;
    }

    private static void extractFromFrame(
            List<PcapTcpSegment> out,
            int index,
            Instant ts,
            int linkType,
            byte[] buf,
            int off,
            int len
    ) {
        try {
            int ipOff;
            if (linkType == LINKTYPE_ETHERNET) {
                if (len < 14) {
                    return;
                }
                int etherType = u16(buf, off + 12, false);
                ipOff = off + 14;
                if (etherType == 0x8100 && len >= 18) {
                    etherType = u16(buf, off + 16, false);
                    ipOff = off + 18;
                }
                if (etherType != 0x0800) {
                    return;
                }
            } else if (linkType == LINKTYPE_LINUX_SLL) {
                if (len < 16) {
                    return;
                }
                int proto = u16(buf, off + 14, false);
                if (proto != 0x0800) {
                    return;
                }
                ipOff = off + 16;
            } else if (linkType == LINKTYPE_RAW || linkType == LINKTYPE_IPV4) {
                ipOff = off;
            } else if (linkType == LINKTYPE_IPV6) {
                return;
            } else if (len >= 14 && u16(buf, off + 12, false) == 0x0800) {
                ipOff = off + 14;
            } else {
                return;
            }
            parseIpv4Tcp(out, index, ts, buf, ipOff, off + len);
        } catch (RuntimeException ignored) {
            // Skip malformed frames
        }
    }

    private static void parseIpv4Tcp(
            List<PcapTcpSegment> out,
            int index,
            Instant ts,
            byte[] buf,
            int ipOff,
            int end
    ) {
        if (ipOff + 20 > end) {
            return;
        }
        int vihl = buf[ipOff] & 0xFF;
        if ((vihl >> 4) != 4) {
            return;
        }
        int ihl = (vihl & 0x0F) * 4;
        if (ihl < 20 || ipOff + ihl > end) {
            return;
        }
        int totalLen = u16(buf, ipOff + 2, false);
        int proto = buf[ipOff + 9] & 0xFF;
        if (proto != 6) {
            return;
        }
        String src = ipv4(buf, ipOff + 12);
        String dst = ipv4(buf, ipOff + 16);
        int tcpOff = ipOff + ihl;
        if (tcpOff + 20 > end) {
            return;
        }
        int srcPort = u16(buf, tcpOff, false);
        int dstPort = u16(buf, tcpOff + 2, false);
        long seq = u32(buf, tcpOff + 4, false) & 0xFFFFFFFFL;
        int dataOff = ((buf[tcpOff + 12] & 0xFF) >> 4) * 4;
        if (dataOff < 20 || tcpOff + dataOff > end) {
            return;
        }
        int ipEnd = ipOff + Math.min(totalLen, end - ipOff);
        int payloadOff = tcpOff + dataOff;
        int payloadLen = Math.max(0, ipEnd - payloadOff);
        if (payloadLen <= 0) {
            return;
        }
        byte[] payload = new byte[payloadLen];
        System.arraycopy(buf, payloadOff, payload, 0, payloadLen);
        out.add(new PcapTcpSegment(
                index,
                ts,
                src,
                dst,
                srcPort,
                dstPort,
                seq,
                payload,
                isLikelyPlaintext(payload)
        ));
    }

    private static int u16(byte[] b, int off, boolean le) {
        int a = b[off] & 0xFF;
        int c = b[off + 1] & 0xFF;
        return le ? (c << 8) | a : (a << 8) | c;
    }

    private static int u32(byte[] b, int off, boolean le) {
        int b0 = b[off] & 0xFF;
        int b1 = b[off + 1] & 0xFF;
        int b2 = b[off + 2] & 0xFF;
        int b3 = b[off + 3] & 0xFF;
        return le
                ? (b3 << 24) | (b2 << 16) | (b1 << 8) | b0
                : (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
    }

    private static String ipv4(byte[] buf, int off) {
        return (buf[off] & 0xFF) + "." + (buf[off + 1] & 0xFF) + "."
                + (buf[off + 2] & 0xFF) + "." + (buf[off + 3] & 0xFF);
    }

    /** Heuristic: mostly printable ASCII / common whitespace → likely cleartext. */
    public static boolean isLikelyPlaintext(byte[] data) {
        if (data == null || data.length == 0) {
            return false;
        }
        int printable = 0;
        int n = Math.min(data.length, 512);
        for (int i = 0; i < n; i++) {
            int b = data[i] & 0xFF;
            if (b == 9 || b == 10 || b == 13 || (b >= 0x20 && b < 0x7F)) {
                printable++;
            }
        }
        return printable * 100 / n >= 70;
    }

    /** First occurrence of {@code needle} in {@code hay}, or -1. */
    public static int indexOf(byte[] hay, byte[] needle) {
        if (hay == null || needle == null || needle.length == 0 || hay.length < needle.length) {
            return -1;
        }
        outer:
        for (int i = 0; i <= hay.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (hay[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }
}
