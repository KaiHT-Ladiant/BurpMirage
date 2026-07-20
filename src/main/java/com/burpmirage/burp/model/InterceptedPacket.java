package com.burpmirage.burp.model;

import java.time.Instant;
import java.util.Arrays;
import java.util.UUID;

/**
 * A single intercepted or historical raw TCP/binary packet.
 */
public final class InterceptedPacket {
    private final String id;
    private final Instant timestamp;
    private final int pid;
    private final String processName;
    private final PacketDirection direction;
    private final String apiName;
    private final String peer;
    private final int socketFd;
    private byte[] data;
    private byte[] originalData;
    private volatile PacketStatus status;
    /** Shared id linking a SEND with its RECV response(s) on the same channel (FIFO + multi-recv). */
    private volatile String pairId;

    public enum PacketStatus {
        PENDING,
        FORWARDED,
        DROPPED,
        AUTO,
        REPLAYED
    }

    public InterceptedPacket(
            String id,
            Instant timestamp,
            int pid,
            String processName,
            PacketDirection direction,
            String apiName,
            String peer,
            int socketFd,
            byte[] data
    ) {
        this.id = id != null ? id : UUID.randomUUID().toString();
        this.timestamp = timestamp != null ? timestamp : Instant.now();
        this.pid = pid;
        this.processName = processName != null ? processName : "";
        this.direction = direction;
        this.apiName = apiName != null ? apiName : "";
        this.peer = peer != null ? peer : "";
        this.socketFd = socketFd;
        this.data = data != null ? Arrays.copyOf(data, data.length) : new byte[0];
        this.originalData = Arrays.copyOf(this.data, this.data.length);
        this.status = PacketStatus.PENDING;
        this.pairId = null;
    }

    public static InterceptedPacket create(
            int pid,
            String processName,
            PacketDirection direction,
            String apiName,
            String peer,
            int socketFd,
            byte[] data
    ) {
        return new InterceptedPacket(
                UUID.randomUUID().toString(),
                Instant.now(),
                pid,
                processName,
                direction,
                apiName,
                peer,
                socketFd,
                data
        );
    }

    public String id() {
        return id;
    }

    public Instant timestamp() {
        return timestamp;
    }

    public int pid() {
        return pid;
    }

    public String processName() {
        return processName;
    }

    public PacketDirection direction() {
        return direction;
    }

    public String apiName() {
        return apiName;
    }

    public String peer() {
        return peer;
    }

    public int socketFd() {
        return socketFd;
    }

    public byte[] data() {
        return Arrays.copyOf(data, data.length);
    }

    public void setData(byte[] newData) {
        this.data = newData != null ? Arrays.copyOf(newData, newData.length) : new byte[0];
    }

    public byte[] originalData() {
        return Arrays.copyOf(originalData, originalData.length);
    }

    public boolean isModified() {
        return !Arrays.equals(data, originalData);
    }

    public PacketStatus status() {
        return status;
    }

    public void setStatus(PacketStatus status) {
        this.status = status;
    }

    public String pairId() {
        return pairId;
    }

    public void setPairId(String pairId) {
        this.pairId = pairId;
    }

    public int length() {
        return data.length;
    }

    public InterceptedPacket copyForReplay() {
        InterceptedPacket copy = new InterceptedPacket(
                UUID.randomUUID().toString(),
                Instant.now(),
                pid,
                processName,
                direction,
                apiName,
                peer,
                socketFd,
                data
        );
        copy.setStatus(PacketStatus.REPLAYED);
        return copy;
    }
}
