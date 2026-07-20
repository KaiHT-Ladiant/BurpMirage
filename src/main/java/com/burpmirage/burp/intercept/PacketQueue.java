package com.burpmirage.burp.intercept;

import com.burpmirage.burp.model.InterceptedPacket;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Queue of packets waiting for user Forward/Drop decisions.
 * The head item is exposed as {@link #current()} for the Interceptor UI.
 */
public final class PacketQueue {
    private final BlockingQueue<PendingPacket> waiting = new LinkedBlockingQueue<>();
    private final AtomicReference<PendingPacket> current = new AtomicReference<>();

    public record PendingPacket(InterceptedPacket packet, DecisionCallback callback) {
    }

    @FunctionalInterface
    public interface DecisionCallback {
        void complete(InterceptDecision decision, byte[] maybeModifiedData);
    }

    public record InterceptDecision(Action action, byte[] data) {
        public enum Action { FORWARD, DROP }
    }

    public synchronized void enqueue(InterceptedPacket packet, DecisionCallback callback) {
        PendingPacket pending = new PendingPacket(packet, callback);
        if (current.get() == null) {
            current.set(pending);
        } else {
            waiting.offer(pending);
        }
    }

    public PendingPacket current() {
        return current.get();
    }

    public synchronized void advanceAfterDecision() {
        PendingPacket next = waiting.poll();
        current.set(next);
    }

    public synchronized void clearCurrentWithoutDecision() {
        current.set(null);
    }

    public int size() {
        return waiting.size() + (current.get() != null ? 1 : 0);
    }

    public synchronized void clear() {
        PendingPacket head = current.getAndSet(null);
        if (head != null) {
            head.callback().complete(
                    new InterceptDecision(InterceptDecision.Action.FORWARD, head.packet().data()),
                    head.packet().data()
            );
        }
        PendingPacket p;
        while ((p = waiting.poll()) != null) {
            p.callback().complete(
                    new InterceptDecision(InterceptDecision.Action.FORWARD, p.packet().data()),
                    p.packet().data()
            );
        }
    }
}
