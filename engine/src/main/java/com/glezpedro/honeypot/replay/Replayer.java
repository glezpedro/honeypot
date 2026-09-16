package com.glezpedro.honeypot.replay;

import com.glezpedro.honeypot.event.EventSink;
import com.glezpedro.honeypot.event.EventStore;

import java.util.concurrent.locks.LockSupport;

public final class Replayer {

    private final EventStore events;

    public Replayer(EventStore events) {
        this.events = events;
    }

    public int replay(EventSink sink) {
        int size = events.size();
        for (int i = 0; i < size; i++) {
            sink.accept(events, i);
        }
        return size;
    }

    public int replay(EventSink sink, long eventsPerSecond) {
        if (eventsPerSecond <= 0) {
            throw new IllegalArgumentException("eventsPerSecond debe ser positivo");
        }
        long nanosPerEvent = 1_000_000_000L / eventsPerSecond;
        long start = System.nanoTime();
        int size = events.size();
        for (int i = 0; i < size; i++) {
            sink.accept(events, i);
            parkUntil(start + (i + 1) * nanosPerEvent);
        }
        return size;
    }

    private static void parkUntil(long deadlineNanos) {
        long remaining = deadlineNanos - System.nanoTime();
        while (remaining > 0) {
            LockSupport.parkNanos(remaining);
            remaining = deadlineNanos - System.nanoTime();
        }
    }
}
