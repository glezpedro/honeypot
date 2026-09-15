package com.glezpedro.honeypot.event;

import java.util.Arrays;

public final class EventStore {

    private long[] timestamp;
    private int[] source;
    private int[] actor;
    private byte[] action;
    private byte[] outcome;
    private int size;

    public EventStore() {
        this(1024);
    }

    public EventStore(int capacity) {
        timestamp = new long[capacity];
        source = new int[capacity];
        actor = new int[capacity];
        action = new byte[capacity];
        outcome = new byte[capacity];
    }

    public void add(long timestamp, int source, int actor, Action action, Outcome outcome) {
        if (size == this.timestamp.length) {
            grow();
        }
        this.timestamp[size] = timestamp;
        this.source[size] = source;
        this.actor[size] = actor;
        this.action[size] = (byte) action.ordinal();
        this.outcome[size] = (byte) outcome.ordinal();
        size++;
    }

    private void grow() {
        int capacity = timestamp.length * 2;
        timestamp = Arrays.copyOf(timestamp, capacity);
        source = Arrays.copyOf(source, capacity);
        actor = Arrays.copyOf(actor, capacity);
        action = Arrays.copyOf(action, capacity);
        outcome = Arrays.copyOf(outcome, capacity);
    }

    public int size() {
        return size;
    }

    public long timestamp(int index) {
        return timestamp[index];
    }

    public int source(int index) {
        return source[index];
    }

    public int actor(int index) {
        return actor[index];
    }

    public Action action(int index) {
        return Action.of(action[index]);
    }

    public Outcome outcome(int index) {
        return Outcome.of(outcome[index]);
    }
}
