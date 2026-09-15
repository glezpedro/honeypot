package com.glezpedro.honeypot.agg;

public interface CardinalityAggregator {

    void add(int key, int value);

    long estimate(int key);

    int[] keys();

    long memoryBytes();

    void reset();
}
