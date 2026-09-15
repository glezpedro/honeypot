package com.glezpedro.honeypot.agg;

public interface CountAggregator {

    void add(int key, long delta);

    long estimate(int key);

    long memoryBytes();

    void reset();
}
