package com.glezpedro.honeypot.agg;

public interface TopKAggregator {

    void add(int key);

    int[] top(int k);

    long memoryBytes();

    void reset();
}
