package com.glezpedro.honeypot.agg;

public interface TopKAggregator {

    void add(int key);

    int[] top(int k);

    long count(int key);

    int size();

    long memoryBytes();

    void reset();
}
