package com.glezpedro.honeypot.agg.exact;

import com.glezpedro.honeypot.agg.TopKAggregator;
import it.unimi.dsi.fastutil.HashCommon;
import it.unimi.dsi.fastutil.ints.Int2LongOpenHashMap;

public final class ExactTopK implements TopKAggregator {

    private static final long BYTES_PER_SLOT = Integer.BYTES + Long.BYTES;

    private final Int2LongOpenHashMap counts = new Int2LongOpenHashMap();

    @Override
    public void add(int key) {
        counts.addTo(key, 1);
    }

    @Override
    public int[] top(int k) {
        int size = Math.min(Math.max(k, 0), counts.size());
        int[] topKeys = new int[size];
        long[] topCounts = new long[size];
        int filled = 0;
        for (int key : counts.keySet().toIntArray()) {
            long value = counts.get(key);
            if (filled == size && (size == 0 || value <= topCounts[size - 1])) {
                continue;
            }
            int position = filled < size ? filled++ : size - 1;
            while (position > 0 && topCounts[position - 1] < value) {
                topKeys[position] = topKeys[position - 1];
                topCounts[position] = topCounts[position - 1];
                position--;
            }
            topKeys[position] = key;
            topCounts[position] = value;
        }
        return topKeys;
    }

    @Override
    public long count(int key) {
        return counts.get(key);
    }

    @Override
    public int size() {
        return counts.size();
    }

    @Override
    public long memoryBytes() {
        return (long) HashCommon.arraySize(counts.size(), 0.75f) * BYTES_PER_SLOT;
    }

    @Override
    public void reset() {
        counts.clear();
    }
}
