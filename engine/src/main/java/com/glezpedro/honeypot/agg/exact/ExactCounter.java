package com.glezpedro.honeypot.agg.exact;

import com.glezpedro.honeypot.agg.CountAggregator;
import it.unimi.dsi.fastutil.HashCommon;
import it.unimi.dsi.fastutil.ints.Int2LongOpenHashMap;

public final class ExactCounter implements CountAggregator {

    private static final long BYTES_PER_SLOT = Integer.BYTES + Long.BYTES;

    private final Int2LongOpenHashMap counts = new Int2LongOpenHashMap();

    @Override
    public void add(int key, long delta) {
        counts.addTo(key, delta);
    }

    @Override
    public long estimate(int key) {
        return counts.get(key);
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
