package com.glezpedro.honeypot.agg.exact;

import com.glezpedro.honeypot.agg.CardinalityAggregator;
import it.unimi.dsi.fastutil.HashCommon;
import it.unimi.dsi.fastutil.ints.Int2ObjectOpenHashMap;
import it.unimi.dsi.fastutil.ints.IntOpenHashSet;

public final class ExactCardinality implements CardinalityAggregator {

    private static final long SET_OVERHEAD_BYTES = 48;

    private final Int2ObjectOpenHashMap<IntOpenHashSet> values = new Int2ObjectOpenHashMap<>();

    @Override
    public void add(int key, int value) {
        IntOpenHashSet seen = values.get(key);
        if (seen == null) {
            seen = new IntOpenHashSet();
            values.put(key, seen);
        }
        seen.add(value);
    }

    @Override
    public long estimate(int key) {
        IntOpenHashSet seen = values.get(key);
        return seen == null ? 0 : seen.size();
    }

    @Override
    public int[] keys() {
        return values.keySet().toIntArray();
    }

    @Override
    public long memoryBytes() {
        long total = (long) HashCommon.arraySize(values.size(), 0.75f) * (Integer.BYTES + Integer.BYTES);
        for (IntOpenHashSet seen : values.values()) {
            total += SET_OVERHEAD_BYTES + (long) HashCommon.arraySize(seen.size(), 0.75f) * Integer.BYTES;
        }
        return total;
    }

    @Override
    public void reset() {
        values.clear();
    }
}
