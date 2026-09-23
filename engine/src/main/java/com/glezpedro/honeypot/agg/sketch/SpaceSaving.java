package com.glezpedro.honeypot.agg.sketch;

import com.glezpedro.honeypot.agg.TopKAggregator;
import it.unimi.dsi.fastutil.HashCommon;
import it.unimi.dsi.fastutil.ints.Int2IntOpenHashMap;

public final class SpaceSaving implements TopKAggregator {

    private final int capacity;
    private final int[] keys;
    private final long[] counts;
    private final long[] errors;
    private final Int2IntOpenHashMap position;
    private int size;

    public SpaceSaving(int capacity) {
        if (capacity <= 0) {
            throw new IllegalArgumentException("capacity debe ser positiva");
        }
        this.capacity = capacity;
        this.keys = new int[capacity];
        this.counts = new long[capacity];
        this.errors = new long[capacity];
        this.position = new Int2IntOpenHashMap(capacity);
        this.position.defaultReturnValue(-1);
    }

    @Override
    public void add(int key) {
        int slot = position.get(key);
        if (slot >= 0) {
            counts[slot]++;
            siftDown(slot);
            return;
        }
        if (size < capacity) {
            keys[size] = key;
            counts[size] = 1;
            errors[size] = 0;
            position.put(key, size);
            siftUp(size++);
            return;
        }
        // La raiz es el minimo: se desaloja y la clave nueva hereda su cuenta.
        long minimum = counts[0];
        position.remove(keys[0]);
        keys[0] = key;
        errors[0] = minimum;
        counts[0] = minimum + 1;
        position.put(key, 0);
        siftDown(0);
    }

    @Override
    public int[] top(int k) {
        int wanted = Math.min(Math.max(k, 0), size);
        Integer[] order = new Integer[size];
        for (int i = 0; i < size; i++) {
            order[i] = i;
        }
        java.util.Arrays.sort(order, (a, b) -> Long.compare(counts[b], counts[a]));
        int[] result = new int[wanted];
        for (int i = 0; i < wanted; i++) {
            result[i] = keys[order[i]];
        }
        return result;
    }

    @Override
    public long count(int key) {
        int slot = position.get(key);
        return slot < 0 ? 0 : counts[slot];
    }

    public long overestimate(int key) {
        int slot = position.get(key);
        return slot < 0 ? 0 : errors[slot];
    }

    @Override
    public int size() {
        return size;
    }

    @Override
    public long memoryBytes() {
        long slots = (long) capacity * (Integer.BYTES + Long.BYTES + Long.BYTES);
        long index = (long) HashCommon.arraySize(capacity, 0.75f) * (Integer.BYTES + Integer.BYTES);
        return slots + index;
    }

    @Override
    public void reset() {
        java.util.Arrays.fill(counts, 0, size, 0);
        java.util.Arrays.fill(errors, 0, size, 0);
        position.clear();
        size = 0;
    }

    private void siftUp(int index) {
        while (index > 0) {
            int parent = (index - 1) >>> 1;
            if (counts[parent] <= counts[index]) {
                break;
            }
            swap(parent, index);
            index = parent;
        }
    }

    private void siftDown(int index) {
        while (true) {
            int left = index * 2 + 1;
            if (left >= size) {
                return;
            }
            int smallest = left;
            int right = left + 1;
            if (right < size && counts[right] < counts[left]) {
                smallest = right;
            }
            if (counts[index] <= counts[smallest]) {
                return;
            }
            swap(index, smallest);
            index = smallest;
        }
    }

    private void swap(int a, int b) {
        int key = keys[a];
        long count = counts[a];
        long error = errors[a];
        keys[a] = keys[b];
        counts[a] = counts[b];
        errors[a] = errors[b];
        keys[b] = key;
        counts[b] = count;
        errors[b] = error;
        position.put(keys[a], a);
        position.put(keys[b], b);
    }
}
