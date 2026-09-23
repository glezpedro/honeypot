package com.glezpedro.honeypot.agg.sketch;

import com.glezpedro.honeypot.agg.CardinalityAggregator;
import it.unimi.dsi.fastutil.HashCommon;
import it.unimi.dsi.fastutil.ints.Int2ObjectOpenHashMap;

public final class HyperLogLog implements CardinalityAggregator {

    private static final long ARRAY_OVERHEAD_BYTES = 16;

    private final int precision;
    private final int registers;
    private final double alpha;
    private final Int2ObjectOpenHashMap<byte[]> byKey = new Int2ObjectOpenHashMap<>();

    public HyperLogLog(int precision) {
        if (precision < 4 || precision > 16) {
            throw new IllegalArgumentException("precision debe estar entre 4 y 16");
        }
        this.precision = precision;
        this.registers = 1 << precision;
        this.alpha = alphaFor(registers);
    }

    public static HyperLogLog withError(double relativeError) {
        if (relativeError <= 0 || relativeError >= 1) {
            throw new IllegalArgumentException("el error relativo debe estar en (0, 1)");
        }
        double needed = Math.pow(1.04 / relativeError, 2);
        int precision = Math.max(4, Math.min(16, (int) Math.ceil(Math.log(needed) / Math.log(2))));
        return new HyperLogLog(precision);
    }

    @Override
    public void add(int key, int value) {
        byte[] slots = byKey.get(key);
        if (slots == null) {
            slots = new byte[registers];
            byKey.put(key, slots);
        }
        long hash = mix64(value);
        int index = (int) (hash >>> (64 - precision));
        // El OR garantiza que queden ceros que contar y acota el rango a 64 - precision + 1.
        int rank = Long.numberOfLeadingZeros((hash << precision) | (1L << (precision - 1))) + 1;
        if (rank > slots[index]) {
            slots[index] = (byte) rank;
        }
    }

    @Override
    public long estimate(int key) {
        byte[] slots = byKey.get(key);
        if (slots == null) {
            return 0;
        }
        double harmonic = 0;
        int empty = 0;
        for (byte slot : slots) {
            harmonic += Math.scalb(1.0, -slot);
            if (slot == 0) {
                empty++;
            }
        }
        double estimate = alpha * registers * registers / harmonic;
        if (estimate <= 2.5 * registers && empty > 0) {
            estimate = registers * Math.log((double) registers / empty);
        }
        return Math.round(estimate);
    }

    @Override
    public int[] keys() {
        return byKey.keySet().toIntArray();
    }

    @Override
    public long memoryBytes() {
        long table = (long) HashCommon.arraySize(byKey.size(), 0.75f) * (Integer.BYTES + Integer.BYTES);
        return table + (long) byKey.size() * (ARRAY_OVERHEAD_BYTES + registers);
    }

    @Override
    public void reset() {
        byKey.clear();
    }

    private static double alphaFor(int registers) {
        return switch (registers) {
            case 16 -> 0.673;
            case 32 -> 0.697;
            case 64 -> 0.709;
            default -> 0.7213 / (1 + 1.079 / registers);
        };
    }

    private static long mix64(long value) {
        long z = value + 0x9E3779B97F4A7C15L;
        z = (z ^ (z >>> 30)) * 0xBF58476D1CE4E5B9L;
        z = (z ^ (z >>> 27)) * 0x94D049BB133111EBL;
        return z ^ (z >>> 31);
    }
}
