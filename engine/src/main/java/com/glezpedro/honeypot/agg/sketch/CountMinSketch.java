package com.glezpedro.honeypot.agg.sketch;

import com.glezpedro.honeypot.agg.CountAggregator;

import java.util.Arrays;
import java.util.Random;

public final class CountMinSketch implements CountAggregator {

    private final long[][] table;
    private final int width;
    private final int seedA;
    private final int seedB;

    public CountMinSketch(int width, int depth, long seed) {
        if (width <= 0 || depth <= 0) {
            throw new IllegalArgumentException("width y depth deben ser positivos");
        }
        this.width = width;
        this.table = new long[depth][width];
        Random random = new Random(seed);
        this.seedA = random.nextInt();
        this.seedB = random.nextInt();
    }

    public static CountMinSketch withError(double epsilon, double delta, long seed) {
        if (epsilon <= 0 || epsilon >= 1 || delta <= 0 || delta >= 1) {
            throw new IllegalArgumentException("epsilon y delta deben estar en (0, 1)");
        }
        int width = (int) Math.ceil(Math.E / epsilon);
        int depth = (int) Math.ceil(Math.log(1 / delta));
        return new CountMinSketch(width, Math.max(depth, 1), seed);
    }

    @Override
    public void add(int key, long delta) {
        int h1 = mix(key, seedA);
        int h2 = mix(key, seedB) | 1;
        for (int row = 0; row < table.length; row++) {
            table[row][column(h1, h2, row)] += delta;
        }
    }

    @Override
    public long estimate(int key) {
        int h1 = mix(key, seedA);
        int h2 = mix(key, seedB) | 1;
        long smallest = Long.MAX_VALUE;
        for (int row = 0; row < table.length; row++) {
            smallest = Math.min(smallest, table[row][column(h1, h2, row)]);
        }
        return smallest;
    }

    @Override
    public long memoryBytes() {
        return (long) table.length * width * Long.BYTES;
    }

    @Override
    public void reset() {
        for (long[] row : table) {
            Arrays.fill(row, 0);
        }
    }

    // Doble hashing de Kirsch-Mitzenmacher: dos hashes generan los d necesarios.
    private int column(int h1, int h2, int row) {
        return ((h1 + row * h2) & 0x7FFFFFFF) % width;
    }

    private static int mix(int value, int seed) {
        int h = value ^ seed;
        h ^= h >>> 16;
        h *= 0x85ebca6b;
        h ^= h >>> 13;
        h *= 0xc2b2ae35;
        h ^= h >>> 16;
        return h;
    }
}
