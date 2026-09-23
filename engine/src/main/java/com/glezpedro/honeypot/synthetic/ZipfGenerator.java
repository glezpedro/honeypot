package com.glezpedro.honeypot.synthetic;

import com.glezpedro.honeypot.event.Action;
import com.glezpedro.honeypot.event.EventStore;
import com.glezpedro.honeypot.event.Outcome;

import java.util.Arrays;
import java.util.Random;

public final class ZipfGenerator {

    private final double[] cumulative;
    private final int users;
    private final long seed;

    public ZipfGenerator(int sources, int users, double skew, long seed) {
        if (sources <= 0 || users <= 0) {
            throw new IllegalArgumentException("sources y users deben ser positivos");
        }
        if (skew < 0) {
            throw new IllegalArgumentException("skew no puede ser negativo");
        }
        this.users = users;
        this.seed = seed;
        this.cumulative = buildCumulative(sources, skew);
    }

    public EventStore generate(int events, long startMillis, long spanMillis) {
        Random random = new Random(seed);
        EventStore store = new EventStore(Math.max(events, 1));
        for (int i = 0; i < events; i++) {
            long timestamp = startMillis + (long) i * spanMillis / Math.max(events, 1);
            store.add(timestamp, sample(random), random.nextInt(users), Action.LOGIN, Outcome.FAILURE);
        }
        return store;
    }

    private int sample(Random random) {
        int index = Arrays.binarySearch(cumulative, random.nextDouble());
        int rank = index >= 0 ? index : -index - 1;
        return Math.min(rank, cumulative.length - 1);
    }

    private static double[] buildCumulative(int sources, double skew) {
        double[] weights = new double[sources];
        double total = 0;
        for (int i = 0; i < sources; i++) {
            weights[i] = 1.0 / Math.pow(i + 1, skew);
            total += weights[i];
        }
        double[] cumulative = new double[sources];
        double accumulated = 0;
        for (int i = 0; i < sources; i++) {
            accumulated += weights[i] / total;
            cumulative[i] = accumulated;
        }
        // El redondeo deja el ultimo ligeramente por debajo de 1 y sample() se saldria.
        cumulative[sources - 1] = 1.0;
        return cumulative;
    }
}
