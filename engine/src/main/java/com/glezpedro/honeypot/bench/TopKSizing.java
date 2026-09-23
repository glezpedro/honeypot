package com.glezpedro.honeypot.bench;

import com.glezpedro.honeypot.agg.TopKAggregator;
import com.glezpedro.honeypot.agg.exact.ExactTopK;
import com.glezpedro.honeypot.agg.sketch.SpaceSaving;
import com.glezpedro.honeypot.event.EventStore;
import com.glezpedro.honeypot.synthetic.ZipfGenerator;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public final class TopKSizing {

    private static final int[] CARDINALITIES = {1_000, 5_000, 20_000, 100_000, 500_000};
    private static final int TOP_K = 20;
    private static final int EVENTS_PER_KEY = 12;
    private static final double SKEW = 0.8;
    private static final long SEED = 42;

    public static void main(String[] args) throws IOException {
        int counters = args.length > 0 ? Integer.parseInt(args[0]) : 256;
        Path csv = Path.of(args.length > 1 ? args[1] : "results/topk-sizing.csv");
        Files.createDirectories(csv.getParent());

        System.out.printf("top-%d  ·  Space-Saving con %d contadores  ·  sesgo %.1f%n%n",
                TOP_K, counters, SKEW);
        System.out.printf("%9s %11s %11s %9s %10s%n",
                "claves", "exacto B", "sketch B", "memoria", "acierto");
        System.out.println("-".repeat(56));

        try (PrintWriter out = new PrintWriter(Files.newBufferedWriter(csv))) {
            out.println("claves,eventos,contadores,exacto_bytes,sketch_bytes,ratio_memoria,solapamiento_pct");
            for (int keys : CARDINALITIES) {
                int events = keys * EVENTS_PER_KEY;
                EventStore stream = new ZipfGenerator(keys, 200, SKEW, SEED).generate(events, 0, 50_000);

                ExactTopK exact = new ExactTopK();
                SpaceSaving sketch = new SpaceSaving(counters);
                feed(stream, exact);
                feed(stream, sketch);

                double overlap = overlap(exact.top(TOP_K), sketch.top(TOP_K));
                double ratio = sketch.memoryBytes() / (double) exact.memoryBytes();
                System.out.printf("%,9d %,11d %,11d %8.3fx %9.0f%%%n",
                        keys, exact.memoryBytes(), sketch.memoryBytes(), ratio, overlap * 100);
                out.printf("%d,%d,%d,%d,%d,%.5f,%.2f%n",
                        keys, events, counters, exact.memoryBytes(), sketch.memoryBytes(), ratio, overlap * 100);
            }
        }
        System.out.println("\nescrito " + csv.toAbsolutePath());
    }

    private static void feed(EventStore stream, TopKAggregator aggregator) {
        for (int i = 0; i < stream.size(); i++) {
            aggregator.add(stream.source(i));
        }
    }

    private static double overlap(int[] expected, int[] actual) {
        Set<Integer> reference = new HashSet<>();
        Arrays.stream(expected).forEach(reference::add);
        long hits = Arrays.stream(actual).filter(reference::contains).count();
        return expected.length == 0 ? 1 : hits / (double) expected.length;
    }

    private TopKSizing() {
    }
}
