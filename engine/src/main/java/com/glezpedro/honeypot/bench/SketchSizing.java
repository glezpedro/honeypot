package com.glezpedro.honeypot.bench;

import com.glezpedro.honeypot.agg.CountAggregator;
import com.glezpedro.honeypot.agg.exact.ExactCardinality;
import com.glezpedro.honeypot.agg.exact.ExactCounter;
import com.glezpedro.honeypot.agg.exact.ExactTopK;
import com.glezpedro.honeypot.agg.sketch.CountMinSketch;
import com.glezpedro.honeypot.detect.Alert;
import com.glezpedro.honeypot.detect.DetectionEngine;
import com.glezpedro.honeypot.detect.DetectionThresholds;
import com.glezpedro.honeypot.detect.DetectionType;
import com.glezpedro.honeypot.event.EventSink;
import com.glezpedro.honeypot.event.EventStore;
import com.glezpedro.honeypot.replay.Replayer;
import com.glezpedro.honeypot.synthetic.ZipfGenerator;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Supplier;

public final class SketchSizing {

    private static final int[] CARDINALITIES = {1_000, 2_000, 5_000, 10_000, 20_000, 50_000, 100_000};
    private static final int DEPTH = 4;
    private static final int EVENTS_PER_KEY = 12;
    private static final double SKEW = 0.8;
    private static final long SEED = 42;

    private record Run(Set<Alert> alerts, long peakBytes) { }

    public static void main(String[] args) throws IOException {
        double target = args.length > 0 ? Double.parseDouble(args[0]) : 0.05;
        Path csv = Path.of(args.length > 1 ? args[1] : "results/sketch-sizing.csv");
        Files.createDirectories(csv.getParent());

        System.out.printf("objetivo: falsas alarmas <= %.0f%%  ·  profundidad %d  ·  sesgo %.1f%n%n",
                target * 100, DEPTH, SKEW);
        System.out.printf("%9s %11s %11s %9s %9s %9s%n",
                "claves", "exacto B", "sketch B", "ancho", "memoria", "falsas");
        System.out.println("-".repeat(64));

        try (PrintWriter out = new PrintWriter(Files.newBufferedWriter(csv))) {
            out.println("claves,eventos,exacto_bytes,sketch_bytes,ancho,profundidad,ratio_memoria,falsas_pct");
            for (int keys : CARDINALITIES) {
                int events = keys * EVENTS_PER_KEY;
                EventStore stream = new ZipfGenerator(keys, 200, SKEW, SEED).generate(events, 0, 50_000);
                Run exact = run(stream, ExactCounter::new);

                int width = 64;
                Run sketch = null;
                double rate = 1;
                while (width <= (1 << 22)) {
                    final int w = width;
                    sketch = run(stream, () -> new CountMinSketch(w, DEPTH, SEED));
                    rate = falseRate(exact.alerts(), sketch.alerts());
                    if (rate <= target) {
                        break;
                    }
                    width <<= 1;
                }

                double ratio = sketch.peakBytes() / (double) exact.peakBytes();
                System.out.printf("%,9d %,11d %,11d %,9d %8.2fx %8.2f%%%n",
                        keys, exact.peakBytes(), sketch.peakBytes(), width, ratio, rate * 100);
                out.printf("%d,%d,%d,%d,%d,%d,%.4f,%.4f%n",
                        keys, events, exact.peakBytes(), sketch.peakBytes(),
                        width, DEPTH, ratio, rate * 100);
            }
        }
        System.out.println("\nescrito " + csv.toAbsolutePath());
    }

    private static double falseRate(Set<Alert> exact, Set<Alert> sketch) {
        Set<Alert> lost = new HashSet<>(exact);
        lost.removeAll(sketch);
        if (!lost.isEmpty()) {
            throw new AssertionError("Count-Min Sketch ha perdido " + lost.size() + " alertas");
        }
        Set<Alert> extra = new HashSet<>(sketch);
        extra.removeAll(exact);
        return exact.isEmpty() ? 0 : extra.size() / (double) exact.size();
    }

    private static Run run(EventStore stream, Supplier<CountAggregator> counters) {
        Set<Alert> alerts = new HashSet<>();
        CountAggregator counter = counters.get();
        DetectionEngine engine = new DetectionEngine(counter, new ExactCardinality(), new ExactTopK(),
                DetectionThresholds.defaults(),
                alert -> {
                    if (alert.type() == DetectionType.BRUTE_FORCE) {
                        alerts.add(alert);
                    }
                });
        long[] peak = {0};
        EventSink sampled = (store, index) -> {
            engine.accept(store, index);
            if ((index & 1023) == 0) {
                peak[0] = Math.max(peak[0], counter.memoryBytes());
            }
        };
        new Replayer(stream).replay(sampled);
        engine.flush();
        return new Run(alerts, peak[0]);
    }

    private SketchSizing() {
    }
}
