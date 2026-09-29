package com.glezpedro.honeypot.bench;

import com.glezpedro.honeypot.agg.exact.ExactCardinality;
import com.glezpedro.honeypot.agg.exact.ExactCounter;
import com.glezpedro.honeypot.agg.exact.ExactTopK;
import com.glezpedro.honeypot.detect.Alert;
import com.glezpedro.honeypot.detect.DetectionEngine;
import com.glezpedro.honeypot.detect.DetectionThresholds;
import com.glezpedro.honeypot.detect.PartitionedEngine;
import com.glezpedro.honeypot.event.EventStore;
import com.glezpedro.honeypot.replay.Replayer;
import com.glezpedro.honeypot.synthetic.ZipfGenerator;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.concurrent.atomic.LongAdder;

public final class ScalingBench {

    private static final int[] THREADS = {1, 2, 4, 8, 16};
    private static final int KEYS = 50_000;
    private static final int EVENTS = 2_000_000;
    private static final double SKEW = 0.8;
    private static final int WARMUP = 2;
    private static final int RUNS = 5;

    public static void main(String[] args) throws IOException {
        Path csv = Path.of(args.length > 0 ? args[0] : "results/scaling.csv");
        Files.createDirectories(csv.getParent());

        EventStore stream = new ZipfGenerator(KEYS, 200, SKEW, 42).generate(EVENTS, 0, 600_000);
        System.out.printf("%,d eventos  ·  %,d claves  ·  sesgo %.1f  ·  %d nucleos logicos%n%n",
                EVENTS, KEYS, SKEW, Runtime.getRuntime().availableProcessors());
        System.out.printf("%8s %14s %10s %10s %12s%n",
                "hilos", "eventos/s", "acelera", "ideal", "reparto max");
        System.out.println("-".repeat(58));

        double base = 0;
        try (PrintWriter out = new PrintWriter(Files.newBufferedWriter(csv))) {
            out.println("hilos,eventos,eventos_por_segundo,aceleracion,reparto_max_pct");
            for (int threads : THREADS) {
                for (int i = 0; i < WARMUP; i++) {
                    measure(stream, threads);
                }
                long best = Long.MAX_VALUE;
                double skewShare = 0;
                for (int i = 0; i < RUNS; i++) {
                    Result r = measure(stream, threads);
                    if (r.nanos() < best) {
                        best = r.nanos();
                        skewShare = r.maxShare();
                    }
                }
                double rate = EVENTS / (best / 1e9);
                if (threads == 1) {
                    base = rate;
                }
                System.out.printf("%8d %,14.0f %9.2fx %9dx %11.1f%%%n",
                        threads, rate, rate / base, threads, skewShare * 100);
                out.printf("%d,%d,%.0f,%.4f,%.2f%n", threads, EVENTS, rate, rate / base, skewShare * 100);
            }
        }
        System.out.println("\nescrito " + csv.toAbsolutePath());
    }

    private record Result(long nanos, double maxShare) { }

    private static Result measure(EventStore stream, int threads) {
        LongAdder alerts = new LongAdder();
        long start;
        long elapsed;
        double maxShare;
        if (threads == 1) {
            DetectionEngine engine = engine(alerts);
            start = System.nanoTime();
            new Replayer(stream).replay(engine);
            engine.flush();
            elapsed = System.nanoTime() - start;
            maxShare = 1;
        } else {
            PartitionedEngine partitioned =
                    new PartitionedEngine(threads, () -> engine(alerts), alert -> alerts.increment());
            start = System.nanoTime();
            new Replayer(stream).replay(partitioned);
            partitioned.close();
            elapsed = System.nanoTime() - start;
            long[] perPartition = partitioned.eventsPerPartition();
            maxShare = Arrays.stream(perPartition).max().orElse(0) / (double) stream.size();
        }
        if (alerts.sum() == 0) {
            throw new AssertionError("sin alertas: el motor no ha hecho trabajo");
        }
        return new Result(elapsed, maxShare);
    }

    private static DetectionEngine engine(LongAdder alerts) {
        return new DetectionEngine(new ExactCounter(), new ExactCardinality(), new ExactTopK(),
                DetectionThresholds.defaults(), (Alert alert) -> alerts.increment());
    }

    private ScalingBench() {
    }
}
