package com.glezpedro.honeypot.detect;

import com.glezpedro.honeypot.event.EventSink;
import com.glezpedro.honeypot.event.EventStore;

import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.function.Supplier;

// Las detecciones por umbral son identicas a la ejecucion de un solo hilo. El
// ranking, no: cada particion emite el suyo, y la union es el conjunto de
// candidatos del que hay que extraer el top-K global con una fusion posterior.
public final class PartitionedEngine implements EventSink, AutoCloseable {

    private static final int BATCH = 1024;
    private static final int[] POISON = new int[0];

    private final Worker[] workers;
    private final int mask;

    public PartitionedEngine(int partitions, Supplier<DetectionEngine> engines) {
        if (partitions <= 0 || Integer.bitCount(partitions) != 1) {
            throw new IllegalArgumentException("partitions debe ser una potencia de dos");
        }
        this.mask = partitions - 1;
        this.workers = new Worker[partitions];
        for (int i = 0; i < partitions; i++) {
            workers[i] = new Worker(i, engines.get());
        }
    }

    @Override
    public void accept(EventStore events, int index) {
        workers[mix(events.source(index)) & mask].offer(events, index);
    }

    @Override
    public void close() {
        for (Worker worker : workers) {
            worker.finish();
        }
        for (Worker worker : workers) {
            worker.join();
        }
    }

    public long[] eventsPerPartition() {
        long[] counts = new long[workers.length];
        for (int i = 0; i < workers.length; i++) {
            counts[i] = workers[i].received;
        }
        return counts;
    }

    public long memoryBytes() {
        long total = 0;
        for (Worker worker : workers) {
            total += worker.engine.memoryBytes();
        }
        return total;
    }

    private static int mix(int value) {
        int h = value * 0x9E3779B9;
        h ^= h >>> 16;
        return h & 0x7FFFFFFF;
    }

    private static final class Worker {

        private final DetectionEngine engine;
        private final BlockingQueue<int[]> queue = new ArrayBlockingQueue<>(64);
        private final Thread thread;
        private int[] batch = new int[BATCH];
        private int filled;
        private long received;
        private EventStore store;

        Worker(int id, DetectionEngine engine) {
            this.engine = engine;
            this.thread = new Thread(this::run, "particion-" + id);
            this.thread.start();
        }

        // store lo escribe el productor y lo lee el consumidor sin volatile: el put
        // de la cola publica todo lo escrito antes, y siempre se asigna antes del put.
        void offer(EventStore events, int index) {
            store = events;
            batch[filled++] = index;
            received++;
            if (filled == BATCH) {
                flushBatch();
            }
        }

        private void flushBatch() {
            if (filled == 0) {
                return;
            }
            int[] ready = new int[filled];
            System.arraycopy(batch, 0, ready, 0, filled);
            filled = 0;
            put(ready);
        }

        void finish() {
            flushBatch();
            put(POISON);
        }

        void join() {
            try {
                thread.join();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        private void put(int[] value) {
            try {
                queue.put(value);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("interrumpido al encolar", e);
            }
        }

        private void run() {
            try {
                while (true) {
                    int[] indexes = queue.take();
                    if (indexes == POISON) {
                        engine.flush();
                        return;
                    }
                    for (int index : indexes) {
                        engine.accept(store, index);
                    }
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }
}
