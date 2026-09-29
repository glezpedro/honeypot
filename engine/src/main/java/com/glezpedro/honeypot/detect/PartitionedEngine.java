package com.glezpedro.honeypot.detect;

import com.glezpedro.honeypot.event.EventSink;
import com.glezpedro.honeypot.event.EventStore;
import it.unimi.dsi.fastutil.ints.IntArrays;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.function.Consumer;
import java.util.function.Supplier;

// Las detecciones por umbral son identicas a la ejecucion de un solo hilo porque cada
// IP vive en una sola particion. El ranking necesita un paso mas: cada particion
// entrega su top-K local al cerrar la ventana y la fusion se queda con el global.
public final class PartitionedEngine implements EventSink, AutoCloseable {

    private static final int BATCH = 1024;

    private final Worker[] workers;
    private final int mask;
    private final long windowMillis;
    private long window = Long.MIN_VALUE;
    private boolean closed;

    public PartitionedEngine(int partitions, Supplier<DetectionEngine> engines, Consumer<Alert> ranking) {
        if (partitions <= 0 || Integer.bitCount(partitions) != 1) {
            throw new IllegalArgumentException("partitions debe ser una potencia de dos");
        }
        DetectionEngine[] built = new DetectionEngine[partitions];
        for (int i = 0; i < partitions; i++) {
            built[i] = engines.get();
            if (!built[i].thresholds().equals(built[0].thresholds())) {
                throw new IllegalArgumentException("todas las particiones deben usar los mismos umbrales");
            }
        }
        DetectionThresholds thresholds = built[0].thresholds();
        Merger merger = new Merger(partitions, thresholds.topK(), ranking);
        this.windowMillis = thresholds.windowMillis();
        this.mask = partitions - 1;
        this.workers = new Worker[partitions];
        for (int i = 0; i < partitions; i++) {
            workers[i] = new Worker(i, built[i], merger);
        }
    }

    // Solo el productor ve todos los eventos, asi que es el unico que sabe cuando
    // cambia la ventana. Avisa a todas las particiones antes de pasar el primer evento
    // de la siguiente: con colas FIFO, ninguna la empieza sin haber cerrado la anterior.
    @Override
    public void accept(EventStore events, int index) {
        long eventWindow = events.timestamp(index) / windowMillis;
        if (eventWindow != window) {
            closeWindow();
            window = eventWindow;
        }
        workers[mix(events.source(index)) & mask].offer(events, index);
    }

    private void closeWindow() {
        if (window == Long.MIN_VALUE) {
            return;
        }
        for (Worker worker : workers) {
            worker.close(window);
        }
    }

    @Override
    public void close() {
        if (closed) {
            return;
        }
        closed = true;
        closeWindow();
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

    // Una clave del top global vive en una sola particion y alli esta al menos igual
    // de arriba, asi que la union de los top-K locales siempre la contiene. Fusionar
    // es quedarse con los K mayores de, como mucho, particiones por K candidatos.
    private static final class Merger {

        private final int partitions;
        private final int k;
        private final Consumer<Alert> alerts;
        private final Map<Long, List<DetectionEngine.Ranking>> pending = new HashMap<>();

        Merger(int partitions, int k, Consumer<Alert> alerts) {
            this.partitions = partitions;
            this.k = k;
            this.alerts = alerts;
        }

        // Emite dentro del cerrojo para que las ventanas salgan en orden: cada particion
        // entrega la ventana N antes que la N+1, asi que la N siempre se completa antes.
        synchronized void add(long window, DetectionEngine.Ranking ranking) {
            List<DetectionEngine.Ranking> parts =
                    pending.computeIfAbsent(window, w -> new ArrayList<>(partitions));
            parts.add(ranking);
            if (parts.size() < partitions) {
                return;
            }
            pending.remove(window);
            emit(window, parts);
        }

        private void emit(long window, List<DetectionEngine.Ranking> parts) {
            int total = 0;
            for (DetectionEngine.Ranking part : parts) {
                total += part.keys().length;
            }
            int[] keys = new int[total];
            long[] counts = new long[total];
            int filled = 0;
            for (DetectionEngine.Ranking part : parts) {
                System.arraycopy(part.keys(), 0, keys, filled, part.keys().length);
                System.arraycopy(part.counts(), 0, counts, filled, part.counts().length);
                filled += part.keys().length;
            }
            int[] order = new int[total];
            for (int i = 0; i < total; i++) {
                order[i] = i;
            }
            IntArrays.quickSort(order, (a, b) -> Long.compare(counts[b], counts[a]));
            for (int i = 0; i < Math.min(k, total); i++) {
                alerts.accept(new Alert(DetectionType.TOP_ATTACKERS, keys[order[i]], window));
            }
        }
    }

    // Lo que viaja por la cola de una particion: un lote de eventos, el cierre de una
    // ventana o el final. La ventana va dentro del mensaje y no en un campo compartido
    // porque el productor puede ir ya por la siguiente cuando la particion lo lee.
    private record Task(int[] batch, long closing) {

        static final Task END = new Task(null, Long.MIN_VALUE);

        static Task events(int[] batch) {
            return new Task(batch, Long.MIN_VALUE);
        }

        static Task closing(long window) {
            return new Task(null, window);
        }
    }

    private static final class Worker {

        private final DetectionEngine engine;
        private final Merger merger;
        private final BlockingQueue<Task> queue = new ArrayBlockingQueue<>(64);
        private final Thread thread;
        private final int[] batch = new int[BATCH];
        private int filled;
        private long received;
        private EventStore store;

        Worker(int id, DetectionEngine engine, Merger merger) {
            this.engine = engine;
            this.merger = merger;
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
            put(Task.events(ready));
        }

        void close(long window) {
            flushBatch();
            put(Task.closing(window));
        }

        void finish() {
            flushBatch();
            put(Task.END);
        }

        void join() {
            try {
                thread.join();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        private void put(Task task) {
            try {
                queue.put(task);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("interrumpido al encolar", e);
            }
        }

        private void run() {
            try {
                while (true) {
                    Task task = queue.take();
                    if (task == Task.END) {
                        return;
                    }
                    if (task.batch() == null) {
                        merger.add(task.closing(), engine.close());
                        continue;
                    }
                    for (int index : task.batch()) {
                        engine.accept(store, index);
                    }
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }
}
