package com.glezpedro.honeypot.dashboard;

import com.glezpedro.honeypot.agg.CardinalityAggregator;
import com.glezpedro.honeypot.agg.CountAggregator;
import com.glezpedro.honeypot.agg.TopKAggregator;
import com.glezpedro.honeypot.agg.exact.ExactCardinality;
import com.glezpedro.honeypot.agg.exact.ExactCounter;
import com.glezpedro.honeypot.agg.exact.ExactTopK;
import com.glezpedro.honeypot.agg.sketch.CountMinSketch;
import com.glezpedro.honeypot.agg.sketch.HyperLogLog;
import com.glezpedro.honeypot.agg.sketch.SpaceSaving;
import com.glezpedro.honeypot.detect.Alert;
import com.glezpedro.honeypot.detect.DetectionEngine;
import com.glezpedro.honeypot.detect.DetectionThresholds;
import com.glezpedro.honeypot.detect.DetectionType;
import com.glezpedro.honeypot.event.EventStore;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.LockSupport;
import java.util.function.IntFunction;

public final class LiveSession {

    private static final int EXACT = 0;
    private static final int SKETCH = 1;
    private static final int MATCHED = 0;
    private static final int EXTRA = 1;
    private static final int MISSED = 2;
    private static final int RANKING = 12;
    private static final int FEED_SIZE = 40;
    private static final int HISTORY_SIZE = 180;
    private static final long PUBLISH_NANOS = 120_000_000L;
    private static final long MAX_WAIT_NANOS = 250_000_000L;

    private final EventStore events;
    private final IntFunction<String> labels;
    private final String origin;
    private final long windowMillis;

    private final CountAggregator exactCount = new ExactCounter();
    private final CountAggregator sketchCount = new CountMinSketch(16_384, 4, 42);
    private final CardinalityAggregator exactDistinct = new ExactCardinality();
    private final CardinalityAggregator sketchDistinct = new HyperLogLog(8);
    private final TopKAggregator exactTop = new ExactTopK();
    private final TopKAggregator sketchTop = new SpaceSaving(4096);
    private final DetectionEngine exact;
    private final DetectionEngine sketch;

    private final Map<Alert, Row> open = new LinkedHashMap<>();
    private final Deque<Row> feed = new ArrayDeque<>();
    private final Deque<Snapshot.Memory> history = new ArrayDeque<>();
    private final long[][] totals = new long[2][2];
    private final long[][] verdicts = new long[2][3];

    private long processed;
    private long windows;
    private long currentWindow = Long.MIN_VALUE;

    private volatile boolean running = true;
    private volatile int timeScale = 10;
    private volatile boolean restart;
    private volatile Snapshot snapshot;

    public LiveSession(EventStore events, IntFunction<String> labels, String origin, DetectionThresholds thresholds) {
        if (events.size() == 0) {
            throw new IllegalArgumentException("el flujo esta vacio");
        }
        this.events = events;
        this.labels = labels;
        this.origin = origin;
        this.windowMillis = thresholds.windowMillis();
        this.exact = new DetectionEngine(exactCount, exactDistinct, exactTop,
                thresholds, alert -> record(alert, EXACT));
        this.sketch = new DetectionEngine(sketchCount, sketchDistinct, sketchTop,
                thresholds, alert -> record(alert, SKETCH));
        this.snapshot = build(0);
    }

    public Snapshot snapshot() {
        return snapshot;
    }

    public void running(boolean value) {
        running = value;
    }

    public void timeScale(int value) {
        if (value > 0) {
            timeScale = value;
        }
    }

    public void restart() {
        restart = true;
    }

    public void start() {
        Thread thread = new Thread(this::run, "live-session");
        thread.setDaemon(true);
        thread.start();
    }

    private void run() {
        int index = 0;
        int scale = timeScale;
        long baseWall = System.nanoTime();
        long baseEvent = events.timestamp(0);
        long lastPublish = baseWall;
        long lastProcessed = 0;

        while (true) {
            if (restart) {
                clear();
                index = 0;
                baseWall = System.nanoTime();
                baseEvent = events.timestamp(0);
                lastProcessed = 0;
                restart = false;
            }

            if (running) {
                consume(index);
                index++;
                if (index == events.size()) {
                    index = 0;
                }
            }

            long now = System.nanoTime();
            if (now - lastPublish >= PUBLISH_NANOS) {
                long rate = (processed - lastProcessed) * 1_000_000_000L / (now - lastPublish);
                publish(rate);
                lastPublish = now;
                lastProcessed = processed;
            }

            if (!running) {
                LockSupport.parkNanos(40_000_000L);
                baseWall = System.nanoTime();
                baseEvent = events.timestamp(index);
                continue;
            }

            if (scale != timeScale) {
                scale = timeScale;
                baseWall = now;
                baseEvent = events.timestamp(index);
            }

            // Reproducir en tiempo de evento, y no a eventos por segundo, conserva
            // las rafagas de la captura real, que son justo lo que hay que ver.
            long target = baseWall + (events.timestamp(index) - baseEvent) * 1_000_000L / scale;
            long wait = target - System.nanoTime();
            if (wait > MAX_WAIT_NANOS) {
                // Un silencio de horas no se mira: los huecos muertos se recortan.
                wait = MAX_WAIT_NANOS;
                baseWall = System.nanoTime() + wait;
                baseEvent = events.timestamp(index);
            }
            if (wait > 0) {
                LockSupport.parkNanos(wait);
            }
        }
    }

    private void consume(int index) {
        long window = events.timestamp(index) / windowMillis;
        if (window != currentWindow) {
            if (currentWindow != Long.MIN_VALUE) {
                closeWindow();
            }
            currentWindow = window;
        }
        // El sketch va primero: solo sobreestima, asi que nunca alerta mas tarde
        // que el exacto y su fila del feed ya existe cuando llega la pareja.
        sketch.accept(events, index);
        exact.accept(events, index);
        processed++;
    }

    private void closeWindow() {
        for (Row row : open.values()) {
            long[] verdict = verdicts[row.type.ordinal()];
            if (row.exact && row.sketch) {
                verdict[MATCHED]++;
            } else if (row.sketch) {
                verdict[EXTRA]++;
            } else {
                verdict[MISSED]++;
            }
        }
        open.clear();
        windows++;
    }

    private void record(Alert alert, int mode) {
        if (alert.type() == DetectionType.TOP_ATTACKERS) {
            return;
        }
        Row row = open.get(alert);
        if (row == null) {
            row = new Row(alert.type(), labels.apply(alert.key()));
            open.put(alert, row);
            feed.addFirst(row);
            while (feed.size() > FEED_SIZE) {
                feed.removeLast();
            }
        }
        if (mode == EXACT && !row.exact) {
            row.exact = true;
            totals[EXACT][alert.type().ordinal()]++;
        } else if (mode == SKETCH && !row.sketch) {
            row.sketch = true;
            totals[SKETCH][alert.type().ordinal()]++;
        }
    }

    private void clear() {
        exact.flush();
        sketch.flush();
        open.clear();
        feed.clear();
        history.clear();
        for (long[] row : totals) {
            java.util.Arrays.fill(row, 0);
        }
        for (long[] row : verdicts) {
            java.util.Arrays.fill(row, 0);
        }
        processed = 0;
        windows = 0;
        currentWindow = Long.MIN_VALUE;
    }

    private void publish(long rate) {
        history.addLast(new Snapshot.Memory(
                exactCount.memoryBytes(), sketchCount.memoryBytes(),
                exactDistinct.memoryBytes(), sketchDistinct.memoryBytes(),
                exactTop.memoryBytes(), sketchTop.memoryBytes()));
        while (history.size() > HISTORY_SIZE) {
            history.removeFirst();
        }
        snapshot = build(rate);
    }

    private Snapshot build(long rate) {
        return new Snapshot(running, origin, timeScale, processed, rate, windows,
                detection(exactCount.memoryBytes(), sketchCount.memoryBytes(), DetectionType.BRUTE_FORCE),
                detection(exactDistinct.memoryBytes(), sketchDistinct.memoryBytes(), DetectionType.USER_ENUMERATION),
                new Snapshot.Ranking(exactTop.memoryBytes(), sketchTop.memoryBytes(),
                        exactTop.size(), sketchTop.size(), ranked(exactTop), ranked(sketchTop)),
                feedView(),
                new ArrayList<>(history));
    }

    private Snapshot.Detection detection(long exactBytes, long sketchBytes, DetectionType type) {
        long[] verdict = verdicts[type.ordinal()];
        return new Snapshot.Detection(exactBytes, sketchBytes,
                totals[EXACT][type.ordinal()], totals[SKETCH][type.ordinal()],
                verdict[MATCHED], verdict[EXTRA], verdict[MISSED]);
    }

    private List<Snapshot.Ranked> ranked(TopKAggregator ranking) {
        int[] top = ranking.top(RANKING);
        List<Snapshot.Ranked> view = new ArrayList<>(top.length);
        for (int key : top) {
            view.add(new Snapshot.Ranked(labels.apply(key), ranking.count(key)));
        }
        return view;
    }

    private List<Snapshot.Feed> feedView() {
        List<Snapshot.Feed> view = new ArrayList<>(feed.size());
        for (Row row : feed) {
            view.add(new Snapshot.Feed(row.type.name(), row.source, row.seen()));
        }
        return view;
    }

    private static final class Row {

        private final DetectionType type;
        private final String source;
        private boolean exact;
        private boolean sketch;

        private Row(DetectionType type, String source) {
            this.type = type;
            this.source = source;
        }

        private String seen() {
            if (exact && sketch) {
                return "ambos";
            }
            return exact ? "solo exacto" : "solo sketch";
        }
    }
}
