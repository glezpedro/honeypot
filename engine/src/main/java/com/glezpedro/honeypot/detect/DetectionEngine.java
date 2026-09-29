package com.glezpedro.honeypot.detect;

import com.glezpedro.honeypot.agg.CardinalityAggregator;
import com.glezpedro.honeypot.agg.CountAggregator;
import com.glezpedro.honeypot.agg.TopKAggregator;
import com.glezpedro.honeypot.event.Action;
import com.glezpedro.honeypot.event.Dictionary;
import com.glezpedro.honeypot.event.EventSink;
import com.glezpedro.honeypot.event.EventStore;
import it.unimi.dsi.fastutil.ints.IntOpenHashSet;

import java.util.function.Consumer;

public final class DetectionEngine implements EventSink {

    private final CountAggregator loginAttempts;
    private final CardinalityAggregator distinctUsers;
    private final TopKAggregator activity;
    private final DetectionThresholds thresholds;
    private final Consumer<Alert> alerts;

    private final IntOpenHashSet bruteForceAlerted = new IntOpenHashSet();
    private final IntOpenHashSet enumerationAlerted = new IntOpenHashSet();
    private long window = Long.MIN_VALUE;

    public DetectionEngine(CountAggregator loginAttempts,
                           CardinalityAggregator distinctUsers,
                           TopKAggregator activity,
                           DetectionThresholds thresholds,
                           Consumer<Alert> alerts) {
        this.loginAttempts = loginAttempts;
        this.distinctUsers = distinctUsers;
        this.activity = activity;
        this.thresholds = thresholds;
        this.alerts = alerts;
    }

    @Override
    public void accept(EventStore events, int index) {
        long eventWindow = events.timestamp(index) / thresholds.windowMillis();
        if (eventWindow != window) {
            flush();
            window = eventWindow;
        }

        int source = events.source(index);
        activity.add(source);

        if (events.action(index) != Action.LOGIN) {
            return;
        }

        loginAttempts.add(source, 1);
        if (loginAttempts.estimate(source) >= thresholds.bruteForce() && bruteForceAlerted.add(source)) {
            alerts.accept(new Alert(DetectionType.BRUTE_FORCE, source, window));
        }

        int actor = events.actor(index);
        if (actor == Dictionary.ABSENT) {
            return;
        }
        distinctUsers.add(source, actor);
        if (distinctUsers.estimate(source) >= thresholds.userEnumeration() && enumerationAlerted.add(source)) {
            alerts.accept(new Alert(DetectionType.USER_ENUMERATION, source, window));
        }
    }

    public void flush() {
        Ranking ranking = close();
        for (int attacker : ranking.keys()) {
            alerts.accept(new Alert(DetectionType.TOP_ATTACKERS, attacker, ranking.window()));
        }
    }

    // Cierra la ventana y devuelve el ranking en lugar de emitirlo: en ejecucion
    // particionada ese ranking es solo local y hay que fusionarlo con los demas.
    Ranking close() {
        if (window == Long.MIN_VALUE) {
            return Ranking.EMPTY;
        }
        int[] keys = activity.top(thresholds.topK());
        long[] counts = new long[keys.length];
        for (int i = 0; i < keys.length; i++) {
            counts[i] = activity.count(keys[i]);
        }
        Ranking ranking = new Ranking(window, keys, counts);
        loginAttempts.reset();
        distinctUsers.reset();
        activity.reset();
        bruteForceAlerted.clear();
        enumerationAlerted.clear();
        window = Long.MIN_VALUE;
        return ranking;
    }

    DetectionThresholds thresholds() {
        return thresholds;
    }

    public long memoryBytes() {
        return loginAttempts.memoryBytes() + distinctUsers.memoryBytes() + activity.memoryBytes();
    }

    record Ranking(long window, int[] keys, long[] counts) {

        static final Ranking EMPTY = new Ranking(Long.MIN_VALUE, new int[0], new long[0]);
    }
}
