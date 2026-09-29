package com.glezpedro.honeypot.detect;

import com.glezpedro.honeypot.agg.exact.ExactCardinality;
import com.glezpedro.honeypot.agg.exact.ExactCounter;
import com.glezpedro.honeypot.agg.exact.ExactTopK;
import com.glezpedro.honeypot.event.EventStore;
import com.glezpedro.honeypot.replay.Replayer;
import com.glezpedro.honeypot.synthetic.ZipfGenerator;
import it.unimi.dsi.fastutil.ints.Int2LongOpenHashMap;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PartitionedEngineTest {

    private static final DetectionThresholds THRESHOLDS = DetectionThresholds.defaults();
    private static final EventStore STREAM =
            new ZipfGenerator(2_000, 100, 0.8, 9).generate(120_000, 0, 600_000);
    private static final Map<Long, Int2LongOpenHashMap> ACTIVITY = activity();

    @Test
    void lasDeteccionesPorUmbralSonIdenticasAUnSoloHilo() {
        Set<Alert> single = single();

        for (int partitions : new int[] {2, 4, 8, 16}) {
            Set<Alert> parallel = parallel(partitions);
            for (DetectionType type : new DetectionType[] {
                    DetectionType.BRUTE_FORCE, DetectionType.USER_ENUMERATION}) {
                assertEquals(of(single, type), of(parallel, type),
                        type + " diverge con " + partitions + " particiones");
            }
        }
    }

    // Los empates en el ultimo puesto se pueden deshacer distinto en cada ejecucion,
    // asi que se compara lo que no depende de eso: cuantos eventos tiene cada puesto.
    @Test
    void elRankingFusionadoEsElDeUnSoloHilo() {
        Map<Long, List<Long>> single = counts(of(single(), DetectionType.TOP_ATTACKERS));

        for (int partitions : new int[] {2, 4, 8, 16}) {
            assertEquals(single, counts(of(parallel(partitions), DetectionType.TOP_ATTACKERS)),
                    "el ranking diverge con " + partitions + " particiones");
        }
    }

    @Test
    void ningunaClaveFueraDelRankingSuperaAUnaDeDentro() {
        Set<Alert> ranking = of(parallel(8), DetectionType.TOP_ATTACKERS);

        for (Map.Entry<Long, Int2LongOpenHashMap> window : ACTIVITY.entrySet()) {
            Int2LongOpenHashMap activity = window.getValue();
            Set<Integer> inside = new HashSet<>();
            for (Alert alert : ranking) {
                if (alert.window() == window.getKey()) {
                    inside.add(alert.key());
                }
            }
            assertEquals(Math.min(THRESHOLDS.topK(), activity.size()), inside.size(),
                    "puestos en la ventana " + window.getKey());

            long floor = inside.stream().mapToLong(key -> activity.get(key.intValue())).min().orElseThrow();
            for (int key : activity.keySet()) {
                if (!inside.contains(key)) {
                    assertTrue(activity.get(key) <= floor,
                            "la clave " + key + " se ha quedado fuera con " + activity.get(key) + " eventos");
                }
            }
        }
    }

    @Test
    void repartirNoPierdeNingunEvento() {
        try (PartitionedEngine partitioned = new PartitionedEngine(8, () -> engine(a -> { }), a -> { })) {
            new Replayer(STREAM).replay(partitioned);
            partitioned.close();
            assertEquals(STREAM.size(), Arrays.stream(partitioned.eventsPerPartition()).sum());
        }
    }

    @Test
    void todasLasParticionesRecibenTrabajo() {
        try (PartitionedEngine partitioned = new PartitionedEngine(8, () -> engine(a -> { }), a -> { })) {
            new Replayer(STREAM).replay(partitioned);
            partitioned.close();
            for (long count : partitioned.eventsPerPartition()) {
                assertTrue(count > 0, "particion vacia: " + Arrays.toString(partitioned.eventsPerPartition()));
            }
        }
    }

    @Test
    void exigeQueElNumeroDeParticionesSeaPotenciaDeDos() {
        assertThrows(IllegalArgumentException.class,
                () -> new PartitionedEngine(3, () -> engine(a -> { }), a -> { }));
        assertThrows(IllegalArgumentException.class,
                () -> new PartitionedEngine(0, () -> engine(a -> { }), a -> { }));
    }

    @Test
    void exigeLosMismosUmbralesEnTodasLasParticiones() {
        int[] built = {0};
        assertThrows(IllegalArgumentException.class, () -> new PartitionedEngine(2, () -> {
            DetectionThresholds thresholds = built[0]++ == 0
                    ? THRESHOLDS
                    : new DetectionThresholds(THRESHOLDS.windowMillis(), 99, 99, THRESHOLDS.topK());
            return new DetectionEngine(new ExactCounter(), new ExactCardinality(), new ExactTopK(),
                    thresholds, a -> { });
        }, a -> { }));
    }

    private static Set<Alert> single() {
        Set<Alert> alerts = ConcurrentHashMap.newKeySet();
        DetectionEngine engine = engine(alerts::add);
        new Replayer(STREAM).replay(engine);
        engine.flush();
        return alerts;
    }

    private static Set<Alert> parallel(int partitions) {
        Set<Alert> alerts = ConcurrentHashMap.newKeySet();
        try (PartitionedEngine partitioned =
                     new PartitionedEngine(partitions, () -> engine(alerts::add), alerts::add)) {
            new Replayer(STREAM).replay(partitioned);
        }
        return alerts;
    }

    private static Set<Alert> of(Set<Alert> alerts, DetectionType type) {
        Set<Alert> filtered = new HashSet<>();
        for (Alert alert : alerts) {
            if (alert.type() == type) {
                filtered.add(alert);
            }
        }
        return filtered;
    }

    private static Map<Long, List<Long>> counts(Set<Alert> ranking) {
        Map<Long, List<Long>> counts = new HashMap<>();
        for (Alert alert : ranking) {
            counts.computeIfAbsent(alert.window(), w -> new ArrayList<>())
                    .add(ACTIVITY.get(alert.window()).get(alert.key()));
        }
        counts.values().forEach(list -> list.sort(Comparator.reverseOrder()));
        return counts;
    }

    private static Map<Long, Int2LongOpenHashMap> activity() {
        Map<Long, Int2LongOpenHashMap> activity = new HashMap<>();
        for (int i = 0; i < STREAM.size(); i++) {
            activity.computeIfAbsent(STREAM.timestamp(i) / THRESHOLDS.windowMillis(),
                    w -> new Int2LongOpenHashMap()).addTo(STREAM.source(i), 1);
        }
        return activity;
    }

    private static DetectionEngine engine(Consumer<Alert> alerts) {
        return new DetectionEngine(new ExactCounter(), new ExactCardinality(), new ExactTopK(),
                THRESHOLDS, alerts);
    }
}
