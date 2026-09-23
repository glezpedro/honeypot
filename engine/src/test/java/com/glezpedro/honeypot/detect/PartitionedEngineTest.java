package com.glezpedro.honeypot.detect;

import com.glezpedro.honeypot.agg.exact.ExactCardinality;
import com.glezpedro.honeypot.agg.exact.ExactCounter;
import com.glezpedro.honeypot.agg.exact.ExactTopK;
import com.glezpedro.honeypot.event.EventStore;
import com.glezpedro.honeypot.replay.Replayer;
import com.glezpedro.honeypot.synthetic.ZipfGenerator;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PartitionedEngineTest {

    private static final EventStore STREAM =
            new ZipfGenerator(2_000, 100, 0.8, 9).generate(120_000, 0, 600_000);

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

    // Un ranking global no particiona: cada particion emite su propio top-K. Pero una
    // clave del top global vive en una sola particion y alli esta al menos igual de
    // arriba, asi que la union de los top-K locales siempre los contiene.
    @Test
    void elTopKParticionadoContieneAlGlobal() {
        Set<Alert> global = of(single(), DetectionType.TOP_ATTACKERS);

        for (int partitions : new int[] {2, 4, 8, 16}) {
            Set<Alert> candidatos = of(parallel(partitions), DetectionType.TOP_ATTACKERS);
            assertTrue(candidatos.containsAll(global),
                    "faltan candidatos con " + partitions + " particiones");
            assertTrue(candidatos.size() >= global.size());
        }
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
        try (PartitionedEngine partitioned = new PartitionedEngine(partitions, () -> engine(alerts::add))) {
            new Replayer(STREAM).replay(partitioned);
        }
        return alerts;
    }

    private static Set<Alert> of(Set<Alert> alerts, DetectionType type) {
        Set<Alert> filtered = new java.util.HashSet<>();
        for (Alert alert : alerts) {
            if (alert.type() == type) {
                filtered.add(alert);
            }
        }
        return filtered;
    }

    @Test
    void repartirNoPierdeNingunEvento() {
        try (PartitionedEngine partitioned =
                     new PartitionedEngine(8, () -> engine(a -> { }))) {
            new Replayer(STREAM).replay(partitioned);
            partitioned.close();
            assertEquals(STREAM.size(), Arrays.stream(partitioned.eventsPerPartition()).sum());
        }
    }

    @Test
    void todasLasParticionesRecibenTrabajo() {
        try (PartitionedEngine partitioned =
                     new PartitionedEngine(8, () -> engine(a -> { }))) {
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
                () -> new PartitionedEngine(3, () -> engine(a -> { })));
        assertThrows(IllegalArgumentException.class,
                () -> new PartitionedEngine(0, () -> engine(a -> { })));
    }

    private static DetectionEngine engine(Consumer<Alert> alerts) {
        return new DetectionEngine(new ExactCounter(), new ExactCardinality(), new ExactTopK(),
                DetectionThresholds.defaults(), alerts);
    }
}
