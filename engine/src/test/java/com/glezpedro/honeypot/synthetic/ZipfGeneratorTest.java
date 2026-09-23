package com.glezpedro.honeypot.synthetic;

import com.glezpedro.honeypot.event.EventStore;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ZipfGeneratorTest {

    @Test
    void laMismaSemillaProduceElMismoFlujo() {
        EventStore first = new ZipfGenerator(500, 50, 1.1, 42).generate(5_000, 0, 60_000);
        EventStore second = new ZipfGenerator(500, 50, 1.1, 42).generate(5_000, 0, 60_000);

        assertEquals(first.size(), second.size());
        for (int i = 0; i < first.size(); i++) {
            assertEquals(first.timestamp(i), second.timestamp(i));
            assertEquals(first.source(i), second.source(i));
            assertEquals(first.actor(i), second.actor(i));
        }
    }

    @Test
    void semillasDistintasProducenFlujosDistintos() {
        EventStore first = new ZipfGenerator(500, 50, 1.1, 1).generate(2_000, 0, 60_000);
        EventStore second = new ZipfGenerator(500, 50, 1.1, 2).generate(2_000, 0, 60_000);

        boolean different = false;
        for (int i = 0; i < first.size() && !different; i++) {
            different = first.source(i) != second.source(i);
        }
        assertTrue(different);
    }

    @Test
    void lasMarcasDeTiempoNoRetroceden() {
        EventStore events = new ZipfGenerator(100, 20, 1.0, 7).generate(10_000, 1_000, 600_000);

        for (int i = 1; i < events.size(); i++) {
            assertTrue(events.timestamp(i) >= events.timestamp(i - 1),
                    "retroceso en la posicion " + i);
        }
    }

    @Test
    void lasMarcasDeTiempoCubrenElIntervaloPedido() {
        EventStore events = new ZipfGenerator(100, 20, 1.0, 7).generate(1_000, 5_000, 60_000);

        assertEquals(5_000, events.timestamp(0));
        assertTrue(events.timestamp(events.size() - 1) < 5_000 + 60_000);
    }

    @Test
    void laDistribucionEsSesgada() {
        EventStore events = new ZipfGenerator(1_000, 50, 1.2, 3).generate(100_000, 0, 60_000);

        Map<Integer, Integer> counts = new HashMap<>();
        for (int i = 0; i < events.size(); i++) {
            counts.merge(events.source(i), 1, Integer::sum);
        }

        int mostActive = counts.values().stream().mapToInt(Integer::intValue).max().orElseThrow();
        double mean = events.size() / (double) counts.size();

        assertTrue(mostActive > mean * 20,
                "esperaba una cabeza dominante: max " + mostActive + ", media " + mean);
    }

    @Test
    void unSesgoNuloRepartePorIgual() {
        EventStore events = new ZipfGenerator(100, 10, 0.0, 5).generate(100_000, 0, 60_000);

        Map<Integer, Integer> counts = new HashMap<>();
        for (int i = 0; i < events.size(); i++) {
            counts.merge(events.source(i), 1, Integer::sum);
        }

        int mostActive = counts.values().stream().mapToInt(Integer::intValue).max().orElseThrow();
        double mean = events.size() / 100.0;

        assertTrue(mostActive < mean * 1.5, "sin sesgo no deberia haber cabeza: " + mostActive);
    }

    @Test
    void conSuficientesEventosAparecenCasiTodasLasClaves() {
        EventStore events = new ZipfGenerator(1_000, 50, 0.8, 11).generate(200_000, 0, 60_000);

        Set<Integer> distinct = new HashSet<>();
        for (int i = 0; i < events.size(); i++) {
            distinct.add(events.source(i));
        }

        assertTrue(distinct.size() > 900, "claves distintas: " + distinct.size());
    }

    @Test
    void rechazaParametrosImposibles() {
        assertThrows(IllegalArgumentException.class, () -> new ZipfGenerator(0, 10, 1.0, 1));
        assertThrows(IllegalArgumentException.class, () -> new ZipfGenerator(10, 0, 1.0, 1));
        assertThrows(IllegalArgumentException.class, () -> new ZipfGenerator(10, 10, -1.0, 1));
    }
}
