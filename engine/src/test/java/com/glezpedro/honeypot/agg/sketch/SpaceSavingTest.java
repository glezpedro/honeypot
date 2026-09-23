package com.glezpedro.honeypot.agg.sketch;

import com.glezpedro.honeypot.agg.exact.ExactTopK;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SpaceSavingTest {

    @Test
    void conMenosClavesQueContadoresEsExacto() {
        SpaceSaving summary = new SpaceSaving(10);
        for (int i = 0; i < 10; i++) {
            summary.add(1);
        }
        for (int i = 0; i < 5; i++) {
            summary.add(2);
        }
        summary.add(3);

        assertArrayEquals(new int[] {1, 2, 3}, summary.top(3));
        assertEquals(10, summary.estimate(1));
        assertEquals(0, summary.overestimate(1));
    }

    // La garantia de Space-Saving cubre las claves con frecuencia mayor que m/k:
    // 500.000 eventos entre 64 contadores dejan el umbral en 7.812, y cada clave
    // pesada recibe 25.000.
    @Test
    void encuentraLasClavesPorEncimaDeLaGarantia() {
        SpaceSaving summary = new SpaceSaving(64);
        ExactTopK exact = new ExactTopK();
        Random random = new Random(5);

        for (int i = 0; i < 500_000; i++) {
            int key = i % 4 == 0 ? random.nextInt(5) : 100 + random.nextInt(50_000);
            summary.add(key);
            exact.add(key);
        }

        int[] esperado = exact.top(5);
        int[] obtenido = summary.top(5);
        Arrays.sort(esperado);
        Arrays.sort(obtenido);
        assertArrayEquals(esperado, obtenido);
    }

    @Test
    void porDebajoDeLaGarantiaLaColaInflaLasCuentas() {
        SpaceSaving summary = new SpaceSaving(64);
        Random random = new Random(5);

        for (int i = 0; i < 500_000; i++) {
            summary.add(i % 20 == 0 ? random.nextInt(5) : 100 + random.nextInt(50_000));
        }

        long minimaMonitorizada = Arrays.stream(summary.top(64))
                .mapToLong(summary::estimate).min().orElseThrow();
        assertTrue(minimaMonitorizada > 500_000 / 64.0 * 0.5,
                "las cuentas heredadas deberian haber crecido: " + minimaMonitorizada);
    }

    @Test
    void nuncaSubestimaLaFrecuenciaDeUnaClaveMonitorizada() {
        SpaceSaving summary = new SpaceSaving(32);
        Map<Integer, Long> real = new HashMap<>();
        Random random = new Random(13);

        for (int i = 0; i < 200_000; i++) {
            int key = random.nextInt(100) < 70 ? random.nextInt(10) : random.nextInt(10_000);
            summary.add(key);
            real.merge(key, 1L, Long::sum);
        }

        for (int key : summary.top(32)) {
            long exacto = real.getOrDefault(key, 0L);
            assertTrue(summary.estimate(key) >= exacto,
                    "subestimacion en " + key + ": " + summary.estimate(key) + " < " + exacto);
        }
    }

    @Test
    void laCotaDeErrorEsLaCuentaHeredada() {
        SpaceSaving summary = new SpaceSaving(4);
        for (int key = 0; key < 100; key++) {
            summary.add(key);
        }

        for (int key : summary.top(4)) {
            assertTrue(summary.estimate(key) - summary.overestimate(key) >= 1);
        }
    }

    @Test
    void nuncaGuardaMasClavesQueSuCapacidad() {
        SpaceSaving summary = new SpaceSaving(16);
        for (int key = 0; key < 100_000; key++) {
            summary.add(key);
        }

        assertEquals(16, summary.top(1_000).length);
    }

    @Test
    void laMemoriaNoDependeDelNumeroDeClaves() {
        SpaceSaving summary = new SpaceSaving(128);
        long vacio = summary.memoryBytes();

        for (int key = 0; key < 1_000_000; key++) {
            summary.add(key);
        }

        assertEquals(vacio, summary.memoryBytes());
    }

    @Test
    void reiniciarDejaLaEstructuraVacia() {
        SpaceSaving summary = new SpaceSaving(8);
        summary.add(1);
        summary.add(1);

        summary.reset();

        assertEquals(0, summary.top(8).length);
        assertEquals(0, summary.estimate(1));
    }

    @Test
    void rechazaCapacidadesImposibles() {
        assertThrows(IllegalArgumentException.class, () -> new SpaceSaving(0));
        assertThrows(IllegalArgumentException.class, () -> new SpaceSaving(-1));
    }
}
