package com.glezpedro.honeypot.agg.sketch;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HyperLogLogTest {

    @Test
    void unaClaveNuncaVistaEstimaCero() {
        assertEquals(0, new HyperLogLog(10).estimate(1));
    }

    @Test
    void noCuentaLosValoresRepetidos() {
        HyperLogLog hll = new HyperLogLog(12);
        for (int i = 0; i < 1_000; i++) {
            hll.add(1, 42);
        }

        assertEquals(1, hll.estimate(1));
    }

    @Test
    void lasCardinalidadesPequenasSonPracticamenteExactas() {
        HyperLogLog hll = new HyperLogLog(12);
        for (int value = 0; value < 50; value++) {
            hll.add(1, value);
        }

        long estimate = hll.estimate(1);
        assertTrue(Math.abs(estimate - 50) <= 2, "estimacion " + estimate + " para 50 valores");
    }

    @Test
    void elErrorMedioSeAjustaALaCotaTeorica() {
        int precision = 12;
        double theoretical = 1.04 / Math.sqrt(1 << precision);

        double worst = 0;
        for (int cardinality : new int[] {1_000, 10_000, 100_000, 500_000}) {
            HyperLogLog hll = new HyperLogLog(precision);
            for (int value = 0; value < cardinality; value++) {
                hll.add(1, value);
            }
            double error = Math.abs(hll.estimate(1) - cardinality) / (double) cardinality;
            worst = Math.max(worst, error);
        }

        assertTrue(worst < theoretical * 4,
                "error peor " + worst + " frente a la cota " + theoretical);
    }

    @Test
    void masPrecisionReduceElError() {
        int cardinality = 200_000;
        double coarse = relativeError(new HyperLogLog(6), cardinality);
        double fine = relativeError(new HyperLogLog(14), cardinality);

        assertTrue(fine < coarse, "fina " + fine + " deberia mejorar a gruesa " + coarse);
    }

    @Test
    void cadaClaveMantieneSuPropioEstimador() {
        HyperLogLog hll = new HyperLogLog(10);
        for (int value = 0; value < 1_000; value++) {
            hll.add(1, value);
        }
        hll.add(2, 7);

        assertTrue(hll.estimate(1) > 800);
        assertEquals(1, hll.estimate(2));
    }

    @Test
    void enumeraSusClaves() {
        HyperLogLog hll = new HyperLogLog(8);
        hll.add(3, 1);
        hll.add(9, 1);

        int[] keys = hll.keys();

        java.util.Arrays.sort(keys);
        assertEquals(2, keys.length);
        assertEquals(3, keys[0]);
        assertEquals(9, keys[1]);
    }

    @Test
    void laMemoriaCreceConElNumeroDeClavesNoConLosValores() {
        HyperLogLog pocasClaves = new HyperLogLog(10);
        for (int value = 0; value < 100_000; value++) {
            pocasClaves.add(1, value);
        }

        HyperLogLog muchasClaves = new HyperLogLog(10);
        for (int key = 0; key < 100; key++) {
            muchasClaves.add(key, 1);
        }

        assertTrue(muchasClaves.memoryBytes() > pocasClaves.memoryBytes() * 50,
                "muchas " + muchasClaves.memoryBytes() + " vs pocas " + pocasClaves.memoryBytes());
    }

    @Test
    void reiniciarDejaLaEstructuraVacia() {
        HyperLogLog hll = new HyperLogLog(10);
        hll.add(1, 1);

        hll.reset();

        assertEquals(0, hll.estimate(1));
        assertEquals(0, hll.keys().length);
    }

    @Test
    void laFabricaPorErrorEligeUnaPrecisionCoherente() {
        assertTrue(relativeError(HyperLogLog.withError(0.02), 100_000) < 0.08);
    }

    @Test
    void rechazaPrecisionesFueraDeRango() {
        assertThrows(IllegalArgumentException.class, () -> new HyperLogLog(3));
        assertThrows(IllegalArgumentException.class, () -> new HyperLogLog(17));
        assertThrows(IllegalArgumentException.class, () -> HyperLogLog.withError(0));
        assertThrows(IllegalArgumentException.class, () -> HyperLogLog.withError(1));
    }

    private static double relativeError(HyperLogLog hll, int cardinality) {
        for (int value = 0; value < cardinality; value++) {
            hll.add(1, value);
        }
        return Math.abs(hll.estimate(1) - cardinality) / (double) cardinality;
    }
}
