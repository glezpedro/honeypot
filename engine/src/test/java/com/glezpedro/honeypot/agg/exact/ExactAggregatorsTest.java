package com.glezpedro.honeypot.agg.exact;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ExactAggregatorsTest {

    @Test
    void elContadorAcumulaPorClave() {
        ExactCounter counter = new ExactCounter();

        counter.add(7, 1);
        counter.add(7, 4);
        counter.add(9, 2);

        assertEquals(5, counter.estimate(7));
        assertEquals(2, counter.estimate(9));
        assertEquals(0, counter.estimate(99));
    }

    @Test
    void elContadorSeVaciaAlReiniciar() {
        ExactCounter counter = new ExactCounter();
        counter.add(7, 5);

        counter.reset();

        assertEquals(0, counter.estimate(7));
    }

    @Test
    void laCardinalidadNoCuentaRepetidos() {
        ExactCardinality cardinality = new ExactCardinality();

        cardinality.add(1, 100);
        cardinality.add(1, 100);
        cardinality.add(1, 200);
        cardinality.add(2, 100);

        assertEquals(2, cardinality.estimate(1));
        assertEquals(1, cardinality.estimate(2));
        assertEquals(0, cardinality.estimate(3));
    }

    @Test
    void laCardinalidadEnumeraSusClaves() {
        ExactCardinality cardinality = new ExactCardinality();
        cardinality.add(5, 1);
        cardinality.add(8, 1);

        int[] keys = cardinality.keys();

        java.util.Arrays.sort(keys);
        assertArrayEquals(new int[] {5, 8}, keys);
    }

    @Test
    void elTopKDevuelveLasClavesMasFrecuentesEnOrden() {
        ExactTopK topK = new ExactTopK();
        for (int i = 0; i < 10; i++) {
            topK.add(1);
        }
        for (int i = 0; i < 5; i++) {
            topK.add(2);
        }
        topK.add(3);

        assertArrayEquals(new int[] {1, 2}, topK.top(2));
        assertArrayEquals(new int[] {1, 2, 3}, topK.top(5));
    }

    @Test
    void elTopKDeUnAgregadorVacioNoFalla() {
        assertEquals(0, new ExactTopK().top(10).length);
    }

    @Test
    void laMemoriaCreceConElNumeroDeClaves() {
        ExactCounter small = new ExactCounter();
        ExactCounter large = new ExactCounter();
        small.add(1, 1);
        for (int i = 0; i < 10_000; i++) {
            large.add(i, 1);
        }

        assertTrue(large.memoryBytes() > small.memoryBytes() * 100,
                "esperaba mucha mas memoria: " + large.memoryBytes() + " vs " + small.memoryBytes());
    }
}
