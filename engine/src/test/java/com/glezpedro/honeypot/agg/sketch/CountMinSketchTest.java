package com.glezpedro.honeypot.agg.sketch;

import com.glezpedro.honeypot.agg.exact.ExactCounter;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CountMinSketchTest {

    @Test
    void nuncaDevuelveMenosQueElValorReal() {
        CountMinSketch sketch = new CountMinSketch(256, 4, 1);
        ExactCounter exact = new ExactCounter();
        Random random = new Random(7);

        for (int i = 0; i < 200_000; i++) {
            int key = random.nextInt(20_000);
            sketch.add(key, 1);
            exact.add(key, 1);
        }

        for (int key = 0; key < 20_000; key++) {
            assertTrue(sketch.estimate(key) >= exact.estimate(key),
                    "subestimacion en la clave " + key);
        }
    }

    @Test
    void sinColisionesElValorEsExacto() {
        CountMinSketch sketch = new CountMinSketch(4096, 5, 3);

        sketch.add(42, 7);

        assertEquals(7, sketch.estimate(42));
    }

    @Test
    void unaClaveNuncaVistaEstimaCeroOMas() {
        CountMinSketch sketch = new CountMinSketch(1024, 4, 3);
        sketch.add(1, 100);

        assertTrue(sketch.estimate(999) >= 0);
    }

    @Test
    void elErrorCaeDentroDeLaCotaTeorica() {
        double epsilon = 0.001;
        CountMinSketch sketch = CountMinSketch.withError(epsilon, 0.01, 5);
        Map<Integer, Long> exact = new HashMap<>();
        Random random = new Random(11);

        long total = 0;
        for (int i = 0; i < 500_000; i++) {
            int key = random.nextInt(50_000);
            sketch.add(key, 1);
            exact.merge(key, 1L, Long::sum);
            total++;
        }

        long allowed = (long) Math.ceil(epsilon * total);
        long excedidas = exact.entrySet().stream()
                .filter(e -> sketch.estimate(e.getKey()) - e.getValue() > allowed)
                .count();

        assertTrue(excedidas < exact.size() * 0.02,
                "claves fuera de cota: " + excedidas + " de " + exact.size());
    }

    @Test
    void masColumnasReducenElError() {
        long errorEstrecho = totalError(new CountMinSketch(128, 4, 9));
        long errorAncho = totalError(new CountMinSketch(8192, 4, 9));

        assertTrue(errorAncho < errorEstrecho,
                "ancho " + errorAncho + " deberia ser menor que estrecho " + errorEstrecho);
    }

    @Test
    void laMemoriaNoDependeDelNumeroDeClaves() {
        CountMinSketch sketch = new CountMinSketch(1024, 4, 1);
        long vacio = sketch.memoryBytes();

        for (int key = 0; key < 1_000_000; key++) {
            sketch.add(key, 1);
        }

        assertEquals(vacio, sketch.memoryBytes());
        assertEquals(1024L * 4 * Long.BYTES, vacio);
    }

    @Test
    void reiniciarDejaLaEstructuraVacia() {
        CountMinSketch sketch = new CountMinSketch(256, 3, 1);
        sketch.add(5, 50);

        sketch.reset();

        assertEquals(0, sketch.estimate(5));
    }

    @Test
    void laMismaSemillaProduceLasMismasEstimaciones() {
        CountMinSketch first = new CountMinSketch(64, 3, 123);
        CountMinSketch second = new CountMinSketch(64, 3, 123);
        for (int key = 0; key < 5_000; key++) {
            first.add(key, 1);
            second.add(key, 1);
        }

        for (int key = 0; key < 5_000; key++) {
            assertEquals(first.estimate(key), second.estimate(key));
        }
    }

    @Test
    void rechazaParametrosImposibles() {
        assertThrows(IllegalArgumentException.class, () -> new CountMinSketch(0, 4, 1));
        assertThrows(IllegalArgumentException.class, () -> new CountMinSketch(10, 0, 1));
        assertThrows(IllegalArgumentException.class, () -> CountMinSketch.withError(0, 0.01, 1));
        assertThrows(IllegalArgumentException.class, () -> CountMinSketch.withError(0.01, 1, 1));
    }

    private static long totalError(CountMinSketch sketch) {
        ExactCounter exact = new ExactCounter();
        Random random = new Random(21);
        for (int i = 0; i < 100_000; i++) {
            int key = random.nextInt(10_000);
            sketch.add(key, 1);
            exact.add(key, 1);
        }
        long error = 0;
        for (int key = 0; key < 10_000; key++) {
            error += sketch.estimate(key) - exact.estimate(key);
        }
        return error;
    }
}
