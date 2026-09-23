package com.glezpedro.honeypot.dashboard;

import com.glezpedro.honeypot.event.Dictionary;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;
import java.util.function.IntFunction;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SourceLabelsTest {

    @Test
    void ocultaElUltimoOcteto() {
        assertEquals("45.148.10.x", SourceLabels.mask("45.148.10.201"));
    }

    @Test
    void recortaLasDireccionesLargas() {
        assertEquals("2001:db8:1::x", SourceLabels.mask("2001:db8:1:2:3:4:5:6"));
    }

    @Test
    void sobreviveAUnaDireccionAusente() {
        assertEquals("desconocido", SourceLabels.mask(null));
        assertEquals("desconocido", SourceLabels.mask("  "));
    }

    @Test
    void traduceLosIdentificadoresDelDiccionario() {
        Dictionary sources = new Dictionary();
        int id = sources.intern("203.0.113.44");

        assertEquals("203.0.113.x", SourceLabels.masked(sources).apply(id));
    }

    @Test
    void lasSinteticasCaenEnElBloqueDePruebas() {
        IntFunction<String> labels = SourceLabels.synthetic();
        Set<String> seen = new HashSet<>();

        for (int id = 0; id < 5_000; id++) {
            String label = labels.apply(id);
            assertTrue(label.startsWith("198.18.") || label.startsWith("198.19."), label);
            seen.add(label);
        }

        assertEquals(5_000, seen.size());
    }
}
