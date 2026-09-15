package com.glezpedro.honeypot.event;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class DictionaryTest {

    @Test
    void elMismoValorDevuelveSiempreElMismoId() {
        Dictionary dictionary = new Dictionary();

        int first = dictionary.intern("10.0.0.1");
        int second = dictionary.intern("10.0.0.1");

        assertEquals(first, second);
        assertEquals(1, dictionary.size());
    }

    @Test
    void valoresDistintosRecibenIdsDistintos() {
        Dictionary dictionary = new Dictionary();

        assertNotEquals(dictionary.intern("10.0.0.1"), dictionary.intern("10.0.0.2"));
        assertEquals(2, dictionary.size());
    }

    @Test
    void elIdPermiteRecuperarElValorOriginal() {
        Dictionary dictionary = new Dictionary();

        int id = dictionary.intern("root");

        assertEquals("root", dictionary.value(id));
    }

    @Test
    void ausenteParaNuloOVacio() {
        Dictionary dictionary = new Dictionary();

        assertEquals(Dictionary.ABSENT, dictionary.intern(null));
        assertEquals(Dictionary.ABSENT, dictionary.intern(""));
        assertNull(dictionary.value(Dictionary.ABSENT));
        assertEquals(0, dictionary.size());
    }
}
