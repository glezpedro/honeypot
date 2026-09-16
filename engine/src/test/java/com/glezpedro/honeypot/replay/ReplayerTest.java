package com.glezpedro.honeypot.replay;

import com.glezpedro.honeypot.event.Action;
import com.glezpedro.honeypot.event.EventStore;
import com.glezpedro.honeypot.event.Outcome;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ReplayerTest {

    @Test
    void entregaTodosLosEventosEnOrden() {
        EventStore events = sample(5);
        List<Long> seen = new ArrayList<>();

        int count = new Replayer(events).replay((store, index) -> seen.add(store.timestamp(index)));

        assertEquals(5, count);
        assertEquals(List.of(0L, 1L, 2L, 3L, 4L), seen);
    }

    @Test
    void dosReproduccionesDelMismoOrigenSonIdenticas() {
        EventStore events = sample(100);
        Replayer replayer = new Replayer(events);

        List<String> first = collect(replayer);
        List<String> second = collect(replayer);

        assertEquals(first, second);
    }

    @Test
    void elModoConTasaRespetaElRitmoPedido() {
        EventStore events = sample(20);

        long start = System.nanoTime();
        new Replayer(events).replay((store, index) -> { }, 200);
        long elapsedMillis = (System.nanoTime() - start) / 1_000_000;

        assertTrue(elapsedMillis >= 90, "demasiado rapido: " + elapsedMillis + " ms");
    }

    private static List<String> collect(Replayer replayer) {
        List<String> seen = new ArrayList<>();
        replayer.replay((store, index) ->
                seen.add(store.timestamp(index) + ":" + store.source(index) + ":" + store.action(index)));
        return seen;
    }

    private static EventStore sample(int size) {
        EventStore events = new EventStore(4);
        for (int i = 0; i < size; i++) {
            events.add(i, i % 3, i % 2, Action.LOGIN, Outcome.FAILURE);
        }
        return events;
    }
}
