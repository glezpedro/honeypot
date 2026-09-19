package com.glezpedro.honeypot.detect;

import com.glezpedro.honeypot.agg.exact.ExactCardinality;
import com.glezpedro.honeypot.agg.exact.ExactCounter;
import com.glezpedro.honeypot.agg.exact.ExactTopK;
import com.glezpedro.honeypot.event.Action;
import com.glezpedro.honeypot.event.Dictionary;
import com.glezpedro.honeypot.event.EventStore;
import com.glezpedro.honeypot.event.Outcome;
import com.glezpedro.honeypot.replay.Replayer;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DetectionEngineTest {

    private static final DetectionThresholds THRESHOLDS = new DetectionThresholds(60_000, 5, 3, 2);

    private final List<Alert> alerts = new ArrayList<>();

    @Test
    void laFuerzaBrutaSaltaAlAlcanzarElUmbralYSoloUnaVez() {
        EventStore events = new EventStore();
        for (int i = 0; i < 20; i++) {
            events.add(1_000, 7, 100, Action.LOGIN, Outcome.FAILURE);
        }

        run(events);

        assertEquals(1, count(DetectionType.BRUTE_FORCE));
        assertEquals(7, first(DetectionType.BRUTE_FORCE).key());
    }

    @Test
    void losEventosQueNoSonLoginNoCuentanComoFuerzaBruta() {
        EventStore events = new EventStore();
        for (int i = 0; i < 20; i++) {
            events.add(1_000, 7, Dictionary.ABSENT, Action.COMMAND, Outcome.UNKNOWN);
        }

        run(events);

        assertEquals(0, count(DetectionType.BRUTE_FORCE));
    }

    @Test
    void laEnumeracionCuentaUsuariosDistintosNoIntentos() {
        EventStore repeated = new EventStore();
        for (int i = 0; i < 20; i++) {
            repeated.add(1_000, 7, 100, Action.LOGIN, Outcome.FAILURE);
        }
        run(repeated);
        assertEquals(0, count(DetectionType.USER_ENUMERATION));

        alerts.clear();
        EventStore varied = new EventStore();
        for (int user = 0; user < 20; user++) {
            varied.add(1_000, 7, user, Action.LOGIN, Outcome.FAILURE);
        }
        run(varied);
        assertEquals(1, count(DetectionType.USER_ENUMERATION));
    }

    @Test
    void cadaVentanaEmpiezaDeCero() {
        EventStore events = new EventStore();
        for (int i = 0; i < 20; i++) {
            events.add(1_000, 7, 100, Action.LOGIN, Outcome.FAILURE);
        }
        for (int i = 0; i < 20; i++) {
            events.add(90_000, 7, 100, Action.LOGIN, Outcome.FAILURE);
        }

        run(events);

        assertEquals(2, count(DetectionType.BRUTE_FORCE), "una alerta por ventana");
        assertEquals(2, alerts.stream()
                .filter(a -> a.type() == DetectionType.BRUTE_FORCE)
                .map(Alert::window)
                .distinct()
                .count());
    }

    @Test
    void elTopKSeEmiteAlCerrarLaVentana() {
        EventStore events = new EventStore();
        for (int i = 0; i < 10; i++) {
            events.add(1_000, 1, Dictionary.ABSENT, Action.CONNECT, Outcome.UNKNOWN);
        }
        for (int i = 0; i < 5; i++) {
            events.add(1_000, 2, Dictionary.ABSENT, Action.CONNECT, Outcome.UNKNOWN);
        }
        events.add(1_000, 3, Dictionary.ABSENT, Action.CONNECT, Outcome.UNKNOWN);

        run(events);

        List<Integer> top = alerts.stream()
                .filter(a -> a.type() == DetectionType.TOP_ATTACKERS)
                .map(Alert::key)
                .toList();
        assertEquals(List.of(1, 2), top, "topK=2, ordenado por actividad");
    }

    @Test
    void laMemoriaDeclaradaCreceConElTrafico() {
        DetectionEngine engine = engine();
        long empty = engine.memoryBytes();

        EventStore events = new EventStore();
        for (int source = 0; source < 5_000; source++) {
            events.add(1_000, source, source, Action.LOGIN, Outcome.FAILURE);
        }
        new Replayer(events).replay(engine);

        assertTrue(engine.memoryBytes() > empty * 10);
    }

    private void run(EventStore events) {
        DetectionEngine engine = engine();
        new Replayer(events).replay(engine);
        engine.flush();
    }

    private DetectionEngine engine() {
        return new DetectionEngine(new ExactCounter(), new ExactCardinality(), new ExactTopK(),
                THRESHOLDS, alerts::add);
    }

    private long count(DetectionType type) {
        return alerts.stream().filter(a -> a.type() == type).count();
    }

    private Alert first(DetectionType type) {
        return alerts.stream().filter(a -> a.type() == type).findFirst().orElseThrow();
    }
}
