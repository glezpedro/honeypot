package com.glezpedro.honeypot.dashboard;

import com.glezpedro.honeypot.detect.DetectionThresholds;
import com.glezpedro.honeypot.event.EventStore;
import com.glezpedro.honeypot.synthetic.ZipfGenerator;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.LockSupport;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LiveSessionTest {

    // Una escala altisima deja el ritmo por debajo de la resolucion del reloj, con
    // lo que la sesion corre a pleno rendimiento y la prueba no depende del reloj.
    private static final int FAST = 50_000;

    private static LiveSession started() {
        EventStore events = new ZipfGenerator(500, 40, 0.8, 7).generate(200_000, 0, 600_000);
        LiveSession session = new LiveSession(events, SourceLabels.synthetic(), "prueba",
                DetectionThresholds.defaults());
        session.timeScale(FAST);
        session.start();
        return session;
    }

    private static Snapshot afterWindows(LiveSession session, long windows) {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(20);
        while (System.nanoTime() < deadline) {
            Snapshot snapshot = session.snapshot();
            if (snapshot.windows() >= windows) {
                return snapshot;
            }
            LockSupport.parkNanos(20_000_000L);
        }
        throw new AssertionError("la sesion no llego a " + windows + " ventanas");
    }

    private static Snapshot afterSamples(LiveSession session, int samples) {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(20);
        while (System.nanoTime() < deadline) {
            Snapshot snapshot = session.snapshot();
            if (snapshot.history().size() >= samples) {
                return snapshot;
            }
            LockSupport.parkNanos(20_000_000L);
        }
        throw new AssertionError("la sesion no publico " + samples + " muestras");
    }

    @Test
    void elSketchNuncaPierdeUnaAlertaDeFuerzaBruta() {
        Snapshot snapshot = afterWindows(started(), 3);

        assertEquals(0, snapshot.bruteForce().missed());
        assertTrue(snapshot.bruteForce().matched() > 0, "no se comparo ninguna alerta");
        assertTrue(snapshot.bruteForce().sketchAlerts() >= snapshot.bruteForce().exactAlerts(),
                "Count-Min solo puede sobreestimar");
    }

    @Test
    void lasDosCabezasDelRankingCoinciden() {
        Snapshot.Ranking ranking = afterWindows(started(), 2).ranking();

        // Las dos listas traen las mismas claves con las mismas cuentas, pero los
        // empates no tienen por que quedar en el mismo orden dentro de cada una.
        assertEquals(sources(ranking.exact()), sources(ranking.sketch()));
        assertEquals(counts(ranking.exact()), counts(ranking.sketch()));
        assertTrue(ranking.sketchKeys() <= 4096, "contadores: " + ranking.sketchKeys());
    }

    @Test
    void elSketchDelRankingNoCambiaDeTamano() {
        Snapshot snapshot = afterSamples(started(), 5);

        long fijo = snapshot.history().get(0).rankSketch();
        for (Snapshot.Memory point : snapshot.history()) {
            assertEquals(fijo, point.rankSketch());
        }
    }

    private static Set<String> sources(List<Snapshot.Ranked> ranked) {
        return ranked.stream().map(Snapshot.Ranked::source).collect(java.util.stream.Collectors.toSet());
    }

    private static List<Long> counts(List<Snapshot.Ranked> ranked) {
        return ranked.stream().map(Snapshot.Ranked::count).toList();
    }

    @Test
    void laPausaDetieneElConsumo() {
        LiveSession session = started();
        afterWindows(session, 1);
        session.running(false);
        LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(300));

        long detenido = session.snapshot().events();
        LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(300));

        assertEquals(detenido, session.snapshot().events());
    }

    @Test
    void elReinicioVuelveACero() {
        LiveSession session = started();
        afterWindows(session, 1);
        session.running(false);
        session.restart();
        LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(500));

        Snapshot snapshot = session.snapshot();
        assertEquals(0, snapshot.events());
        assertEquals(0, snapshot.windows());
        assertTrue(snapshot.feed().isEmpty());
    }

    @Test
    void rechazaUnFlujoVacio() {
        assertThrows(IllegalArgumentException.class, () -> new LiveSession(new EventStore(),
                SourceLabels.synthetic(), "prueba", DetectionThresholds.defaults()));
    }
}
