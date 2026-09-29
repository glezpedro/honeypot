package com.glezpedro.honeypot.normalize;

import com.glezpedro.honeypot.event.Action;
import com.glezpedro.honeypot.event.Dictionary;
import com.glezpedro.honeypot.event.EventStore;
import com.glezpedro.honeypot.event.Outcome;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CowrieNormalizerTest {

    private static final String LOGIN_FAILED = """
            {"eventid":"cowrie.login.failed","src_ip":"198.51.100.3","username":"root",            "password":"x","epoch":1700000000000,"timestamp":"2023-11-14T22:13:20.000000Z"}""";

    private static final String LOGIN_SUCCESS = """
            {"eventid":"cowrie.login.success","src_ip":"198.51.100.3","username":"admin",            "password":"admin","epoch":1700000001000,"timestamp":"2023-11-14T22:13:21.000000Z"}""";

    private static final String KEX = """
            {"eventid":"cowrie.client.kex","src_ip":"198.51.100.3","epoch":1700000002000}""";

    @Test
    void traduceLosCamposDeCowrieAlEsquemaComun(@TempDir Path dir) throws IOException {
        Dictionary sources = new Dictionary();
        Dictionary actors = new Dictionary();
        Path file = write(dir, LOGIN_FAILED);

        EventStore events = new CowrieNormalizer(sources, actors).read(file);

        assertEquals(1, events.size());
        assertEquals(1700000000000L, events.timestamp(0));
        assertEquals("198.51.100.3", sources.value(events.source(0)));
        assertEquals("root", actors.value(events.actor(0)));
        assertEquals(Action.LOGIN, events.action(0));
        assertEquals(Outcome.FAILURE, events.outcome(0));
    }

    @Test
    void distingueExitoDeFalloEnElLogin(@TempDir Path dir) throws IOException {
        Path file = write(dir, LOGIN_FAILED, LOGIN_SUCCESS);

        EventStore events = new CowrieNormalizer(new Dictionary(), new Dictionary()).read(file);

        assertEquals(Outcome.FAILURE, events.outcome(0));
        assertEquals(Outcome.SUCCESS, events.outcome(1));
    }

    @Test
    void descartaLosEventosDeProtocoloQueNoAportan(@TempDir Path dir) throws IOException {
        Path file = write(dir, KEX, LOGIN_FAILED, KEX);

        EventStore events = new CowrieNormalizer(new Dictionary(), new Dictionary()).read(file);

        assertEquals(1, events.size());
    }

    @Test
    void laMismaIpRecibeUnSoloIdentificador(@TempDir Path dir) throws IOException {
        Dictionary sources = new Dictionary();
        Path file = write(dir, LOGIN_FAILED, LOGIN_SUCCESS);

        EventStore events = new CowrieNormalizer(sources, new Dictionary()).read(file);

        assertEquals(events.source(0), events.source(1));
        assertEquals(1, sources.size());
    }

    private static Path write(Path dir, String... lines) throws IOException {
        Path file = dir.resolve("cowrie.json");
        Files.write(file, java.util.List.of(lines));
        return file;
    }
}
