package com.glezpedro.honeypot.dashboard;

import com.glezpedro.honeypot.detect.DetectionThresholds;
import com.glezpedro.honeypot.event.Dictionary;
import com.glezpedro.honeypot.event.EventStore;
import com.glezpedro.honeypot.normalize.CowrieNormalizer;
import com.glezpedro.honeypot.synthetic.ZipfGenerator;

import java.io.IOException;
import java.nio.file.Path;
import java.util.function.IntFunction;

public final class Dashboard {

    // 60 ventanas de 20.000 eventos: suficientes claves distintas por ventana para
    // que el mapa exacto adelante a Space-Saving delante de quien mira.
    private static final int SOURCES = 50_000;
    private static final int USERS = 200;
    private static final double SKEW = 0.8;
    private static final int EVENTS = 1_200_000;
    private static final long SPAN_MILLIS = 60 * 60_000L;

    public static void main(String[] args) throws IOException {
        int port = 8080;
        Path capture = null;
        for (int i = 0; i < args.length; i++) {
            if ("--port".equals(args[i]) && i + 1 < args.length) {
                port = Integer.parseInt(args[++i]);
            } else {
                capture = Path.of(args[i]);
            }
        }

        EventStore events;
        IntFunction<String> labels;
        String origin;
        if (capture == null) {
            events = new ZipfGenerator(SOURCES, USERS, SKEW, 42).generate(EVENTS, 0, SPAN_MILLIS);
            labels = SourceLabels.synthetic();
            origin = "tráfico sintético";
        } else {
            Dictionary sources = new Dictionary();
            events = new CowrieNormalizer(sources, new Dictionary()).read(capture);
            labels = SourceLabels.masked(sources);
            origin = "captura real";
        }

        LiveSession session = new LiveSession(events, labels, origin, DetectionThresholds.defaults());
        ApiServer server = new ApiServer(session, port);
        session.start();
        server.start();
        System.out.printf("%s  ·  %,d eventos  ·  http://localhost:%d%n", origin, events.size(), server.port());
    }
}
