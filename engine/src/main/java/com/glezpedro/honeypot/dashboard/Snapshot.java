package com.glezpedro.honeypot.dashboard;

import java.util.List;

public record Snapshot(boolean running,
                       String origin,
                       int timeScale,
                       long events,
                       long eventsPerSecond,
                       long windows,
                       Detection bruteForce,
                       Detection enumeration,
                       Ranking ranking,
                       List<Feed> feed,
                       List<Memory> history) {

    public record Detection(long exactBytes, long sketchBytes,
                            long exactAlerts, long sketchAlerts,
                            long matched, long extra, long missed) {
    }

    public record Ranking(long exactBytes, long sketchBytes, int exactKeys, int sketchKeys,
                          List<Ranked> exact, List<Ranked> sketch) {
    }

    public record Ranked(String source, long count) {
    }

    public record Feed(String type, String source, String seen) {
    }

    public record Memory(long bruteExact, long bruteSketch,
                         long enumExact, long enumSketch,
                         long rankExact, long rankSketch) {
    }
}
