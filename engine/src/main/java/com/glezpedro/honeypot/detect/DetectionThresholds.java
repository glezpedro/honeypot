package com.glezpedro.honeypot.detect;

public record DetectionThresholds(long windowMillis, long bruteForce, long userEnumeration, int topK) {

    // Fijados sobre la distribucion observada: en ventanas de 60 s, el 90 % de las
    // IPs no pasa de 12 intentos ni de 8 usuarios distintos.
    public static DetectionThresholds defaults() {
        return new DetectionThresholds(60_000, 10, 6, 20);
    }
}
