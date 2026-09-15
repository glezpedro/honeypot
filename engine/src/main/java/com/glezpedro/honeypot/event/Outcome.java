package com.glezpedro.honeypot.event;

public enum Outcome {
    SUCCESS,
    FAILURE,
    UNKNOWN;

    private static final Outcome[] VALUES = values();

    public static Outcome of(byte code) {
        return VALUES[code];
    }
}
