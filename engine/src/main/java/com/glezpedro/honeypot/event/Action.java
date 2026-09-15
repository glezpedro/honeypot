package com.glezpedro.honeypot.event;

public enum Action {
    CONNECT,
    LOGIN,
    COMMAND,
    FILE_TRANSFER,
    DISCONNECT;

    private static final Action[] VALUES = values();

    public static Action of(byte code) {
        return VALUES[code];
    }
}
