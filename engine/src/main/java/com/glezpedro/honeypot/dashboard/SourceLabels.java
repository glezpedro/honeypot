package com.glezpedro.honeypot.dashboard;

import com.glezpedro.honeypot.event.Dictionary;

import java.util.function.IntFunction;

public final class SourceLabels {

    private SourceLabels() {
    }

    // Bloque 198.18.0.0/15, reservado por la RFC 2544 para bancos de pruebas:
    // no enruta a nadie, asi que ninguna direccion inventada cae sobre un tercero.
    public static IntFunction<String> synthetic() {
        return id -> "198." + (18 + ((id >>> 16) & 1)) + "." + ((id >>> 8) & 0xFF) + "." + ((id & 0xFF) + 1);
    }

    // El panel nunca muestra la direccion completa de un atacante real, asi que
    // cualquier captura de pantalla es publicable tal cual.
    public static IntFunction<String> masked(Dictionary sources) {
        return id -> mask(sources.value(id));
    }

    static String mask(String address) {
        if (address == null || address.isBlank()) {
            return "desconocido";
        }
        int colon = address.indexOf(':');
        if (colon >= 0) {
            int third = nth(address, 3);
            return third < 0 ? address : address.substring(0, third + 1) + ":x";
        }
        int dot = address.lastIndexOf('.');
        return dot < 0 ? address : address.substring(0, dot + 1) + "x";
    }

    private static int nth(String value, int count) {
        int found = 0;
        for (int i = 0; i < value.length(); i++) {
            if (value.charAt(i) == ':' && ++found == count) {
                return i;
            }
        }
        return -1;
    }
}
