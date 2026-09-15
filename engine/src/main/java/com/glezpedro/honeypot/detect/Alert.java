package com.glezpedro.honeypot.detect;

public record Alert(DetectionType type, int key, long window) {
}
