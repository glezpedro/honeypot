package com.glezpedro.honeypot.event;

@FunctionalInterface
public interface EventSink {

    void accept(EventStore events, int index);
}
