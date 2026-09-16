package com.glezpedro.honeypot.normalize;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.glezpedro.honeypot.event.Action;
import com.glezpedro.honeypot.event.Dictionary;
import com.glezpedro.honeypot.event.EventStore;
import com.glezpedro.honeypot.event.Outcome;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Map;

public final class CowrieNormalizer {

    private static final Map<String, Action> ACTIONS = Map.of(
            "cowrie.session.connect", Action.CONNECT,
            "cowrie.login.success", Action.LOGIN,
            "cowrie.login.failed", Action.LOGIN,
            "cowrie.command.input", Action.COMMAND,
            "cowrie.session.file_download", Action.FILE_TRANSFER,
            "cowrie.session.file_download.failed", Action.FILE_TRANSFER,
            "cowrie.session.file_upload", Action.FILE_TRANSFER,
            "cowrie.session.closed", Action.DISCONNECT);

    private final ObjectMapper mapper = new ObjectMapper();
    private final Dictionary sources;
    private final Dictionary actors;

    public CowrieNormalizer(Dictionary sources, Dictionary actors) {
        this.sources = sources;
        this.actors = actors;
    }

    public EventStore read(Path file) throws IOException {
        EventStore events = new EventStore();
        try (BufferedReader reader = Files.newBufferedReader(file)) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (!line.isBlank()) {
                    append(events, mapper.readTree(line));
                }
            }
        }
        return events;
    }

    private void append(EventStore events, JsonNode node) {
        String eventId = node.path("eventid").asText("");
        Action action = ACTIONS.get(eventId);
        if (action == null) {
            return;
        }
        events.add(
                timestampOf(node),
                sources.intern(node.path("src_ip").asText(null)),
                actors.intern(node.path("username").asText(null)),
                action,
                outcomeOf(eventId));
    }

    private static long timestampOf(JsonNode node) {
        JsonNode epoch = node.get("epoch");
        if (epoch != null && epoch.isNumber()) {
            return epoch.asLong();
        }
        return Instant.parse(node.path("timestamp").asText()).toEpochMilli();
    }

    private static Outcome outcomeOf(String eventId) {
        return switch (eventId) {
            case "cowrie.login.success" -> Outcome.SUCCESS;
            case "cowrie.login.failed", "cowrie.session.file_download.failed" -> Outcome.FAILURE;
            default -> Outcome.UNKNOWN;
        };
    }
}
