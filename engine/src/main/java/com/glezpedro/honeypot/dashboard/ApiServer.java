package com.glezpedro.honeypot.dashboard;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.Executors;

public final class ApiServer {

    private static final Map<String, String> STATIC = Map.of(
            "/", "index.html",
            "/index.html", "index.html",
            "/panel.css", "panel.css",
            "/panel.js", "panel.js");

    private static final Map<String, String> TYPES = Map.of(
            "html", "text/html; charset=utf-8",
            "css", "text/css; charset=utf-8",
            "js", "text/javascript; charset=utf-8");

    private final ObjectMapper mapper = new ObjectMapper();
    private final LiveSession session;
    private final HttpServer server;

    public ApiServer(LiveSession session, int port) throws IOException {
        this.session = session;
        // Solo escucha en el bucle local: es un panel de demostracion, sin autenticacion.
        this.server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), port), 0);
        server.setExecutor(Executors.newFixedThreadPool(4));
        server.createContext("/api/state", this::state);
        server.createContext("/api/control", this::control);
        server.createContext("/", this::resource);
    }

    public int port() {
        return server.getAddress().getPort();
    }

    public void start() {
        server.start();
    }

    private void state(HttpExchange exchange) throws IOException {
        if (!"GET".equals(exchange.getRequestMethod())) {
            send(exchange, 405, "text/plain", "metodo no permitido".getBytes(StandardCharsets.UTF_8));
            return;
        }
        byte[] body = mapper.writeValueAsBytes(session.snapshot());
        exchange.getResponseHeaders().add("Cache-Control", "no-store");
        send(exchange, 200, "application/json; charset=utf-8", body);
    }

    private void control(HttpExchange exchange) throws IOException {
        if (!"POST".equals(exchange.getRequestMethod())) {
            send(exchange, 405, "text/plain", "metodo no permitido".getBytes(StandardCharsets.UTF_8));
            return;
        }
        JsonNode body;
        try (InputStream input = exchange.getRequestBody()) {
            body = mapper.readTree(input.readAllBytes());
        } catch (IOException invalid) {
            send(exchange, 400, "text/plain", "cuerpo ilegible".getBytes(StandardCharsets.UTF_8));
            return;
        }
        if (body != null && body.has("running")) {
            session.running(body.get("running").asBoolean());
        }
        if (body != null && body.has("timeScale")) {
            session.timeScale(body.get("timeScale").asInt());
        }
        if (body != null && body.path("restart").asBoolean()) {
            session.restart();
        }
        // Sin cuerpo: la instantanea publicada es la de antes del cambio y devolverla
        // haria que el panel pintase el estado que acaba de dejar de ser cierto.
        exchange.sendResponseHeaders(204, -1);
        exchange.close();
    }

    private void resource(HttpExchange exchange) throws IOException {
        String name = STATIC.get(exchange.getRequestURI().getPath());
        if (name == null) {
            send(exchange, 404, "text/plain", "no encontrado".getBytes(StandardCharsets.UTF_8));
            return;
        }
        try (InputStream input = ApiServer.class.getResourceAsStream("/dashboard/" + name)) {
            if (input == null) {
                send(exchange, 500, "text/plain", "recurso ausente".getBytes(StandardCharsets.UTF_8));
                return;
            }
            String extension = name.substring(name.lastIndexOf('.') + 1);
            send(exchange, 200, TYPES.get(extension), input.readAllBytes());
        }
    }

    private static void send(HttpExchange exchange, int status, String type, byte[] body) throws IOException {
        exchange.getResponseHeaders().add("Content-Type", type);
        exchange.sendResponseHeaders(status, body.length);
        try (OutputStream output = exchange.getResponseBody()) {
            output.write(body);
        }
    }
}
