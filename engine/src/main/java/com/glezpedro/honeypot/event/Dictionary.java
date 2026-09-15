package com.glezpedro.honeypot.event;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class Dictionary {

    public static final int ABSENT = -1;

    private final Map<String, Integer> ids = new HashMap<>();
    private final List<String> values = new ArrayList<>();

    public int intern(String value) {
        if (value == null || value.isEmpty()) {
            return ABSENT;
        }
        Integer existing = ids.get(value);
        if (existing != null) {
            return existing;
        }
        int id = values.size();
        values.add(value);
        ids.put(value, id);
        return id;
    }

    public String value(int id) {
        return id == ABSENT ? null : values.get(id);
    }

    public int size() {
        return values.size();
    }
}
