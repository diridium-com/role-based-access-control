// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.mirth.connect.plugins.auth.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import org.junit.jupiter.api.Test;

/**
 * The Swing controller's task maps and admin-only tasks equal the web administrator's, through
 * the checked-in parity file webadmin/web/task-permission-map.json (the web module's own test
 * compares the same file with task-permission-map.js). A missing file fails the test.
 */
class TaskPermissionMapParityTest {

    private static Map<String, Object> parityFile() throws Exception {
        Path file = Paths.get(System.getProperty("basedir", ".")).resolve("../webadmin/web/task-permission-map.json")
                .normalize();
        assertTrue(Files.isRegularFile(file), "the parity file is missing: " + file);
        Object json = new JsonReader(new String(Files.readAllBytes(file), StandardCharsets.UTF_8)).read();
        @SuppressWarnings("unchecked")
        Map<String, Object> top = (Map<String, Object>) json;
        return top;
    }

    private static Object field(String name) throws Exception {
        Field f = SecureAuthorizationController.class.getDeclaredField(name);
        f.setAccessible(true);
        return f.get(new SecureAuthorizationController());
    }

    @Test
    void taskPermissionsEqualTheParityFile() throws Exception {
        assertEquals(new TreeMap<>((Map<?, ?>) parityFile().get("taskPermissions")),
                new TreeMap<>((Map<?, ?>) field("taskPermissionMap")));
    }

    @Test
    void groupTaskPermissionsEqualTheParityFile() throws Exception {
        assertEquals(new TreeMap<>((Map<?, ?>) parityFile().get("groupTaskPermissions")),
                new TreeMap<>((Map<?, ?>) field("groupTaskPermissionMap")));
    }

    @Test
    void adminOnlyTasksEqualTheParityFile() throws Exception {
        List<?> adminOnly = (List<?>) parityFile().get("adminOnlyTasks");
        assertFalse(adminOnly.isEmpty());
        assertEquals(adminOnly.size(), new HashSet<>(adminOnly).size(), "no task listed twice");
        assertEquals(new HashSet<>(adminOnly), new HashSet<>((Set<?>) field("ADMIN_ONLY_TASKS")));
    }

    @Test
    void theReaderReadsWhatTheFileUses() {
        Object json = new JsonReader("{ \"a\": {\"k\": \"v\\\"q\\u00e9\"}, \"b\": [\"x\", \"y\"], \"c\": [] }").read();
        Map<String, Object> expected = new LinkedHashMap<>();
        Map<String, Object> inner = new LinkedHashMap<>();
        inner.put("k", "v\"q" + (char) 0xE9);
        expected.put("a", inner);
        expected.put("b", List.of("x", "y"));
        expected.put("c", List.of());
        assertEquals(expected, json);
    }

    /** Reads the JSON the parity file uses: objects, arrays and strings. */
    private static final class JsonReader {
        private final String text;
        private int pos;

        JsonReader(String text) {
            this.text = text;
        }

        Object read() {
            Object value = value();
            skipSpace();
            if (pos != text.length()) {
                throw new IllegalStateException("text after the JSON value at " + pos);
            }
            return value;
        }

        private Object value() {
            skipSpace();
            char c = text.charAt(pos);
            if (c == '{') {
                return object();
            }
            if (c == '[') {
                return array();
            }
            if (c == '"') {
                return string();
            }
            throw new IllegalStateException("unexpected '" + c + "' at " + pos);
        }

        private Map<String, Object> object() {
            Map<String, Object> map = new LinkedHashMap<>();
            pos++;
            skipSpace();
            if (text.charAt(pos) == '}') {
                pos++;
                return map;
            }
            while (true) {
                skipSpace();
                String key = string();
                skipSpace();
                expect(':');
                if (map.put(key, value()) != null) {
                    throw new IllegalStateException("key listed twice: " + key);
                }
                skipSpace();
                if (text.charAt(pos) == '}') {
                    pos++;
                    return map;
                }
                expect(',');
            }
        }

        private List<Object> array() {
            List<Object> list = new ArrayList<>();
            pos++;
            skipSpace();
            if (text.charAt(pos) == ']') {
                pos++;
                return list;
            }
            while (true) {
                list.add(value());
                skipSpace();
                if (text.charAt(pos) == ']') {
                    pos++;
                    return list;
                }
                expect(',');
            }
        }

        private String string() {
            expect('"');
            StringBuilder sb = new StringBuilder();
            while (true) {
                char c = text.charAt(pos++);
                if (c == '"') {
                    return sb.toString();
                }
                if (c != '\\') {
                    sb.append(c);
                    continue;
                }
                char e = text.charAt(pos++);
                switch (e) {
                    case 'n':
                        sb.append('\n');
                        break;
                    case 't':
                        sb.append('\t');
                        break;
                    case 'r':
                        sb.append('\r');
                        break;
                    case 'b':
                        sb.append('\b');
                        break;
                    case 'f':
                        sb.append('\f');
                        break;
                    case 'u':
                        sb.append((char) Integer.parseInt(text.substring(pos, pos + 4), 16));
                        pos += 4;
                        break;
                    default:
                        sb.append(e);
                }
            }
        }

        private void expect(char c) {
            if (text.charAt(pos) != c) {
                throw new IllegalStateException("expected '" + c + "' at " + pos);
            }
            pos++;
        }

        private void skipSpace() {
            while (pos < text.length() && Character.isWhitespace(text.charAt(pos))) {
                pos++;
            }
        }
    }
}
