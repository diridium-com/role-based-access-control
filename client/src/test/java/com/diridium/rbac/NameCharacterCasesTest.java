// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

/**
 * The Swing role editor checks names with {@link NameCharacters}, the server's own rule. The web role editor has the
 * rule in rbac-core.js. Both answer the cases in webadmin/web/name-character-cases.txt; the web side's
 * name-characters.test.mjs reads the same file.
 */
class NameCharacterCasesTest {

    private static final Pattern ESCAPE = Pattern.compile("\\\\u([0-9a-fA-F]{4})");

    @Test
    void theSharedCases_getTheExpectedAnswers() throws IOException {
        Path file = Paths.get(System.getProperty("basedir", ".")).resolve("../webadmin/web/name-character-cases.txt")
                .normalize();
        List<String> wrong = new ArrayList<>();
        int checked = 0;
        int messages = 0;
        for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
            if (line.isBlank() || line.startsWith("#")) {
                continue;
            }
            String[] parts = line.split(" ", 3);
            if ("message".equals(parts[0])) {
                String shown = "name".equals(parts[1]) ? NameCharacters.NAME_MESSAGE : NameCharacters.DESCRIPTION_MESSAGE;
                if (!shown.equals(parts[2])) {
                    wrong.add(line);
                }
                messages++;
                continue;
            }
            String value = ESCAPE.matcher(parts[2]).replaceAll(m ->
                    Matcher.quoteReplacement(String.valueOf((char) Integer.parseInt(m.group(1), 16))));
            boolean refused = "name".equals(parts[0])
                    ? NameCharacters.isRefused(value) : NameCharacters.isRefusedInDescription(value);
            if (refused != "refused".equals(parts[1])) {
                wrong.add(line);
            }
            checked++;
        }
        assertTrue(checked >= 20, "read only " + checked + " cases from " + file);
        assertEquals(2, messages, "message lines in " + file);
        assertTrue(wrong.isEmpty(), "cases NameCharacters answers differently: " + wrong);
    }

    @Test
    void editorRefusal_checksOnlyANewOrChangedNameOrDescription() {
        assertEquals(NameCharacters.NAME_MESSAGE, NameCharacters.editorRefusal(null, null, "Lab\tX", ""));
        assertEquals(NameCharacters.NAME_MESSAGE, NameCharacters.editorRefusal("Lab", "d", "Lab\u202EX", "d"));
        assertNull(NameCharacters.editorRefusal("Lab\tX", "d", "Lab\tX", "d"), "an existing name is kept");
        assertEquals(NameCharacters.DESCRIPTION_MESSAGE, NameCharacters.editorRefusal("Lab", "d", "Lab", "d\u0007"));
        assertNull(NameCharacters.editorRefusal("Lab", "d\u0007", "Lab", "d\u0007"), "an existing description is kept");
        assertNull(NameCharacters.editorRefusal(null, null, "Lab", "first\nsecond"));
    }
}
