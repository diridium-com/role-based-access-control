// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;

/**
 * rbac's log lines quote a role, permission, channel, user or plugin name as '{}'. The engine writes log messages as
 * they are, so each such line has to pass the name through {@link NameCharacters#forLog}. This test reads the server
 * sources and fails for a log line that quotes a placeholder and never calls it.
 */
class LogNameEscapingTest {

    private static final Pattern LOG_CALL = Pattern.compile("\\blog\\.(trace|debug|info|warn|error)\\(");

    @Test
    void everyLogLineThatQuotesAName_escapesIt() throws IOException {
        List<String> missing = new ArrayList<>();
        int quoted = 0;
        try (Stream<Path> files = Files.walk(Path.of("src/main/java"))) {
            for (Path file : files.filter(p -> p.toString().endsWith(".java")).toList()) {
                String source = Files.readString(file);
                Matcher m = LOG_CALL.matcher(source);
                while (m.find()) {
                    String call = arguments(source, m.end());
                    if (!call.contains("'{}'")) {
                        continue;
                    }
                    quoted++;
                    // The bootstrap admin role's name is a constant.
                    if (!call.contains("NameCharacters.forLog(") && !call.contains("BOOTSTRAP_ADMIN_ROLE_NAME")) {
                        missing.add(file.getFileName() + ": " + call.lines().findFirst().orElse("").strip());
                    }
                }
            }
        }
        assertTrue(quoted > 10, "found only " + quoted + " log lines that quote a placeholder; is the source path right?");
        assertTrue(missing.isEmpty(), "log lines that quote '{}' without NameCharacters.forLog: " + missing);
    }

    /** The call's arguments: the text from its opening parenthesis to the matching one, skipping string literals. */
    private static String arguments(String source, int from) {
        int depth = 1;
        boolean inString = false;
        for (int i = from; i < source.length(); i++) {
            char c = source.charAt(i);
            if (inString) {
                if (c == '\\') {
                    i++;
                } else if (c == '"') {
                    inString = false;
                }
            } else if (c == '"') {
                inString = true;
            } else if (c == '(') {
                depth++;
            } else if (c == ')' && --depth == 0) {
                return source.substring(from, i);
            }
        }
        return source.substring(from);
    }
}
