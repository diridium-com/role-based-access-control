// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;

/** Captures what the code under test logs. The tests log through slf4j-simple, to stderr. */
final class LogCapture {

    private LogCapture() {
    }

    /** Runs the action and returns what was logged meanwhile. */
    static String stderrDuring(Runnable action) {
        PrintStream stderr = System.err;
        ByteArrayOutputStream captured = new ByteArrayOutputStream();
        try {
            System.setErr(new PrintStream(captured, true, StandardCharsets.UTF_8));
            action.run();
        } finally {
            System.setErr(stderr);
        }
        return captured.toString(StandardCharsets.UTF_8);
    }
}
