// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * The Swing Orphaned Permissions dialog shows the texts in webadmin/web/orphaned-permissions-texts.txt; the web
 * dialog's orphaned-permissions.test.mjs reads the same file.
 */
class OrphanedPermissionsTextsTest {

    @Test
    void theSharedTexts_areTheOnesTheSwingDialogShows() throws IOException {
        Path file = Paths.get(System.getProperty("basedir", ".")).resolve("../webadmin/web/orphaned-permissions-texts.txt")
                .normalize();
        List<String> wrong = new ArrayList<>();
        int checked = 0;
        for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
            if (line.isBlank() || line.startsWith("#")) {
                continue;
            }
            String[] parts = line.split(" ", 2);
            String expected = parts[1];
            String shown;
            switch (parts[0]) {
                case "title" -> shown = OrphanedPermissionsDialog.TITLE;
                case "tooltip" -> shown = OrphanedPermissionsDialog.TOOLTIP;
                case "intro" -> shown = OrphanedPermissionsDialog.INTRO;
                case "empty" -> shown = OrphanedPermissionsDialog.EMPTY;
                case "disabled" -> {
                    String[] io = parts[1].split(" => ", 2);
                    expected = io[1];
                    shown = OrphanedPermissionsDialog.disabledLine(Arrays.asList(io[0].split(", ")));
                }
                case "confirmation" -> {
                    String[] io = parts[1].split(" => ", 2);
                    String[] counts = io[0].split(" ");
                    expected = io[1];
                    shown = OrphanedPermissionsDialog.confirmation(grants(Integer.parseInt(counts[0]),
                            Integer.parseInt(counts[1])));
                }
                default -> shown = "unknown key " + parts[0];
            }
            if (!expected.equals(shown)) {
                wrong.add(line + "  (Swing shows: " + shown + ")");
            }
            checked++;
        }
        assertTrue(checked >= 8, "read only " + checked + " texts from " + file);
        assertEquals(List.of(), wrong);
    }

    /** {@code permissions} grants spread over {@code roles} roles, every role holding at least one. */
    private static List<UnregisteredGrant> grants(int permissions, int roles) {
        List<UnregisteredGrant> grants = new ArrayList<>();
        for (int i = 0; i < permissions; i++) {
            int role = Math.min(i, roles - 1) + 1;
            grants.add(new UnregisteredGrant(role, "Role " + role, "Permission " + i));
        }
        return grants;
    }
}
