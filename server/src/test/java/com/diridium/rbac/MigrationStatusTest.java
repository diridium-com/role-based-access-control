// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Verifies the {@link MigrationStatus} flag transitions in isolation.
 *
 * <p>Integration of the flag with {@code RbacServicePlugin.start()} and
 * {@code RbacServlet.requireMigrationOk()} is exercised end-to-end when
 * the plugin runs against a real engine; those paths are not unit-tested
 * here because they require a live {@code ConfigurationController} and
 * {@code MirthServlet} HTTP context.</p>
 */
class MigrationStatusTest {

    @BeforeEach
    void resetBeforeTest() {
        MigrationStatus.markOk();
    }

    @AfterEach
    void resetAfterTest() {
        MigrationStatus.markOk();
    }

    @Test
    void defaultStateIsOk() {
        assertTrue(MigrationStatus.isOk());
        assertNull(MigrationStatus.getError());
    }

    @Test
    void markFailed_recordsReason() {
        MigrationStatus.markFailed("schema_version is 1, expected 2");
        assertFalse(MigrationStatus.isOk());
        assertEquals("schema_version is 1, expected 2", MigrationStatus.getError());
    }

    @Test
    void markOk_clearsFailure() {
        MigrationStatus.markFailed("test failure");
        MigrationStatus.markOk();
        assertTrue(MigrationStatus.isOk());
        assertNull(MigrationStatus.getError());
    }

    @Test
    void markFailed_overwritesPreviousReason() {
        MigrationStatus.markFailed("first failure");
        MigrationStatus.markFailed("second failure");
        assertEquals("second failure", MigrationStatus.getError());
        assertFalse(MigrationStatus.isOk());
    }
}
