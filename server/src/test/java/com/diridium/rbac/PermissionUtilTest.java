// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Set;

import org.junit.jupiter.api.Test;

class PermissionUtilTest {

    @Test
    void getAllCorePermissions_returnsNonEmpty() {
        Set<String> perms = PermissionUtil.getAllCorePermissions();
        assertFalse(perms.isEmpty(), "Engine declares many permission constants; result should not be empty");
    }

    @Test
    void getAllCorePermissions_includesKnownConstants() {
        Set<String> perms = PermissionUtil.getAllCorePermissions();
        assertTrue(perms.contains("viewChannels"));
        assertTrue(perms.contains("manageChannels"));
        assertTrue(perms.contains("manageUsers"));
        assertTrue(perms.contains("viewDashboard"));
    }

    @Test
    void getAllCorePermissions_isStable() {
        // Two calls return the same set (no hidden state, idempotent).
        assertEquals(PermissionUtil.getAllCorePermissions(), PermissionUtil.getAllCorePermissions());
    }
}
