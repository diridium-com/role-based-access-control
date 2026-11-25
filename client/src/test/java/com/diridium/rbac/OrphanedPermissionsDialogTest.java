// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.List;

import org.junit.jupiter.api.Test;

class OrphanedPermissionsDialogTest {

    @Test
    void confirmation_countsEachRoleOnce() {
        assertEquals("Remove 2 orphaned permissions from 1 role?", OrphanedPermissionsDialog.confirmation(List.of(
                new UnregisteredGrant(2, "Billing", "A"), new UnregisteredGrant(2, "Billing", "B"))));
    }

    @Test
    void disabledLine_isAbsentWithNoDisabledPlugin() {
        assertNull(OrphanedPermissionsDialog.disabledLine(List.of()));
        assertNull(OrphanedPermissionsDialog.disabledLine(null));
    }
}
