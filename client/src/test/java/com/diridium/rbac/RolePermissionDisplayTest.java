// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;

class RolePermissionDisplayTest {

    private static final List<String> CATALOG = List.of("viewChannels", "manageUsers", "Cache Manager#View Caches");

    private static Role role(boolean admin, Set<String> permissions) {
        Role role = new Role();
        role.setAdmin(admin);
        role.setPermissions(permissions);
        return role;
    }

    @Test
    void theAdminRoleShowsTheWholeCatalog_whateverIsStored() {
        assertEquals(Set.copyOf(CATALOG), RolePermissionDisplay.shown(role(true, Set.of("viewChannels")), CATALOG));
        assertEquals(Set.copyOf(CATALOG), RolePermissionDisplay.shown(role(true, Set.of()), CATALOG));
    }

    @Test
    void anyOtherRoleShowsItsStoredPermissions() {
        assertEquals(Set.of("viewChannels"), RolePermissionDisplay.shown(role(false, Set.of("viewChannels")), CATALOG));
        assertEquals(Set.of(), RolePermissionDisplay.shown(role(false, null), CATALOG));
    }
}
