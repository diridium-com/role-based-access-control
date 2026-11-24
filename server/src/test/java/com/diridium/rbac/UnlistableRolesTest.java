// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import static com.diridium.rbac.LogCapture.stderrDuring;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;

class UnlistableRolesTest {

    @Test
    void aRoleWithACharacterXmlCannotCarry_isNamedWithItsId() {
        Role described = role(10, "Described", Set.of("viewChannels"));
        described.setDescription("desc\u0007bell");
        String output = stderrDuring(() -> UnlistableRoles.logAll(List.of(
                role(7, "probe\u0007role", Set.of("viewChannels")),
                role(8, "Lab", Set.of("viewChannels", "bell\u0007perm")),
                role(9, "Line\nbreak", Set.of("viewChannels")),
                described)));

        assertTrue(output.contains("RBAC: role 7 'probe\\u0007role' has a character that stops the Administrators from"
                + " listing roles and blocks role export. Delete it; the README says how."), output);
        assertTrue(output.contains("RBAC: role 8 'Lab' has a character"), output);
        assertTrue(output.contains("RBAC: role 10 'Described' has a character"), output);
        assertFalse(output.contains("role 9"), "a line break doesn't stop the role list: " + output);
    }

    private static Role role(int id, String name, Set<String> permissions) {
        Role role = new Role();
        role.setId(id);
        role.setName(name);
        role.setPermissions(new HashSet<>(permissions));
        role.setChannelIds(new HashSet<>());
        return role;
    }
}
