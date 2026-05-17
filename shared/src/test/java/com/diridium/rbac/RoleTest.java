// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashSet;
import java.util.Set;

import org.junit.jupiter.api.Test;

class RoleTest {

    @Test
    void copy_preservesAllScalarFields() {
        Role role = new Role();
        role.setId(42);
        role.setName("Admin");
        role.setDescription("Full access");
        role.setPermissions(new HashSet<>(Set.of("viewChannels", "manageUsers")));
        role.setChannelIds(new HashSet<>(Set.of("ch1", "ch2")));
        role.setAdmin(true);

        Role copy = role.copy();

        assertEquals(42, copy.getId());
        assertEquals("Admin", copy.getName());
        assertEquals("Full access", copy.getDescription());
        assertEquals(Set.of("viewChannels", "manageUsers"), copy.getPermissions());
        assertEquals(Set.of("ch1", "ch2"), copy.getChannelIds());
        assertTrue(copy.isAdmin());
    }

    @Test
    void isAdmin_defaultsToFalse() {
        Role role = new Role();
        assertFalse(role.isAdmin());
    }

    @Test
    void copy_preservesIsAdminFalse() {
        Role role = new Role();
        role.setAdmin(false);
        assertFalse(role.copy().isAdmin());
    }

    @Test
    void copy_returnsDistinctInstance() {
        Role role = new Role();
        Role copy = role.copy();
        assertNotSame(role, copy);
    }

    @Test
    void copy_isDefensive() {
        // Mutating the copy's collections must not affect the original.
        Role role = new Role();
        role.setPermissions(new HashSet<>(Set.of("a")));
        role.setChannelIds(new HashSet<>(Set.of("ch1")));

        Role copy = role.copy();
        copy.getPermissions().add("b");
        copy.getChannelIds().add("ch2");

        assertEquals(Set.of("a"), role.getPermissions());
        assertEquals(Set.of("ch1"), role.getChannelIds());
    }

    @Test
    void copy_normalisesNullSetsToEmpty() {
        Role role = new Role();
        role.setPermissions(null);
        role.setChannelIds(null);

        Role copy = role.copy();

        assertNotNull(copy.getPermissions());
        assertNotNull(copy.getChannelIds());
        assertTrue(copy.getPermissions().isEmpty());
        assertTrue(copy.getChannelIds().isEmpty());
    }
}
