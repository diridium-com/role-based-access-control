// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.junit.jupiter.api.Test;

/**
 * The role editor keeps the channels its user cannot see: the engine redacts the channel list by the
 * editing user's own restriction, so stored ids missing from the list must survive an edit.
 */
class RoleChannelSelectionTest {

    private static Set<String> set(String... ids) {
        return new HashSet<>(java.util.Arrays.asList(ids));
    }

    private static Role role(boolean admin, boolean restricted) {
        Role role = new Role();
        role.setAdmin(admin);
        role.setRestricted(restricted);
        return role;
    }

    @Test
    void specificKeepsUnseenStoredIdsAlongWithTickedOnes() {
        Set<String> saved = RoleChannelSelection.savedChannelIds(true, set("a"), set("a", "b", "hidden"),
                set("a", "b"));
        assertEquals(set("a", "hidden"), saved);
    }

    @Test
    void specificWithNothingTickedStillKeepsUnseenIds() {
        assertEquals(set("hidden"), RoleChannelSelection.savedChannelIds(true, set(), set("a", "hidden"), set("a")));
    }

    @Test
    void allChannelsDropsEverything() {
        assertTrue(RoleChannelSelection.savedChannelIds(false, set("a"), set("a", "hidden"), set("a")).isEmpty());
    }

    @Test
    void newRoleHasNoStoredIds() {
        assertEquals(set("a"), RoleChannelSelection.savedChannelIds(true, set("a"), null, set("a", "b")));
        assertTrue(RoleChannelSelection.savedChannelIds(true, set(), Collections.<String>emptySet(), set("a")).isEmpty());
    }

    @Test
    void restrictedFollowsTheRadioForOrdinaryRolesAndNewRoles() {
        assertTrue(RoleChannelSelection.savedRestricted(null, true));
        assertFalse(RoleChannelSelection.savedRestricted(null, false));
        assertTrue(RoleChannelSelection.savedRestricted(role(false, false), true));
        assertFalse(RoleChannelSelection.savedRestricted(role(false, true), false));
    }

    @Test
    void adminRoleKeepsItsStoredFlag() {
        assertFalse(RoleChannelSelection.savedRestricted(role(true, false), true));
        assertTrue(RoleChannelSelection.savedRestricted(role(true, true), false));
    }
}
