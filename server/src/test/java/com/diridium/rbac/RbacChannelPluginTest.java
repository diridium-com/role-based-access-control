// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;

/** What rbac does when the engine deletes a channel: the restriction rows go, the cache is cleared, nothing widens. */
class RbacChannelPluginTest {

    private final List<String> deleted = new ArrayList<>();
    private boolean invalidated;

    private static Role role(int id, String name, Set<String> channelIds) {
        Role role = new Role();
        role.setId(id);
        role.setName(name);
        role.setChannelIds(new HashSet<>(channelIds));
        role.setRestricted(true);
        return role;
    }

    @Test
    void removesTheRowsOfEveryRoleRestrictedToTheChannel_andClearsTheCache() {
        int removed = RbacChannelPlugin.channelRemoved("id-gone", "Gone", id -> List.of(5, 6),
                id -> { deleted.add(id); return 2; },
                id -> id == 5 ? role(5, "Lab", Set.of("id-lab")) : role(6, "Retired", Set.of()),
                () -> invalidated = true);

        assertEquals(2, removed);
        assertEquals(List.of("id-gone"), deleted);
        assertTrue(invalidated);
    }

    @Test
    void aChannelNoRoleIsRestrictedTo_changesNothing() {
        int removed = RbacChannelPlugin.channelRemoved("id-free", "Free", id -> List.of(),
                id -> { deleted.add(id); return 0; }, id -> null, () -> invalidated = true);

        assertEquals(0, removed);
        assertTrue(deleted.isEmpty());
        assertFalse(invalidated, "nothing changed, so the cache stays");
    }

    @Test
    void aFailedRoleLookupAfterTheDelete_stillReportsTheRowsRemoved() {
        int removed = RbacChannelPlugin.channelRemoved("id-gone", "Gone", id -> List.of(5),
                id -> { deleted.add(id); return 1; },
                id -> { throw new IllegalStateException("db unreachable"); }, () -> invalidated = true);

        assertEquals(1, removed, "the rows were removed before the lookup failed");
        assertEquals(List.of("id-gone"), deleted);
        assertTrue(invalidated);
    }

    @Test
    void aFailure_isNonFatal_andLeavesTheRowsForTheSweep() {
        int removed = RbacChannelPlugin.channelRemoved("id-gone", "Gone",
                id -> { throw new IllegalStateException("db unreachable"); },
                id -> { deleted.add(id); return 1; }, id -> null, () -> invalidated = true);

        assertEquals(0, removed);
        assertTrue(deleted.isEmpty());
        assertFalse(invalidated);
    }
}
