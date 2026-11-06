// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

/**
 * The startup sweep of channel restrictions to channels the engine no longer has, against
 * in-memory rows: which rows go, which stay, and that an unreadable or empty channel list removes
 * nothing.
 */
class DeletedChannelSweepTest {

    private final List<String> deleted = new ArrayList<>();

    private static Map<String, Object> row(int roleId, String channelId) {
        return Map.of("roleId", roleId, "channelId", channelId);
    }

    @Test
    void removesOnlyRowsWhoseChannelIsGone_andLeavesTheRoleRestricted() {
        List<Map<String, Object>> rows = List.of(row(5, "id-lab"), row(5, "id-gone"), row(6, "id-gone2"), row(7, "id-adt"));

        int removed = DeletedChannelSweep.run(() -> Set.of("id-lab", "id-adt"), () -> rows,
                (roleId, channelId) -> deleted.add(roleId + ":" + channelId),
                () -> Map.of(5, "Lab", 6, "Retired", 7, "ADT"));

        assertEquals(2, removed);
        assertEquals(List.of("5:id-gone", "6:id-gone2"), deleted, "role 6 is left restricted to no channel");
    }

    @Test
    void readsTheColumnsWhateverCaseTheDriverReturns() {
        List<Map<String, Object>> rows = List.of(Map.of("ROLEID", 5, "CHANNELID", "id-gone"),
                Map.of("roleid", 6, "channelid", "id-gone2"));

        int removed = DeletedChannelSweep.run(() -> Set.of("id-lab"), () -> rows,
                (roleId, channelId) -> deleted.add(roleId + ":" + channelId), () -> Map.of());

        assertEquals(2, removed);
        assertEquals(List.of("5:id-gone", "6:id-gone2"), deleted);
    }

    @Test
    void trimsTheCharColumn_beforeComparing() {
        List<Map<String, Object>> rows = List.of(row(5, "id-lab   "));

        int removed = DeletedChannelSweep.run(() -> Set.of("id-lab"), () -> rows,
                (roleId, channelId) -> deleted.add(channelId), () -> Map.of());

        assertEquals(0, removed);
        assertTrue(deleted.isEmpty());
    }

    @Test
    void anUnreadableChannelList_removesNothing() {
        List<Map<String, Object>> rows = List.of(row(5, "id-lab"));

        int removed = DeletedChannelSweep.run(() -> { throw new IllegalStateException("engine not ready"); },
                () -> rows, (roleId, channelId) -> deleted.add(channelId), () -> Map.of());

        assertEquals(0, removed, "an unreadable list must not pass for an empty one");
        assertTrue(deleted.isEmpty());
    }

    @Test
    void anEmptyChannelList_withRowsPresent_removesNothing() {
        // The engine's channel cache answers empty after a failed database read instead of
        // throwing, so an empty list must not pass for "every channel is gone".
        List<Map<String, Object>> rows = List.of(row(5, "id-lab"));

        int removed = DeletedChannelSweep.run(() -> Set.of(), () -> rows,
                (roleId, channelId) -> deleted.add(channelId), () -> Map.of(5, "Lab"));

        assertEquals(0, removed, "an empty list must not pass for every channel being gone");
        assertTrue(deleted.isEmpty());
    }

    @Test
    void anEmptyChannelList_withNoRows_isNothingToDo() {
        int removed = DeletedChannelSweep.run(() -> Set.of(), List::of,
                (roleId, channelId) -> deleted.add(channelId), () -> Map.of());

        assertEquals(0, removed);
        assertTrue(deleted.isEmpty());
    }

    @Test
    void aFailingDelete_isNonFatal() {
        List<Map<String, Object>> rows = List.of(row(5, "id-gone"));

        int removed = DeletedChannelSweep.run(() -> Set.of("id-lab"), () -> rows,
                (roleId, channelId) -> { throw new IllegalStateException("db unreachable"); }, () -> Map.of());

        assertEquals(0, removed);
    }
}
