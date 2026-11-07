// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0
package com.diridium.rbac;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

import org.junit.jupiter.api.Test;

class DeletedUserCleanupTest {

    private final Set<Integer> engineUsers = new java.util.HashSet<>(Set.of(7, 8));
    private final List<Integer> deleted = new ArrayList<>();
    private final List<Integer> invalidated = new ArrayList<>();
    private final AtomicLong now = new AtomicLong(1_000);

    private DeletedUserCleanup cleanup(String roleName) {
        return new DeletedUserCleanup(engineUsers::contains, id -> roleName, deleted::add, invalidated::add, now::get);
    }

    @Test
    void nothingPendingDoesNothing() {
        DeletedUserCleanup c = new DeletedUserCleanup(id -> { throw new AssertionError("asked the engine"); },
                id -> { throw new AssertionError("asked the repository"); }, deleted::add, invalidated::add, now::get);
        assertEquals(0, c.run());
        assertTrue(c.pendingUserIds().isEmpty());
    }

    @Test
    void userGoneRemovesTheAssignmentAndTheCacheEntry() {
        DeletedUserCleanup c = cleanup("Pharmacy");
        c.expect(7, "jsmith");
        engineUsers.remove(7);
        assertEquals(1, c.run());
        assertEquals(List.of(7), deleted);
        assertEquals(List.of(7), invalidated);
        assertTrue(c.pendingUserIds().isEmpty());
        assertEquals(0, c.run(), "nothing left to do");
    }

    @Test
    void userStillThereIsCheckedAgainUntilTheGiveUpTime() {
        DeletedUserCleanup c = cleanup("Pharmacy");
        c.expect(7, "jsmith");
        assertEquals(0, c.run());
        assertEquals(Set.of(7), c.pendingUserIds(), "the delete may still be in flight");
        assertTrue(deleted.isEmpty());
        now.addAndGet(DeletedUserCleanup.GIVE_UP_AFTER_MS + 1);
        assertEquals(0, c.run());
        assertTrue(c.pendingUserIds().isEmpty(), "the delete did not go through: forgotten");
        assertTrue(deleted.isEmpty(), "a user who is still there keeps the role");
    }

    @Test
    void twoRequestsHandlingTheSameDeletedUser_removeTheAssignmentOnce() {
        // A second request runs the cleanup while the first is inside the engine lookup: whichever takes the
        // pending entry does the delete, the other skips it.
        DeletedUserCleanup[] holder = new DeletedUserCleanup[1];
        int[] lookups = {0};
        holder[0] = new DeletedUserCleanup(id -> {
            if (lookups[0]++ == 0) {
                holder[0].run();  // the other request, between this lookup and the removal
            }
            return false;
        }, id -> "Pharmacy", deleted::add, invalidated::add, now::get);
        holder[0].expect(7, "jsmith");
        engineUsers.remove(7);

        int removed = holder[0].run();

        assertEquals(List.of(7), deleted, "one delete, not two");
        assertEquals(0, removed, "the nested run took the entry, so the outer run removed nothing");
        assertTrue(holder[0].pendingUserIds().isEmpty());
    }

    @Test
    void userGoneWithNoRoleRemovesNothing() {
        DeletedUserCleanup c = cleanup(null);
        c.expect(8, "nobody");
        engineUsers.remove(8);
        assertEquals(0, c.run());
        assertTrue(deleted.isEmpty());
        assertTrue(c.pendingUserIds().isEmpty());
    }

    @Test
    void aFailureDropsTheEntryWithoutThrowing() {
        DeletedUserCleanup c = new DeletedUserCleanup(id -> false,
                id -> { throw new IllegalStateException("database down"); }, deleted::add, invalidated::add, now::get);
        c.expect(7, "jsmith");
        assertEquals(0, c.run());
        assertTrue(c.pendingUserIds().isEmpty(), "left to the startup sweep");
        assertTrue(deleted.isEmpty());
    }

    @Test
    void severalPendingUsersAreHandledIndependently() {
        DeletedUserCleanup c = cleanup("Lab");
        c.expect(7, "a");
        c.expect(8, "b");
        engineUsers.remove(8);
        assertEquals(1, c.run());
        assertEquals(List.of(8), deleted);
        assertEquals(Set.of(7), c.pendingUserIds());
    }
}
