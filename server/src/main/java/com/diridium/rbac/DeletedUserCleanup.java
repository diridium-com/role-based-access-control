// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0
package com.diridium.rbac;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.IntConsumer;
import java.util.function.IntFunction;
import java.util.function.IntPredicate;
import java.util.function.LongSupplier;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.mirth.connect.model.User;
import com.mirth.connect.server.controllers.ControllerFactory;

/**
 * Removes a deleted user's role assignment as soon as the engine has deleted the user.
 * The engine tells no plugin about a user delete, but it asks RBAC to authorize the
 * {@code removeUser} call first, so RBAC knows a delete is about to happen, never that it
 * did. The approved target is held as pending; on the next authorization request, from
 * anyone, the engine is asked whether the user still exists. Gone: the assignment row is
 * deleted, the cache entry dropped, and one line logged. Still there (the delete failed):
 * the entry is kept for a minute and then forgotten, and the startup sweep stays the backstop.
 *
 * <p>The assignment is never removed before the delete, because the engine can still refuse it
 * (deleting yourself, a database error), and that must not strip a role from a user who is
 * still there. Non-fatal throughout.</p>
 */
final class DeletedUserCleanup {

    private static final Logger log = LoggerFactory.getLogger(DeletedUserCleanup.class);

    /** How long a pending user whose delete did not go through is checked for. */
    static final long GIVE_UP_AFTER_MS = 60_000;

    private final IntPredicate userExists;
    private final IntFunction<String> roleNameOf;
    private final IntConsumer deleteAssignment;
    private final IntConsumer invalidate;
    private final LongSupplier clock;
    private final ConcurrentHashMap<Integer, Pending> pending = new ConcurrentHashMap<>();

    private record Pending(String username, long since) {
    }

    /**
     * @param userExists       asks the engine whether a user id still exists
     * @param roleNameOf       the name of the role the user holds, or null for none
     * @param deleteAssignment removes the user's assignment row
     * @param invalidate       drops the user's authorization cache entry
     * @param clock            milliseconds, for the give-up time
     */
    DeletedUserCleanup(IntPredicate userExists, IntFunction<String> roleNameOf, IntConsumer deleteAssignment,
            IntConsumer invalidate, LongSupplier clock) {
        this.userExists = userExists;
        this.roleNameOf = roleNameOf;
        this.deleteAssignment = deleteAssignment;
        this.invalidate = invalidate;
        this.clock = clock;
    }

    /** The production wiring: the engine's user controller and the repository. */
    static DeletedUserCleanup create(IntConsumer invalidate) {
        return new DeletedUserCleanup(DeletedUserCleanup::engineHasUser, userId -> {
            Role role = RbacRepository.getInstance().getUserRole(userId);
            return role == null ? null : role.getName();
        }, userId -> RbacRepository.getInstance().removeUserRole(userId), invalidate, System::currentTimeMillis);
    }

    /** Notes that the engine was allowed to delete this user. */
    void expect(int userId, String username) {
        pending.put(userId, new Pending(username, clock.getAsLong()));
    }

    /** The user ids waiting to be confirmed deleted. */
    Set<Integer> pendingUserIds() {
        return Set.copyOf(pending.keySet());
    }

    /**
     * Checks every pending user; called on each authorization, and free when nothing is pending.
     *
     * @return the number of assignments removed
     */
    int run() {
        if (pending.isEmpty()) {
            return 0;
        }
        int removed = 0;
        for (Map.Entry<Integer, Pending> entry : pending.entrySet()) {
            int userId = entry.getKey();
            Pending p = entry.getValue();
            try {
                if (userExists.test(userId)) {
                    if (clock.getAsLong() - p.since() > GIVE_UP_AFTER_MS) {
                        pending.remove(userId, p);
                    }
                    continue;
                }
                pending.remove(userId, p);
                String role = roleNameOf.apply(userId);
                if (role != null) {
                    deleteAssignment.accept(userId);
                    invalidate.accept(userId);
                    removed++;
                    log.info("RBAC maintenance: user '{}' was deleted, removed the assignment to role '{}'.",
                            p.username(), role);
                }
            } catch (Exception e) {
                pending.remove(userId, p);
                log.warn("RBAC maintenance: could not remove the role assignment of deleted user '{}' (non-fatal,"
                        + " the startup sweep will): {}", p.username(), e.getMessage());
            }
        }
        return removed;
    }

    private static boolean engineHasUser(int userId) {
        try {
            return ControllerFactory.getFactory().createUserController().getUser(userId, null) != null;
        } catch (Exception e) {
            // Unknown is not "gone": keep the entry and ask again on the next request.
            log.debug("RBAC: could not read user {} from the engine", userId, e);
            return true;
        }
    }

    /** The user's name for the log, read while the user still exists; the id if it can't be. */
    static String usernameOf(int userId) {
        try {
            User user = ControllerFactory.getFactory().createUserController().getUser(userId, null);
            if (user != null && user.getUsername() != null) {
                return user.getUsername();
            }
        } catch (Exception e) {
            log.debug("RBAC: could not read user {} from the engine", userId, e);
        }
        return "id " + userId;
    }
}
