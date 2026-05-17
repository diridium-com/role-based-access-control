// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import java.util.HashSet;
import java.util.Set;
import java.util.function.Supplier;

import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import com.mirth.connect.client.core.api.MirthApiException;

/**
 * Enforces the admin-role invariants on every mutation.
 *
 * <p>The "admin role" is identified by the {@code is_admin} flag on
 * {@code rbac_role}. The flag is set once at seed time and never editable
 * from the UI or REST API. The role's name and description are cosmetic and
 * can be changed freely.</p>
 *
 * <p>Multiple users can be assigned to the admin role (multi-admin
 * deployments). The guard enforces an "admin floor": at least one user must
 * always hold the admin role, preventing accidental lockout.</p>
 *
 * <p>Protections:</p>
 * <ul>
 *   <li>The admin role must always retain the full core-permission set (the
 *       floor it is seeded with; admin access itself is by the is_admin flag,
 *       so extension perms are not part of the retention requirement)</li>
 *   <li>The admin role cannot have channel restrictions</li>
 *   <li>The admin role cannot be deleted</li>
 *   <li>The last admin user's role cannot be removed</li>
 *   <li>The last admin user cannot be reassigned to a non-admin role</li>
 * </ul>
 *
 * <p>When no admin role exists (edge case during bootstrap or after disaster),
 * the guard is permissive — there is no admin role to protect.</p>
 *
 * <p><b>Concurrency:</b> the floor checks are check-then-act and deliberately
 * unsynchronized — they are best-effort under concurrent mutations. Defeating
 * them requires two requests that each strip one of the last two admins to
 * interleave within the milliseconds between the COUNT and the write, which
 * no realistic admin-UI usage produces. A lock spanning validate-plus-mutate
 * was considered and rejected (2026-06-12): concurrency machinery in
 * security-critical code is its own mistake generator. If the race ever
 * fires, recovery is a server restart — {@link AdminRoleSeeder} re-floors
 * user 1 if they end up roleless. Revisit only if admins start mutating
 * roles programmatically/concurrently via the REST API.</p>
 *
 * <p>Validation failures throw {@link MirthApiException} with
 * {@link Status#BAD_REQUEST} so the admin UI can surface a clean error code
 * + message instead of a wrapped {@link com.mirth.connect.client.core.ClientException}.</p>
 */
class AdminRoleGuard {

    private final RbacRepository repo;
    private final Supplier<Set<String>> requiredPermissionsSupplier;

    /**
     * @param repo source of truth for which role is flagged is_admin and which
     *             users hold it
     * @param requiredPermissionsSupplier returns the core-permission floor the
     *                                    admin role must retain (the set the
     *                                    seeder grants it); evaluated lazily
     */
    AdminRoleGuard(RbacRepository repo, Supplier<Set<String>> requiredPermissionsSupplier) {
        this.repo = repo;
        this.requiredPermissionsSupplier = requiredPermissionsSupplier;
    }

    /**
     * Looks up the current admin role by its flag.
     *
     * @return the id of the role currently flagged {@code is_admin=true}, or
     *         {@code null} if no role carries the flag
     */
    Integer getAdminRoleId() {
        return repo.getAdminRoleId();
    }

    /**
     * Validates an incoming role update against the admin invariants.
     * Non-admin roles pass through with no checks; admin roles must keep
     * their full permission set and remain free of channel restrictions.
     *
     * @param roleId   the id of the role being updated
     * @param incoming the proposed new state of the role
     * @throws MirthApiException with {@link Status#BAD_REQUEST} if the
     *                           update would weaken the admin role
     */
    void validateRoleUpdate(int roleId, Role incoming) {
        Integer adminRoleId = getAdminRoleId();
        if (adminRoleId == null || roleId != adminRoleId) {
            return;
        }

        Set<String> incomingPerms = incoming.getPermissions() != null
                ? incoming.getPermissions()
                : Set.of();

        Set<String> required = new HashSet<>(requiredPermissionsSupplier.get());
        if (!incomingPerms.containsAll(required)) {
            throw badRequest("The admin role must retain all permissions; users assigned to it would otherwise lose access");
        }

        if (incoming.getChannelIds() != null && !incoming.getChannelIds().isEmpty()) {
            throw badRequest("The admin role cannot have channel restrictions");
        }
    }

    /**
     * Validates a role deletion against the admin invariants.
     *
     * @param roleId the id of the role being deleted
     * @throws MirthApiException with {@link Status#BAD_REQUEST} if the
     *                           role is the admin role
     */
    void validateRoleDeletion(int roleId) {
        Integer adminRoleId = getAdminRoleId();
        if (adminRoleId != null && roleId == adminRoleId) {
            throw badRequest("Cannot delete the admin role");
        }
    }

    /**
     * Validates removal of a user's role assignment. Refuses to leave zero
     * admins; an admin user can be unassigned only while at least one other
     * admin remains.
     *
     * @param userId the user whose role assignment is being removed
     * @throws MirthApiException with {@link Status#BAD_REQUEST} if removing
     *                           this user's role would leave zero admins
     */
    void validateUserRoleRemoval(int userId) {
        Integer adminRoleId = getAdminRoleId();
        if (adminRoleId == null) {
            return;
        }
        Integer currentRoleId = repo.getUserRoleId(userId);
        if (currentRoleId == null || !currentRoleId.equals(adminRoleId)) {
            return; // User isn't an admin; removal is fine
        }
        if (repo.countUsersByRoleId(adminRoleId) <= 1) {
            throw badRequest("Cannot remove the role assignment from the last admin user; assign another admin first");
        }
    }

    /**
     * Validates a user-role (re)assignment. Refuses to leave zero admins when
     * moving the last admin user to a non-admin role.
     *
     * @param userId    the user whose role is being (re)assigned
     * @param newRoleId the role id the user will hold after the assignment
     * @throws MirthApiException with {@link Status#BAD_REQUEST} if the
     *                           assignment would leave zero admins
     */
    void validateUserRoleAssignment(int userId, int newRoleId) {
        Integer adminRoleId = getAdminRoleId();
        if (adminRoleId == null) {
            return;
        }
        if (newRoleId == adminRoleId) {
            return; // Becoming or staying an admin — fine
        }
        Integer currentRoleId = repo.getUserRoleId(userId);
        if (currentRoleId == null || !currentRoleId.equals(adminRoleId)) {
            return; // Wasn't an admin to begin with
        }
        if (repo.countUsersByRoleId(adminRoleId) <= 1) {
            throw badRequest("Cannot reassign the last admin user to a non-admin role; assign another admin first");
        }
    }

    private static MirthApiException badRequest(String message) {
        return new MirthApiException(Response.status(Status.BAD_REQUEST).entity(message).build());
    }
}
