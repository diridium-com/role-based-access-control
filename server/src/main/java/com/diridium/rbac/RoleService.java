// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import java.util.LinkedHashSet;
import java.util.Set;
import java.util.function.Supplier;

import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import com.mirth.connect.client.core.api.MirthApiException;

/**
 * Business logic for role and user-role mutations.
 *
 * <p>Extracted from {@link RbacServlet} so the validation rules, conflict
 * detection, admin-guard delegation, and audit dispatch can be unit-tested
 * without instantiating {@code MirthServlet}'s HTTP machinery. The servlet
 * methods are thin wrappers that handle {@link MirthApiException}
 * translation and the migration-status guard.</p>
 *
 * <p>All collaborators are injected via the constructor; the cache
 * invalidator is a {@link Runnable} so the servlet can pass a method
 * reference without exposing its private auth-controller lookup.</p>
 */
class RoleService {

    private final RbacRepository repo;
    private final AdminRoleGuard adminGuard;
    private final RbacAuditLog auditLog;
    private final Runnable cacheInvalidator;

    /**
     * @param repo             persistence layer
     * @param adminGuard       enforces the admin-role invariants
     * @param auditLog         records ServerEvents for mutations
     * @param cacheInvalidator called after every successful mutation to
     *                         drop cached per-user auth state; pass a
     *                         no-op {@link Runnable} in tests
     */
    RoleService(RbacRepository repo, AdminRoleGuard adminGuard, RbacAuditLog auditLog, Runnable cacheInvalidator) {
        this.repo = repo;
        this.adminGuard = adminGuard;
        this.auditLog = auditLog;
        this.cacheInvalidator = cacheInvalidator;
    }

    /**
     * @param roleId database id to look up
     * @return the role
     * @throws MirthApiException with {@link Status#NOT_FOUND} if no row exists
     */
    Role get(int roleId) {
        Role role = repo.getRoleById(roleId);
        if (role == null) {
            throw new MirthApiException(Status.NOT_FOUND);
        }
        return role;
    }

    /**
     * Creates a new role. The {@code isAdmin} field on the input is
     * deliberately overwritten to {@code false} — admin roles are seeded
     * by {@link RbacRepository#seedAdministratorPermissions}, not by REST.
     *
     * @param role the role to create; {@code id} is ignored
     * @return a defensive copy with the assigned id
     * @throws MirthApiException with {@link Status#BAD_REQUEST} for input
     *                           validation failures, {@link Status#CONFLICT}
     *                           if the name is taken
     */
    Role create(Role role) {
        validateInput(role);
        role.setAdmin(false);
        if (repo.findRoleIdByName(role.getName()) != null) {
            throw conflict("A role named '" + role.getName() + "' already exists");
        }
        Role created = repo.createRole(role);
        cacheInvalidator.run();
        auditLog.role("Created", created.getName());
        return created;
    }

    /**
     * Updates an existing role.
     *
     * @param roleId id of the role to update
     * @param role   new state; id field is ignored
     * @throws MirthApiException with {@link Status#NOT_FOUND} if the role
     *                           doesn't exist, {@link Status#CONFLICT} if
     *                           the rename targets a name already owned
     *                           by another role, {@link Status#BAD_REQUEST}
     *                           from {@link AdminRoleGuard#validateRoleUpdate}
     *                           or input validation
     */
    void update(int roleId, Role role) {
        validateInput(role);
        Role existing = repo.getRoleById(roleId);
        if (existing == null) {
            throw new MirthApiException(Status.NOT_FOUND);
        }
        if (!existing.getName().equals(role.getName())) {
            Integer otherId = repo.findRoleIdByName(role.getName());
            if (otherId != null && otherId != roleId) {
                throw conflict("A role named '" + role.getName() + "' already exists");
            }
        }
        adminGuard.validateRoleUpdate(roleId, role);
        repo.updateRole(roleId, role);
        cacheInvalidator.run();
        auditLog.role("Updated", role.getName());
    }

    /**
     * Deletes a role.
     *
     * @param roleId id of the role to delete
     * @throws MirthApiException with {@link Status#NOT_FOUND} if the role
     *                           doesn't exist, {@link Status#BAD_REQUEST}
     *                           if it's the admin role
     */
    void delete(int roleId) {
        Role existing = repo.getRoleById(roleId);
        if (existing == null) {
            throw new MirthApiException(Status.NOT_FOUND);
        }
        adminGuard.validateRoleDeletion(roleId);
        repo.deleteRole(roleId);
        cacheInvalidator.run();
        auditLog.role("Deleted", existing.getName());
    }

    /**
     * @param userId user to look up
     * @return the user's role, or {@code null} if no assignment exists
     */
    Role getUserRole(int userId) {
        return repo.getUserRole(userId);
    }

    /**
     * Computes the effective permission set for the current user, mirroring the
     * client-visible {@code getMyPermissions} contract: an admin-role holder gets
     * the full catalog (supplied lazily, since it depends on the live auth
     * controller), a non-admin gets exactly their role's grants, and a user with
     * no role — or a role with a null permission set — gets an empty set.
     *
     * @param userId                  the current user's id
     * @param allPermissionsSupplier  supplies the full core+extension catalog for admins
     * @return the effective permission set (never {@code null})
     */
    Set<String> effectivePermissions(int userId, Supplier<Set<String>> allPermissionsSupplier) {
        Role role = repo.getUserRole(userId);
        if (role != null && role.isAdmin()) {
            return allPermissionsSupplier.get();
        }
        if (role != null && role.getPermissions() != null) {
            return role.getPermissions();
        }
        return new LinkedHashSet<>();
    }

    /**
     * Assigns a role to a user, replacing any prior assignment.
     *
     * @param userId user receiving the assignment
     * @param roleId role to assign
     * @throws MirthApiException with {@link Status#NOT_FOUND} if the role
     *                           doesn't exist, {@link Status#BAD_REQUEST}
     *                           from {@link AdminRoleGuard#validateUserRoleAssignment}
     */
    void assignUserRole(int userId, int roleId) {
        if (repo.getRoleById(roleId) == null) {
            throw new MirthApiException(Status.NOT_FOUND);
        }
        adminGuard.validateUserRoleAssignment(userId, roleId);
        repo.assignUserRole(userId, roleId);
        cacheInvalidator.run();
        auditLog.assignment("Assigned", userId, roleId);
    }

    /**
     * Removes a user's role assignment. Idempotent — a user with no
     * assignment is not a 404 (no operation needed).
     *
     * @param userId user whose assignment is being cleared
     * @throws MirthApiException with {@link Status#BAD_REQUEST} from
     *                           {@link AdminRoleGuard#validateUserRoleRemoval}
     *                           if removing this user would leave zero admins
     */
    void removeUserRole(int userId) {
        adminGuard.validateUserRoleRemoval(userId);
        repo.removeUserRole(userId);
        cacheInvalidator.run();
        auditLog.assignment("Removed", userId, null);
    }

    private static void validateInput(Role role) {
        if (role == null) {
            throw badRequest("Role is required");
        }
        if (role.getName() == null || role.getName().isBlank()) {
            throw badRequest("Role name is required");
        }
    }

    private static MirthApiException badRequest(String message) {
        return new MirthApiException(Response.status(Status.BAD_REQUEST).entity(message).build());
    }

    private static MirthApiException conflict(String message) {
        return new MirthApiException(Response.status(Status.CONFLICT).entity(message).build());
    }
}
