// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;

import org.apache.ibatis.session.SqlSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static com.diridium.rbac.RbacRepository.stmt;

/**
 * Establishes the admin role and its assignments at plugin startup.
 *
 * <p>Extracted from {@link RbacRepository} so the bootstrap decision cascade
 * can be unit-tested against a mocked {@link SqlSession}. The repository
 * owns the session lifecycle (open / commit / close); this class runs
 * entirely inside the caller's transaction.</p>
 *
 * <p>Admin-role discovery, in order:</p>
 * <ol>
 *   <li>A role already flagged {@code is_admin=true} — use it as-is</li>
 *   <li>The role assigned to user 1 — flag it as admin (upgrade from
 *       pre-flag plugin versions)</li>
 *   <li>A role named "Administrator" — flag it as admin (upgrade from
 *       name-based versions)</li>
 *   <li>None of the above — fresh install: create a new "Administrator" role</li>
 * </ol>
 *
 * <p>On a fresh install (case 4) every existing engine user is assigned to
 * the new admin role: under OIE's default allow-all controller they were
 * all effectively admins, and dropping them to no-role would lock them out.
 * On upgrades/restarts (cases 1–3) only user 1 is ensured, leaving the
 * operator's existing assignments untouched.</p>
 */
class AdminRoleSeeder {

    static final int BOOTSTRAP_ADMIN_USER_ID = 1;
    static final String BOOTSTRAP_ADMIN_ROLE_NAME = "Administrator";
    static final String BOOTSTRAP_ADMIN_ROLE_DESCRIPTION =
            "Full access to all operations and channels";

    private static final Logger log = LoggerFactory.getLogger(AdminRoleSeeder.class);

    private final Supplier<Set<String>> corePermissionsSupplier;

    /**
     * @param corePermissionsSupplier returns every core permission the admin
     *                                role must hold; production passes
     *                                {@code PermissionUtil::getAllCorePermissions},
     *                                tests pass a fixed set
     */
    AdminRoleSeeder(Supplier<Set<String>> corePermissionsSupplier) {
        this.corePermissionsSupplier = corePermissionsSupplier;
    }

    /**
     * Ensures the plugin has a designated admin role with full permissions,
     * and that the right users are assigned to it. Idempotent.
     *
     * @param session    the caller's manual-commit session; the caller owns
     *                   commit/rollback/close
     * @param allUserIds ids of every engine user, used only on fresh install;
     *                   may be {@code null} or empty (user 1 is floored
     *                   regardless)
     */
    void seed(SqlSession session, List<Integer> allUserIds) {
        Integer adminRoleId = findExistingAdminRole(session);
        boolean freshInstall = (adminRoleId == null);
        if (freshInstall) {
            adminRoleId = createAdminRole(session);
        }
        if (adminRoleId == null) {
            log.warn("Could not establish an admin role; skipping seed");
            return;
        }

        if (freshInstall) {
            assignUsersToAdminRole(session, adminRoleId, allUserIds);
        } else {
            ensureUserOneAssignedIfPossible(session, adminRoleId);
        }
        seedMissingCorePermissions(session, adminRoleId);
    }

    /**
     * Locates an already-established admin role: one flagged {@code is_admin},
     * or (for upgrades from pre-flag versions) user 1's role or a role named
     * "Administrator", backfilling the flag in those two cases.
     *
     * @return the admin role id, or {@code null} if none exists yet — a fresh
     *         install, where the caller should create one
     */
    private Integer findExistingAdminRole(SqlSession session) {
        // 1. Existing role flagged is_admin
        Map<String, Object> flagParams = new HashMap<>();
        flagParams.put("flag", Boolean.TRUE);
        Integer adminRoleId = session.selectOne(stmt("getAdminRoleId"), flagParams);
        if (adminRoleId != null) {
            return adminRoleId;
        }

        // 2. Backfill: role assigned to user 1
        adminRoleId = session.selectOne(stmt("getUserRoleId"), BOOTSTRAP_ADMIN_USER_ID);
        if (adminRoleId != null) {
            log.info("Backfilling is_admin flag onto user 1's existing role (id={})", adminRoleId);
            setRoleIsAdmin(session, adminRoleId, true);
            return adminRoleId;
        }

        // 3. Legacy: role named "Administrator" (from prior plugin versions that seeded by name)
        adminRoleId = session.selectOne(stmt("getRoleIdByName"), BOOTSTRAP_ADMIN_ROLE_NAME);
        if (adminRoleId != null) {
            log.info("Backfilling is_admin flag onto pre-existing '{}' role (id={})",
                    BOOTSTRAP_ADMIN_ROLE_NAME, adminRoleId);
            setRoleIsAdmin(session, adminRoleId, true);
            return adminRoleId;
        }

        return null;
    }

    /**
     * Creates the bootstrap admin role flagged {@code is_admin=true}. Called
     * only on a fresh install, when {@link #findExistingAdminRole} found none.
     *
     * @return the new role's id
     */
    private Integer createAdminRole(SqlSession session) {
        Map<String, Object> params = new HashMap<>();
        params.put("name", BOOTSTRAP_ADMIN_ROLE_NAME);
        params.put("description", BOOTSTRAP_ADMIN_ROLE_DESCRIPTION);
        params.put("isAdmin", Boolean.TRUE);
        session.insert(stmt("insertRole"), params);

        Integer adminRoleId = RbacRepository.toInteger(params.get("id"));
        log.info("Created admin role (id={}, name='{}')", adminRoleId, BOOTSTRAP_ADMIN_ROLE_NAME);
        return adminRoleId;
    }

    /**
     * Assigns the admin role to every supplied user on first install, preserving
     * the access they had under OIE's default allow-all controller. User 1 is
     * always included as a floor even if the engine user list was empty. Users
     * that somehow already hold an assignment are left alone, and a failure to
     * assign one user is logged and skipped rather than aborting the seed.
     *
     * @param adminRoleId the freshly created admin role id
     * @param allUserIds  ids of every engine user; may be {@code null} or empty
     */
    private void assignUsersToAdminRole(SqlSession session, int adminRoleId, List<Integer> allUserIds) {
        Set<Integer> userIds = new HashSet<>();
        userIds.add(BOOTSTRAP_ADMIN_USER_ID); // always floor user 1
        if (allUserIds != null) {
            userIds.addAll(allUserIds);
        }

        int assigned = 0;
        for (Integer userId : userIds) {
            if (userId == null) {
                continue;
            }
            Integer existing = session.selectOne(stmt("getUserRoleId"), userId);
            if (existing != null) {
                continue; // already assigned; leave it
            }
            try {
                Map<String, Object> params = new HashMap<>();
                params.put("userId", userId);
                params.put("roleId", adminRoleId);
                session.insert(stmt("insertUserRole"), params);
                assigned++;
            } catch (Exception e) {
                log.warn("Could not assign admin role to user {} during first-install seed: {}",
                        userId, e.getMessage());
            }
        }
        log.info("First install: assigned the admin role to {} user(s)", assigned);
    }

    private void ensureUserOneAssignedIfPossible(SqlSession session, int adminRoleId) {
        Integer userOneRole = session.selectOne(stmt("getUserRoleId"), BOOTSTRAP_ADMIN_USER_ID);
        if (userOneRole != null) {
            return; // Already assigned (to the admin role or not — operator's choice from here)
        }

        // No role assigned to user 1 yet. Try to assign. If user 1 doesn't exist in the
        // engine's person table the FK isn't enforced (rbac_user_role has no FK to person),
        // so the insert "succeeds" but points to a phantom user. We accept that on the
        // assumption that user 1 exists; if it doesn't, the operator broke the engine and
        // needs to bootstrap manually.
        try {
            Map<String, Object> params = new HashMap<>();
            params.put("userId", BOOTSTRAP_ADMIN_USER_ID);
            params.put("roleId", adminRoleId);
            session.insert(stmt("insertUserRole"), params);
            log.info("Assigned admin role to user ID {} (bootstrap)", BOOTSTRAP_ADMIN_USER_ID);
        } catch (Exception e) {
            log.warn("Could not assign admin role to user {} (perhaps user does not exist in engine?): {}",
                    BOOTSTRAP_ADMIN_USER_ID, e.getMessage());
        }
    }

    private void seedMissingCorePermissions(SqlSession session, int adminRoleId) {
        List<String> existing = session.selectList(stmt("getPermissionsForRole"), adminRoleId);
        Set<String> missing = new HashSet<>(corePermissionsSupplier.get());
        missing.removeAll(new HashSet<>(existing));

        if (missing.isEmpty()) {
            log.debug("Admin role permissions are up to date");
            return;
        }

        log.info("Adding {} permissions to admin role", missing.size());
        for (String perm : missing) {
            Map<String, Object> params = new HashMap<>();
            params.put("roleId", adminRoleId);
            params.put("permission", perm);
            session.insert(stmt("insertPermission"), params);
        }
    }

    private void setRoleIsAdmin(SqlSession session, int roleId, boolean isAdmin) {
        Map<String, Object> params = new HashMap<>();
        params.put("id", roleId);
        params.put("isAdmin", isAdmin);
        session.update(stmt("setRoleIsAdmin"), params);
    }
}
