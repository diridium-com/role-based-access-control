// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.ibatis.session.SqlSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.mirth.connect.server.util.SqlConfig;

/**
 * Persistence for roles, role-permission grants, role-channel restrictions,
 * and user-role assignments.
 *
 * <p>Single-statement reads use {@code SqlConfig.getInstance().getSqlSessionManager()}
 * directly. Multi-statement writes follow the engine's transaction pattern
 * (see {@code DefaultUserController.vacuumPersonTable}): open a manual-commit
 * session, run all statements, commit, close in a finally. An uncommitted
 * session rolls back automatically on close.</p>
 */
public class RbacRepository {

    private static final String NAMESPACE = "Rbac";

    // volatile: init()/close() write under synchronization, but getInstance()
    // reads without it, so the field needs volatile for safe publication.
    private static volatile RbacRepository instance;
    private static final Logger log = LoggerFactory.getLogger(RbacRepository.class);

    private RbacRepository() {
    }

    /**
     * Initializes the singleton instance and runs the admin role seeder.
     * Called once from {@code RbacServicePlugin.start} during plugin startup.
     * Idempotent — subsequent calls are no-ops.
     *
     * @param allUserIds ids of every user currently known to the engine. On a
     *                   fresh install these are all assigned to the admin role
     *                   (they were effectively admins under OIE's default
     *                   allow-all controller); ignored on upgrades/restarts.
     *                   May be empty if the list could not be gathered — user 1
     *                   is always seeded as a floor regardless.
     */
    public static synchronized void init(List<Integer> allUserIds) {
        if (instance == null) {
            instance = new RbacRepository();
            instance.seedAdministratorPermissions(allUserIds);
            log.info("RbacRepository initialized");
        }
    }

    /**
     * @return the singleton repository instance
     * @throws IllegalStateException if {@link #init(java.util.List)} has not been called yet
     */
    public static RbacRepository getInstance() {
        if (instance == null) {
            throw new IllegalStateException("RbacRepository not initialized, call init() first");
        }
        return instance;
    }

    /**
     * Tears down the singleton instance. Called from {@code RbacServicePlugin.stop}
     * during plugin shutdown so a subsequent {@link #init(java.util.List)} starts fresh.
     */
    public static synchronized void close() {
        instance = null;
    }

    /** Qualifies a mapped-statement id with the plugin's MyBatis namespace. */
    static String stmt(String id) {
        return NAMESPACE + "." + id;
    }

    // ========== Role CRUD ==========

    /**
     * @return every role in the database, in id order, fully populated with
     *         its permission and channel-id sets
     * @throws RbacRepositoryException on persistence failure
     */
    public List<Role> getAllRoles() {
        try {
            List<Map<String, Object>> results = SqlConfig.getInstance().getSqlSessionManager()
                    .selectList(stmt("getAllRoles"));

            List<Role> roles = new ArrayList<>();
            for (Map<String, Object> row : results) {
                roles.add(buildRole(row));
            }
            return roles;
        } catch (Exception e) {
            log.error("Failed to get all roles", e);
            throw new RbacRepositoryException(e);
        }
    }

    /**
     * Fetches one role by its database id.
     *
     * @param roleId database id to look up
     * @return the role with its permissions and channel ids, or {@code null}
     *         if no row exists
     * @throws RbacRepositoryException on persistence failure
     */
    public Role getRoleById(int roleId) {
        try {
            Map<String, Object> row = SqlConfig.getInstance().getSqlSessionManager()
                    .selectOne(stmt("getRoleById"), roleId);

            if (row == null) {
                return null;
            }
            return buildRole(row);
        } catch (Exception e) {
            log.error("Failed to get role {}", roleId, e);
            throw new RbacRepositoryException(e);
        }
    }

    /**
     * Inserts a new role with its permissions and channel restrictions, all
     * within a single transaction so a mid-flight failure leaves the database
     * in its pre-call state.
     *
     * @param role the role to create; the {@code id} field is ignored (the
     *             database assigns it) and {@code isAdmin} is persisted
     *             as-given (the servlet layer forces it to {@code false} for
     *             REST-driven creates)
     * @return a defensive copy of the input with the newly assigned {@code id};
     *         the caller's input object is not mutated
     * @throws RbacRepositoryException on persistence failure including
     *                                 unique-name violations
     */
    public Role createRole(Role role) {
        SqlSession session = null;
        try {
            session = SqlConfig.getInstance().getSqlSessionManager().openSession(false);

            Map<String, Object> params = new HashMap<>();
            params.put("name", role.getName());
            params.put("description", role.getDescription());
            params.put("isAdmin", role.isAdmin());
            // useGeneratedKeys writes the assigned id back into params["id"]
            session.insert(stmt("insertRole"), params);
            Integer roleId = toInteger(params.get("id"));

            savePermissionsForRole(session, roleId, role.getPermissions());
            saveChannelIdsForRole(session, roleId, role.getChannelIds());

            session.commit();

            // Return a defensive copy with the assigned id; do not mutate caller's input.
            Role created = role.copy();
            created.setId(roleId);
            return created;
        } catch (Exception e) {
            log.error("Failed to create role {}", role.getName(), e);
            throw new RbacRepositoryException(e);
        } finally {
            if (session != null) {
                session.close();
            }
        }
    }

    /**
     * Updates a role's name, description, permissions, and channel restrictions
     * within a single transaction. The {@code is_admin} flag is deliberately
     * not touched — once seeded it remains immutable from this surface.
     *
     * @param roleId database id of the role to update
     * @param role   new state for the role (id field on the object is ignored)
     * @throws RbacRepositoryException on persistence failure
     */
    public void updateRole(int roleId, Role role) {
        SqlSession session = null;
        try {
            session = SqlConfig.getInstance().getSqlSessionManager().openSession(false);

            // Note: we deliberately do NOT update is_admin here. The flag is set once
            // by the seeder and stays put — the REST/UI surface never edits it.
            Map<String, Object> params = new HashMap<>();
            params.put("id", roleId);
            params.put("name", role.getName());
            params.put("description", role.getDescription());
            session.update(stmt("updateRole"), params);

            savePermissionsForRole(session, roleId, role.getPermissions());
            saveChannelIdsForRole(session, roleId, role.getChannelIds());

            session.commit();
        } catch (Exception e) {
            log.error("Failed to update role {}", roleId, e);
            throw new RbacRepositoryException(e);
        } finally {
            if (session != null) {
                session.close();
            }
        }
    }

    /**
     * Deletes a role by id. FK cascades on {@code rbac_role_permission},
     * {@code rbac_role_channel}, and {@code rbac_user_role} clear the
     * dependent rows automatically. The admin-role check lives at the
     * servlet boundary, not here.
     *
     * @param roleId database id of the role to delete
     * @throws RbacRepositoryException on persistence failure
     */
    public void deleteRole(int roleId) {
        // Single statement (FK cascade handles child rows); auto-commit is fine.
        try {
            SqlConfig.getInstance().getSqlSessionManager().delete(stmt("deleteRole"), roleId);
        } catch (Exception e) {
            log.error("Failed to delete role {}", roleId, e);
            throw new RbacRepositoryException(e);
        }
    }

    /**
     * Looks up a role's id by its unique name. Used by the servlet for
     * duplicate-name conflict detection without loading every role.
     *
     * @param name the role name to look up
     * @return the role id, or {@code null} if no role has that name
     * @throws RbacRepositoryException on persistence failure
     */
    public Integer findRoleIdByName(String name) {
        try {
            return SqlConfig.getInstance().getSqlSessionManager()
                    .selectOne(stmt("getRoleIdByName"), name);
        } catch (Exception e) {
            log.error("Failed to look up role by name '{}'", name, e);
            throw new RbacRepositoryException(e);
        }
    }

    // ========== Admin Role Identification ==========

    /**
     * @return the id of the role flagged is_admin=true, or null if none exists.
     */
    public Integer getAdminRoleId() {
        try {
            Map<String, Object> params = new HashMap<>();
            params.put("flag", Boolean.TRUE);
            return SqlConfig.getInstance().getSqlSessionManager()
                    .selectOne(stmt("getAdminRoleId"), params);
        } catch (Exception e) {
            log.error("Failed to get admin role id", e);
            throw new RbacRepositoryException(e);
        }
    }

    /**
     * @return the number of users assigned to the given role.
     */
    public int countUsersByRoleId(int roleId) {
        try {
            Integer count = SqlConfig.getInstance().getSqlSessionManager()
                    .selectOne(stmt("countUsersByRoleId"), roleId);
            return count != null ? count : 0;
        } catch (Exception e) {
            log.error("Failed to count users for role {}", roleId, e);
            throw new RbacRepositoryException(e);
        }
    }

    // ========== User-Role Assignment ==========

    /**
     * Convenience method: looks up a user's role id and fetches the full
     * role record.
     *
     * @param userId engine user id to look up
     * @return the role currently assigned to that user, or {@code null} if
     *         the user has no assignment
     * @throws RbacRepositoryException on persistence failure
     */
    public Role getUserRole(int userId) {
        // getUserRoleId and getRoleById already log + wrap failures, so let an
        // RbacRepositoryException from either pass straight through rather than
        // logging and wrapping it a second time.
        try {
            Integer roleId = getUserRoleId(userId);
            if (roleId == null) {
                return null;
            }
            return getRoleById(roleId);
        } catch (RbacRepositoryException e) {
            throw e;
        } catch (Exception e) {
            log.error("Failed to get role for user {}", userId, e);
            throw new RbacRepositoryException(e);
        }
    }

    /**
     * Returns just the role id assigned to a user without fetching the full
     * role record. Faster than {@link #getUserRole(int)} when the caller
     * only needs the id (e.g., comparing against the admin role id).
     *
     * @param userId engine user id to look up
     * @return the assigned role id, or {@code null} if the user has no role
     * @throws RbacRepositoryException on persistence failure
     */
    public Integer getUserRoleId(int userId) {
        try {
            return SqlConfig.getInstance().getSqlSessionManager()
                    .selectOne(stmt("getUserRoleId"), userId);
        } catch (Exception e) {
            log.error("Failed to get role ID for user {}", userId, e);
            throw new RbacRepositoryException(e);
        }
    }

    /**
     * Assigns a role to a user, replacing any prior assignment, atomically.
     * The delete + insert pair runs inside a transaction so a crash between
     * them leaves the user with their previous role rather than no role.
     *
     * @param userId engine user id receiving the assignment
     * @param roleId role id to assign
     * @throws RbacRepositoryException on persistence failure
     */
    public void assignUserRole(int userId, int roleId) {
        SqlSession session = null;
        try {
            session = SqlConfig.getInstance().getSqlSessionManager().openSession(false);
            session.delete(stmt("deleteUserRole"), userId);

            Map<String, Object> params = new HashMap<>();
            params.put("userId", userId);
            params.put("roleId", roleId);
            session.insert(stmt("insertUserRole"), params);

            session.commit();
        } catch (Exception e) {
            log.error("Failed to assign role {} to user {}", roleId, userId, e);
            throw new RbacRepositoryException(e);
        }  finally {
            if (session != null) {
                session.close();
            }
        }
    }

    /**
     * Deletes assignment rows whose user no longer exists in the engine PERSON
     * table. The engine deletes users without notifying RBAC ({@code rbac_user_role}
     * has no FK to PERSON and there is no deletion hook), so orphaned rows
     * accumulate. Run once at plugin startup. Idempotent — deletes zero rows in
     * steady state.
     *
     * <p>A sweep failure is non-fatal: the stale rows are latent (engine user ids
     * are auto-increment and not reused) and the admin-floor count already excludes
     * them, so plugin startup must not depend on this succeeding.</p>
     *
     * @return the number of orphaned rows removed (0 on failure)
     */
    public static int deleteOrphanUserRoles() {
        try {
            int removed = SqlConfig.getInstance().getSqlSessionManager()
                    .delete(stmt("deleteOrphanUserRoles"));
            if (removed > 0) {
                log.info("RBAC: removed {} orphaned user-role assignment(s) for deleted users", removed);
            }
            return removed;
        } catch (Exception e) {
            log.warn("RBAC: orphan user-role sweep failed (non-fatal): {}", e.getMessage());
            return 0;
        }
    }

    /**
     * Removes a user's role assignment entirely. The admin-floor check lives
     * at the servlet boundary, not here.
     *
     * @param userId engine user id whose assignment is being cleared
     * @throws RbacRepositoryException on persistence failure
     */
    public void removeUserRole(int userId) {
        // Single statement; auto-commit is fine.
        try {
            SqlConfig.getInstance().getSqlSessionManager().delete(stmt("deleteUserRole"), userId);
        } catch (Exception e) {
            log.error("Failed to remove role from user {}", userId, e);
            throw new RbacRepositoryException(e);
        }
    }

    // ========== Permission and Channel Helpers ==========

    private Set<String> getPermissionsForRole(int roleId) {
        try {
            List<String> results = SqlConfig.getInstance().getSqlSessionManager()
                    .selectList(stmt("getPermissionsForRole"), roleId);
            return new HashSet<>(results);
        } catch (Exception e) {
            log.error("Failed to get permissions for role {}", roleId, e);
            throw new RbacRepositoryException(e);
        }
    }

    private Set<String> getChannelIdsForRole(int roleId) {
        try {
            List<String> results = SqlConfig.getInstance().getSqlSessionManager()
                    .selectList(stmt("getChannelIdsForRole"), roleId);
            Set<String> channelIds = new HashSet<>();
            for (String id : results) {
                channelIds.add(id.trim());
            }
            return channelIds;
        } catch (Exception e) {
            log.error("Failed to get channel IDs for role {}", roleId, e);
            throw new RbacRepositoryException(e);
        }
    }

    /**
     * Replaces all permission grants for a role within the caller's transaction.
     * Caller owns commit/rollback.
     */
    private void savePermissionsForRole(SqlSession session, int roleId, Set<String> permissions) {
        session.delete(stmt("deletePermissionsForRole"), roleId);

        if (permissions != null && !permissions.isEmpty()) {
            for (String permission : permissions) {
                Map<String, Object> params = new HashMap<>();
                params.put("roleId", roleId);
                params.put("permission", permission);
                session.insert(stmt("insertPermission"), params);
            }
        }
    }

    /**
     * Replaces all channel restrictions for a role within the caller's transaction.
     * Caller owns commit/rollback.
     */
    private void saveChannelIdsForRole(SqlSession session, int roleId, Set<String> channelIds) {
        session.delete(stmt("deleteChannelIdsForRole"), roleId);

        if (channelIds != null && !channelIds.isEmpty()) {
            for (String channelId : channelIds) {
                Map<String, Object> params = new HashMap<>();
                params.put("roleId", roleId);
                params.put("channelId", channelId);
                session.insert(stmt("insertChannelId"), params);
            }
        }
    }

    // ========== Role Builder ==========

    private Role buildRole(Map<String, Object> row) {
        Role role = new Role();
        role.setId(toInteger(row.get("id")));
        role.setName((String) row.get("name"));
        role.setDescription((String) row.get("description"));
        role.setPermissions(getPermissionsForRole(role.getId()));
        role.setChannelIds(getChannelIdsForRole(role.getId()));
        role.setAdmin(toBoolean(row.get("isAdmin")));
        return role;
    }

    /**
     * Coerce a boolean-ish DB value to a Java boolean. Different JDBC drivers
     * return different types for boolean columns (Boolean for Postgres/Derby/MySQL,
     * Number for Oracle/SQL Server).
     */
    private static boolean toBoolean(Object value) {
        if (value == null) return false;
        if (value instanceof Boolean b) return b;
        if (value instanceof Number n) return n.intValue() != 0;
        return false;
    }

    /**
     * Coerces a MyBatis-returned key or id to an {@link Integer}. Most drivers
     * return an {@code Integer}, but Derby hands back identity/generated keys as
     * a {@link java.math.BigDecimal}, so a direct {@code (Integer)} cast throws
     * {@link ClassCastException}. Handles any {@link Number}.
     *
     * @param value the raw value from a params map or result row
     * @return the value as an {@code Integer}, or {@code null} if it is null
     */
    static Integer toInteger(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof Integer i) {
            return i;
        }
        if (value instanceof Number n) {
            return n.intValue();
        }
        return Integer.valueOf(value.toString().trim());
    }

    // ========== Administrator Role Seeding ==========

    /**
     * Runs the admin-role seed inside a single transaction. The discovery
     * cascade, assignment rules, and permission backfill live in
     * {@link AdminRoleSeeder}; this method owns the session lifecycle.
     *
     * <p>A seed failure leaves a fresh install with no admin role and no
     * assignments: every user is denied, and nobody holds Manage Roles to
     * repair it over REST. That is the same broken-bootstrap class as a failed
     * migration, so we mark {@link MigrationStatus} failed — the servlet then
     * returns a clear "plugin disabled, check logs and restart" error instead
     * of leaving the operator staring at unexplained 403s. A restart re-runs
     * {@link #init} and re-attempts the seed.</p>
     *
     * @param allUserIds ids of every engine user, used only on fresh install;
     *                   may be empty (user 1 is floored regardless)
     */
    private void seedAdministratorPermissions(List<Integer> allUserIds) {
        SqlSession session = null;
        try {
            session = SqlConfig.getInstance().getSqlSessionManager().openSession(false);
            new AdminRoleSeeder(PermissionUtil::getAllCorePermissions).seed(session, allUserIds);
            session.commit();
        } catch (Exception e) {
            log.error("Failed to seed admin permissions; RBAC bootstrap is incomplete: {}", e.getMessage(), e);
            MigrationStatus.markFailed("admin role seeding failed: " + e.getMessage());
        } finally {
            if (session != null) {
                session.close();
            }
        }
    }
}
