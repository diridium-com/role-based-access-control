// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.ibatis.session.SqlSession;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

/**
 * Tests the admin-bootstrap decision cascade in {@link AdminRoleSeeder}
 * against a mocked {@link SqlSession}. The seeder runs inside the caller's
 * transaction, so commit/rollback behavior is out of scope here (owned by
 * {@code RbacRepository.seedAdministratorPermissions}).
 */
class AdminRoleSeederTest {

    private static final Set<String> CORE_PERMS = Set.of("permA", "permB");

    private static final String GET_ADMIN_ROLE_ID = "Rbac.getAdminRoleId";
    private static final String GET_USER_ROLE_ID = "Rbac.getUserRoleId";
    private static final String GET_ROLE_ID_BY_NAME = "Rbac.getRoleIdByName";
    private static final String SET_ROLE_IS_ADMIN = "Rbac.setRoleIsAdmin";
    private static final String INSERT_ROLE = "Rbac.insertRole";
    private static final String INSERT_USER_ROLE = "Rbac.insertUserRole";
    private static final String INSERT_PERMISSION = "Rbac.insertPermission";
    private static final String GET_PERMISSIONS_FOR_ROLE = "Rbac.getPermissionsForRole";

    private SqlSession session;
    private AdminRoleSeeder seeder;

    @BeforeEach
    void setUp() {
        session = mock(SqlSession.class);
        seeder = new AdminRoleSeeder(() -> CORE_PERMS);
    }

    // ========== Discovery cascade ==========

    @Test
    void flaggedRoleExists_usedAsIs_noBackfillNoCreate() {
        givenFlaggedAdminRole(5);
        givenUserRole(1, 5);
        givenRolePermissions(5, "permA", "permB");

        seeder.seed(session, List.of(1));

        verify(session, never()).update(eq(SET_ROLE_IS_ADMIN), any());
        verify(session, never()).insert(eq(INSERT_ROLE), any());
        verify(session, never()).insert(eq(INSERT_USER_ROLE), any());
        verify(session, never()).insert(eq(INSERT_PERMISSION), any());
    }

    @Test
    void noFlag_userOnesRoleExists_flagBackfilled() {
        givenUserRole(1, 7);
        givenRolePermissions(7, "permA", "permB");

        seeder.seed(session, List.of(1));

        ArgumentCaptor<Map<String, Object>> captor = mapCaptor();
        verify(session).update(eq(SET_ROLE_IS_ADMIN), captor.capture());
        assertEquals(7, captor.getValue().get("id"));
        assertEquals(true, captor.getValue().get("isAdmin"));
        // Not a fresh install: no role created, no mass assignment
        verify(session, never()).insert(eq(INSERT_ROLE), any());
        verify(session, never()).insert(eq(INSERT_USER_ROLE), any());
    }

    @Test
    void noFlag_noUserOneRole_administratorNameExists_flagBackfilledAndUserOneAssigned() {
        when(session.selectOne(eq(GET_ROLE_ID_BY_NAME), eq("Administrator"))).thenReturn(9);
        givenRolePermissions(9, "permA", "permB");

        seeder.seed(session, List.of());

        ArgumentCaptor<Map<String, Object>> flagCaptor = mapCaptor();
        verify(session).update(eq(SET_ROLE_IS_ADMIN), flagCaptor.capture());
        assertEquals(9, flagCaptor.getValue().get("id"));

        // Upgrade path with user 1 roleless: the floor assigns user 1
        ArgumentCaptor<Map<String, Object>> assignCaptor = mapCaptor();
        verify(session).insert(eq(INSERT_USER_ROLE), assignCaptor.capture());
        assertEquals(1, assignCaptor.getValue().get("userId"));
        assertEquals(9, assignCaptor.getValue().get("roleId"));
    }

    @Test
    void freshInstall_createsAdminRole_assignsAllUnassignedUsers() {
        givenInsertRoleAssignsId(42);
        givenUserRole(2, 8); // user 2 already holds a role; must be left alone
        givenRolePermissions(42); // brand-new role: no permissions yet

        seeder.seed(session, Arrays.asList(1, 2, 3));

        ArgumentCaptor<Map<String, Object>> roleCaptor = mapCaptor();
        verify(session).insert(eq(INSERT_ROLE), roleCaptor.capture());
        assertEquals("Administrator", roleCaptor.getValue().get("name"));
        assertEquals(Boolean.TRUE, roleCaptor.getValue().get("isAdmin"));

        List<Integer> assignedUsers = capturedUserAssignments(42);
        assertEquals(List.of(1, 3), assignedUsers.stream().sorted().toList(),
                "users 1 and 3 assigned; user 2 already had a role");

        List<String> seededPerms = capturedPermissionInserts(42);
        assertEquals(List.of("permA", "permB"), seededPerms.stream().sorted().toList());
    }

    @Test
    void freshInstall_nullUserList_userOneStillFloored() {
        givenInsertRoleAssignsId(42);
        givenRolePermissions(42);

        seeder.seed(session, null);

        assertEquals(List.of(1), capturedUserAssignments(42));
    }

    @Test
    void freshInstall_nullUserIdInList_skippedWithoutError() {
        givenInsertRoleAssignsId(42);
        givenRolePermissions(42);

        assertDoesNotThrow(() -> seeder.seed(session, Arrays.asList(1, null, 3)));

        assertEquals(List.of(1, 3), capturedUserAssignments(42).stream().sorted().toList());
    }

    @Test
    void freshInstall_oneUserAssignmentFails_othersStillAssigned() {
        givenInsertRoleAssignsId(42);
        givenRolePermissions(42);
        when(session.insert(eq(INSERT_USER_ROLE), any())).thenAnswer(inv -> {
            Map<String, Object> params = inv.getArgument(1);
            if (Integer.valueOf(2).equals(params.get("userId"))) {
                throw new RuntimeException("constraint violation for user 2");
            }
            return 1;
        });

        assertDoesNotThrow(() -> seeder.seed(session, Arrays.asList(1, 2, 3)));

        // All three were attempted; 2 failed but did not abort 1 and 3
        ArgumentCaptor<Map<String, Object>> captor = mapCaptor();
        verify(session, times(3)).insert(eq(INSERT_USER_ROLE), captor.capture());
    }

    @Test
    void freshInstall_insertRoleYieldsNoId_seedAbortsQuietly() {
        // insertRole runs but the driver writes no generated key back
        assertDoesNotThrow(() -> seeder.seed(session, List.of(1)));

        verify(session, never()).insert(eq(INSERT_USER_ROLE), any());
        verify(session, never()).insert(eq(INSERT_PERMISSION), any());
        verify(session, never()).selectList(eq(GET_PERMISSIONS_FOR_ROLE), any());
    }

    // ========== Permission backfill ==========

    @Test
    void permissionBackfill_addsOnlyMissingPermissions() {
        givenFlaggedAdminRole(5);
        givenUserRole(1, 5);
        givenRolePermissions(5, "permA"); // permB missing

        seeder.seed(session, List.of(1));

        assertEquals(List.of("permB"), capturedPermissionInserts(5));
    }

    // ========== Upgrade-path floor ==========

    @Test
    void upgradePath_userOneAssignmentFails_swallowedNotPropagated() {
        givenFlaggedAdminRole(5);
        givenRolePermissions(5, "permA", "permB");
        // user 1 has no role; the floor insert blows up (e.g., phantom user weirdness)
        when(session.insert(eq(INSERT_USER_ROLE), any())).thenThrow(new RuntimeException("boom"));

        assertDoesNotThrow(() -> seeder.seed(session, List.of(1)));
    }

    @Test
    void upgradePath_userOneAlreadyAssignedElsewhere_leftAlone() {
        givenFlaggedAdminRole(5);
        givenUserRole(1, 3); // operator moved user 1 to a non-admin role on purpose
        givenRolePermissions(5, "permA", "permB");

        seeder.seed(session, List.of(1));

        verify(session, never()).insert(eq(INSERT_USER_ROLE), any());
    }

    // ========== Idempotency ==========

    @Test
    void steadyState_rerunProducesZeroWrites() {
        givenFlaggedAdminRole(5);
        givenUserRole(1, 5);
        givenRolePermissions(5, "permA", "permB");

        seeder.seed(session, List.of(1));

        verify(session, never()).insert(anyString(), any());
        verify(session, never()).update(anyString(), any());
    }

    // ========== Helpers ==========

    private void givenFlaggedAdminRole(int roleId) {
        when(session.selectOne(eq(GET_ADMIN_ROLE_ID), any())).thenReturn(roleId);
    }

    private void givenUserRole(int userId, int roleId) {
        when(session.selectOne(eq(GET_USER_ROLE_ID), eq(userId))).thenReturn(roleId);
    }

    private void givenRolePermissions(int roleId, String... perms) {
        when(session.<String>selectList(eq(GET_PERMISSIONS_FOR_ROLE), eq(roleId)))
                .thenReturn(Arrays.asList(perms));
    }

    private void givenInsertRoleAssignsId(int id) {
        when(session.insert(eq(INSERT_ROLE), any())).thenAnswer(inv -> {
            Map<String, Object> params = inv.getArgument(1);
            params.put("id", id);
            return 1;
        });
    }

    private List<Integer> capturedUserAssignments(int expectedRoleId) {
        ArgumentCaptor<Map<String, Object>> captor = mapCaptor();
        verify(session, atLeast(0)).insert(eq(INSERT_USER_ROLE), captor.capture());
        List<Integer> userIds = new ArrayList<>();
        for (Map<String, Object> params : captor.getAllValues()) {
            assertEquals(expectedRoleId, params.get("roleId"));
            userIds.add((Integer) params.get("userId"));
        }
        return userIds;
    }

    private List<String> capturedPermissionInserts(int expectedRoleId) {
        ArgumentCaptor<Map<String, Object>> captor = mapCaptor();
        verify(session, atLeast(0)).insert(eq(INSERT_PERMISSION), captor.capture());
        List<String> perms = new ArrayList<>();
        for (Map<String, Object> params : captor.getAllValues()) {
            assertEquals(expectedRoleId, params.get("roleId"));
            perms.add((String) params.get("permission"));
        }
        return perms;
    }

    @SuppressWarnings("unchecked")
    private static ArgumentCaptor<Map<String, Object>> mapCaptor() {
        return ArgumentCaptor.forClass((Class<Map<String, Object>>) (Class<?>) Map.class);
    }
}
