// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.HashSet;
import java.util.Set;

import com.mirth.connect.client.core.api.MirthApiException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Tests the admin-role invariants: rename is fine (cosmetic), but the role
 * must retain all permissions, must not gain channel restrictions, must not
 * be deleted, and the admin-user floor (at least one admin always assigned)
 * must hold.
 */
class AdminRoleGuardTest {

    private static final int ADMIN_ROLE_ID = 42;
    private static final int OTHER_ROLE_ID = 99;

    private RbacRepository repo;
    private Set<String> requiredPerms;
    private AdminRoleGuard guard;

    @BeforeEach
    void setUp() {
        repo = mock(RbacRepository.class);
        requiredPerms = new HashSet<>(Set.of("viewChannels", "manageChannels", "manageUsers", "View Roles", "Manage Roles"));
        guard = new AdminRoleGuard(repo, () -> requiredPerms);
    }

    // ========== getAdminRoleId ==========

    @Test
    void getAdminRoleId_returnsFlagLookup() {
        when(repo.getAdminRoleId()).thenReturn(ADMIN_ROLE_ID);
        assertEquals(ADMIN_ROLE_ID, guard.getAdminRoleId());
    }

    @Test
    void getAdminRoleId_returnsNullWhenNoAdminRole() {
        when(repo.getAdminRoleId()).thenReturn(null);
        assertNull(guard.getAdminRoleId());
    }

    // ========== validateRoleUpdate ==========

    @Test
    void validateRoleUpdate_nonAdminRole_passes() throws Exception {
        when(repo.getAdminRoleId()).thenReturn(ADMIN_ROLE_ID);
        guard.validateRoleUpdate(OTHER_ROLE_ID, roleWithPerms());
    }

    @Test
    void validateRoleUpdate_adminRoleWithFullPermissions_passes() throws Exception {
        when(repo.getAdminRoleId()).thenReturn(ADMIN_ROLE_ID);
        guard.validateRoleUpdate(ADMIN_ROLE_ID, roleWithPerms(requiredPerms.toArray(new String[0])));
    }

    @Test
    void validateRoleUpdate_adminRoleMissingOnePermission_throws() {
        when(repo.getAdminRoleId()).thenReturn(ADMIN_ROLE_ID);
        Role role = roleWithPerms("viewChannels", "manageChannels", "manageUsers", "View Roles");
        // missing "Manage Roles"
        MirthApiException e = assertThrows(MirthApiException.class,
                () -> guard.validateRoleUpdate(ADMIN_ROLE_ID, role));
        assertTrue(entityText(e).contains("must retain all permissions"));
    }

    @Test
    void validateRoleUpdate_adminRoleWithEmptyPermissions_throws() {
        when(repo.getAdminRoleId()).thenReturn(ADMIN_ROLE_ID);
        assertThrows(MirthApiException.class,
                () -> guard.validateRoleUpdate(ADMIN_ROLE_ID, roleWithPerms()));
    }

    @Test
    void validateRoleUpdate_adminRoleWithNullPermissions_throws() {
        when(repo.getAdminRoleId()).thenReturn(ADMIN_ROLE_ID);
        Role role = new Role();
        role.setPermissions(null);
        assertThrows(MirthApiException.class,
                () -> guard.validateRoleUpdate(ADMIN_ROLE_ID, role));
    }

    @Test
    void validateRoleUpdate_adminRoleWithChannelRestrictions_throws() {
        when(repo.getAdminRoleId()).thenReturn(ADMIN_ROLE_ID);
        Role role = roleWithPerms(requiredPerms.toArray(new String[0]));
        role.setChannelIds(new HashSet<>(Set.of("ch1")));
        MirthApiException e = assertThrows(MirthApiException.class,
                () -> guard.validateRoleUpdate(ADMIN_ROLE_ID, role));
        assertTrue(entityText(e).contains("channel restrictions"));
    }

    @Test
    void validateRoleUpdate_adminRoleRenameOnly_passes() throws Exception {
        // Rename + description edit are cosmetic; permissions intact => fine
        when(repo.getAdminRoleId()).thenReturn(ADMIN_ROLE_ID);
        Role role = roleWithPerms(requiredPerms.toArray(new String[0]));
        role.setName("Platform Owner");
        role.setDescription("Renamed admin role");
        guard.validateRoleUpdate(ADMIN_ROLE_ID, role);
    }

    @Test
    void validateRoleUpdate_noAdminRoleExists_allUpdatesPass() throws Exception {
        when(repo.getAdminRoleId()).thenReturn(null);
        guard.validateRoleUpdate(ADMIN_ROLE_ID, roleWithPerms()); // empty perms — would normally fail
    }

    // ========== validateRoleDeletion ==========

    @Test
    void validateRoleDeletion_nonAdminRole_passes() throws Exception {
        when(repo.getAdminRoleId()).thenReturn(ADMIN_ROLE_ID);
        guard.validateRoleDeletion(OTHER_ROLE_ID);
    }

    @Test
    void validateRoleDeletion_adminRole_throws() {
        when(repo.getAdminRoleId()).thenReturn(ADMIN_ROLE_ID);
        MirthApiException e = assertThrows(MirthApiException.class,
                () -> guard.validateRoleDeletion(ADMIN_ROLE_ID));
        assertTrue(entityText(e).contains("admin role"));
    }

    @Test
    void validateRoleDeletion_noAdminRoleExists_allDeletesPass() throws Exception {
        when(repo.getAdminRoleId()).thenReturn(null);
        guard.validateRoleDeletion(ADMIN_ROLE_ID);
    }

    // ========== validateUserRoleRemoval ==========

    @Test
    void validateUserRoleRemoval_userNotAdmin_passes() throws Exception {
        when(repo.getAdminRoleId()).thenReturn(ADMIN_ROLE_ID);
        when(repo.getUserRoleId(2)).thenReturn(OTHER_ROLE_ID);
        guard.validateUserRoleRemoval(2);
    }

    @Test
    void validateUserRoleRemoval_userWithoutAnyRole_passes() throws Exception {
        when(repo.getAdminRoleId()).thenReturn(ADMIN_ROLE_ID);
        when(repo.getUserRoleId(2)).thenReturn(null);
        guard.validateUserRoleRemoval(2);
    }

    @Test
    void validateUserRoleRemoval_adminUserWithOtherAdmins_passes() throws Exception {
        when(repo.getAdminRoleId()).thenReturn(ADMIN_ROLE_ID);
        when(repo.getUserRoleId(2)).thenReturn(ADMIN_ROLE_ID);
        when(repo.countUsersByRoleId(ADMIN_ROLE_ID)).thenReturn(2);
        guard.validateUserRoleRemoval(2);
    }

    @Test
    void validateUserRoleRemoval_lastAdmin_throws() {
        when(repo.getAdminRoleId()).thenReturn(ADMIN_ROLE_ID);
        when(repo.getUserRoleId(1)).thenReturn(ADMIN_ROLE_ID);
        when(repo.countUsersByRoleId(ADMIN_ROLE_ID)).thenReturn(1);
        MirthApiException e = assertThrows(MirthApiException.class,
                () -> guard.validateUserRoleRemoval(1));
        assertTrue(entityText(e).contains("last admin"));
    }

    @Test
    void validateUserRoleRemoval_noAdminRoleExists_passes() throws Exception {
        when(repo.getAdminRoleId()).thenReturn(null);
        guard.validateUserRoleRemoval(1);
    }

    // ========== validateUserRoleAssignment ==========

    @Test
    void validateUserRoleAssignment_assigningAdminRole_passes() throws Exception {
        when(repo.getAdminRoleId()).thenReturn(ADMIN_ROLE_ID);
        // Assigning admin role is always fine — never reduces admin count
        guard.validateUserRoleAssignment(2, ADMIN_ROLE_ID);
    }

    @Test
    void validateUserRoleAssignment_movingNonAdminToOtherRole_passes() throws Exception {
        when(repo.getAdminRoleId()).thenReturn(ADMIN_ROLE_ID);
        when(repo.getUserRoleId(2)).thenReturn(OTHER_ROLE_ID);
        guard.validateUserRoleAssignment(2, 100); // moving 2 from OTHER_ROLE_ID to 100
    }

    @Test
    void validateUserRoleAssignment_movingAdminAwayWhenOthersExist_passes() throws Exception {
        when(repo.getAdminRoleId()).thenReturn(ADMIN_ROLE_ID);
        when(repo.getUserRoleId(2)).thenReturn(ADMIN_ROLE_ID);
        when(repo.countUsersByRoleId(ADMIN_ROLE_ID)).thenReturn(2);
        guard.validateUserRoleAssignment(2, OTHER_ROLE_ID);
    }

    @Test
    void validateUserRoleAssignment_movingLastAdminAway_throws() {
        when(repo.getAdminRoleId()).thenReturn(ADMIN_ROLE_ID);
        when(repo.getUserRoleId(1)).thenReturn(ADMIN_ROLE_ID);
        when(repo.countUsersByRoleId(ADMIN_ROLE_ID)).thenReturn(1);
        MirthApiException e = assertThrows(MirthApiException.class,
                () -> guard.validateUserRoleAssignment(1, OTHER_ROLE_ID));
        assertTrue(entityText(e).contains("last admin"));
    }

    @Test
    void validateUserRoleAssignment_userWithoutPriorRole_passes() throws Exception {
        when(repo.getAdminRoleId()).thenReturn(ADMIN_ROLE_ID);
        when(repo.getUserRoleId(99)).thenReturn(null);
        guard.validateUserRoleAssignment(99, OTHER_ROLE_ID);
    }

    @Test
    void validateUserRoleAssignment_noAdminRoleExists_passes() throws Exception {
        when(repo.getAdminRoleId()).thenReturn(null);
        guard.validateUserRoleAssignment(1, OTHER_ROLE_ID);
    }

    // ========== Helpers ==========

    private static Role roleWithPerms(String... perms) {
        Role role = new Role();
        role.setPermissions(new HashSet<>(Set.of(perms)));
        return role;
    }

    /**
     * Extracts the textual entity from a MirthApiException's Response. The
     * guard puts its error message in the response entity (so HTTP clients
     * see it as the response body); {@code getMessage()} on the exception
     * itself is not set.
     */
    private static String entityText(MirthApiException e) {
        Object entity = e.getResponse().getEntity();
        return entity != null ? entity.toString() : "";
    }
}
