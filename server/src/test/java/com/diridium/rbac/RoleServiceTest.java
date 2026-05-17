// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.HashSet;
import java.util.Set;

import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import com.mirth.connect.client.core.api.MirthApiException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Tests for the role + user-role business logic extracted from
 * {@link RbacServlet}. Covers input validation, conflict detection,
 * status codes, defensive copies, audit dispatch, and admin-guard delegation.
 */
class RoleServiceTest {

    private RbacRepository repo;
    private AdminRoleGuard adminGuard;
    private RbacAuditLog auditLog;
    private Runnable cacheInvalidator;
    private RoleService service;

    @BeforeEach
    void setUp() {
        repo = mock(RbacRepository.class);
        adminGuard = mock(AdminRoleGuard.class);
        auditLog = mock(RbacAuditLog.class);
        cacheInvalidator = mock(Runnable.class);
        service = new RoleService(repo, adminGuard, auditLog, cacheInvalidator);
    }

    // ========== get ==========

    @Test
    void get_existingRole_returnsIt() {
        Role role = roleWithName(7, "Editor");
        when(repo.getRoleById(7)).thenReturn(role);
        assertEquals(role, service.get(7));
    }

    @Test
    void get_missingRole_throws404() {
        when(repo.getRoleById(99)).thenReturn(null);
        MirthApiException e = assertThrows(MirthApiException.class, () -> service.get(99));
        assertEquals(Status.NOT_FOUND.getStatusCode(), e.getResponse().getStatus());
    }

    // ========== create ==========

    @Test
    void create_happyPath_persistsAndAudits() {
        Role input = roleWithName(null, "Editor");
        Role persisted = roleWithName(42, "Editor");
        when(repo.findRoleIdByName("Editor")).thenReturn(null);
        when(repo.createRole(input)).thenReturn(persisted);

        Role result = service.create(input);

        assertEquals(persisted, result);
        verify(cacheInvalidator).run();
        verify(auditLog).role("Created", "Editor");
    }

    @Test
    void create_nullRole_throws400() {
        MirthApiException e = assertThrows(MirthApiException.class, () -> service.create(null));
        assertEquals(Status.BAD_REQUEST.getStatusCode(), e.getResponse().getStatus());
        assertEquals("Role is required", entityText(e));
    }

    @Test
    void create_blankName_throws400() {
        Role input = roleWithName(null, "   ");
        MirthApiException e = assertThrows(MirthApiException.class, () -> service.create(input));
        assertEquals(Status.BAD_REQUEST.getStatusCode(), e.getResponse().getStatus());
        assertEquals("Role name is required", entityText(e));
    }

    @Test
    void create_nullName_throws400() {
        Role input = new Role();
        MirthApiException e = assertThrows(MirthApiException.class, () -> service.create(input));
        assertEquals(Status.BAD_REQUEST.getStatusCode(), e.getResponse().getStatus());
    }

    @Test
    void create_duplicateName_throws409() {
        Role input = roleWithName(null, "Editor");
        when(repo.findRoleIdByName("Editor")).thenReturn(42); // already exists

        MirthApiException e = assertThrows(MirthApiException.class, () -> service.create(input));
        assertEquals(Status.CONFLICT.getStatusCode(), e.getResponse().getStatus());
        assertTrue(entityText(e).contains("'Editor'"));
        verify(repo, never()).createRole(any());
    }

    @Test
    void create_forcesIsAdminFalse_evenWhenInputSaysTrue() {
        Role input = roleWithName(null, "AlmostAdmin");
        input.setAdmin(true); // malicious / mistaken input
        when(repo.findRoleIdByName("AlmostAdmin")).thenReturn(null);
        when(repo.createRole(any(Role.class))).thenAnswer(inv -> inv.getArgument(0));

        service.create(input);

        // The role passed to repo.createRole must have isAdmin=false
        assertFalse(input.isAdmin(), "Service must overwrite isAdmin to false");
    }

    // ========== update ==========

    @Test
    void update_happyPath_persistsAndAudits() {
        Role existing = roleWithName(42, "Editor");
        Role incoming = roleWithName(42, "Editor");
        when(repo.getRoleById(42)).thenReturn(existing);

        service.update(42, incoming);

        verify(adminGuard).validateRoleUpdate(42, incoming);
        verify(repo).updateRole(42, incoming);
        verify(cacheInvalidator).run();
        verify(auditLog).role("Updated", "Editor");
    }

    @Test
    void update_missingRole_throws404() {
        Role incoming = roleWithName(99, "Editor");
        when(repo.getRoleById(99)).thenReturn(null);

        MirthApiException e = assertThrows(MirthApiException.class, () -> service.update(99, incoming));
        assertEquals(Status.NOT_FOUND.getStatusCode(), e.getResponse().getStatus());
        verify(repo, never()).updateRole(anyInt(), any());
    }

    @Test
    void update_nullRole_throws400() {
        MirthApiException e = assertThrows(MirthApiException.class, () -> service.update(42, null));
        assertEquals(Status.BAD_REQUEST.getStatusCode(), e.getResponse().getStatus());
    }

    @Test
    void update_blankName_throws400() {
        Role incoming = roleWithName(42, "");
        MirthApiException e = assertThrows(MirthApiException.class, () -> service.update(42, incoming));
        assertEquals(Status.BAD_REQUEST.getStatusCode(), e.getResponse().getStatus());
    }

    @Test
    void update_renameToExistingOther_throws409() {
        Role existing = roleWithName(42, "Editor");
        Role incoming = roleWithName(42, "Admin"); // rename to another role's name
        when(repo.getRoleById(42)).thenReturn(existing);
        when(repo.findRoleIdByName("Admin")).thenReturn(7); // some other role has it

        MirthApiException e = assertThrows(MirthApiException.class, () -> service.update(42, incoming));
        assertEquals(Status.CONFLICT.getStatusCode(), e.getResponse().getStatus());
        verify(repo, never()).updateRole(anyInt(), any());
    }

    @Test
    void update_renameToOwnName_allowed() {
        // Looking up your own name returns your id — that's not a conflict.
        Role existing = roleWithName(42, "Editor");
        Role incoming = roleWithName(42, "Editor");
        when(repo.getRoleById(42)).thenReturn(existing);
        // findRoleIdByName won't be called since names match (short-circuited)

        service.update(42, incoming);

        verify(repo).updateRole(42, incoming);
    }

    @Test
    void update_rename_findReturnsSelfId_allowed() {
        // Edge case: rename "Editor" → "Editor2", findRoleIdByName("Editor2") returns 42 (us).
        // Shouldn't happen unless we're already at that name, but defensive.
        Role existing = roleWithName(42, "Editor");
        Role incoming = roleWithName(42, "Editor2");
        when(repo.getRoleById(42)).thenReturn(existing);
        when(repo.findRoleIdByName("Editor2")).thenReturn(42);

        service.update(42, incoming);

        verify(repo).updateRole(42, incoming);
    }

    @Test
    void update_adminGuardRejection_propagates() {
        Role existing = roleWithName(42, "Admin");
        Role incoming = roleWithName(42, "Admin");
        when(repo.getRoleById(42)).thenReturn(existing);
        doThrow(new MirthApiException(Response.status(Status.BAD_REQUEST).entity("guard says no").build()))
                .when(adminGuard).validateRoleUpdate(42, incoming);

        MirthApiException e = assertThrows(MirthApiException.class, () -> service.update(42, incoming));
        assertEquals(Status.BAD_REQUEST.getStatusCode(), e.getResponse().getStatus());
        verify(repo, never()).updateRole(anyInt(), any());
        verify(cacheInvalidator, never()).run();
    }

    // ========== delete ==========

    @Test
    void delete_happyPath_persistsAndAudits() {
        Role existing = roleWithName(42, "Editor");
        when(repo.getRoleById(42)).thenReturn(existing);

        service.delete(42);

        verify(adminGuard).validateRoleDeletion(42);
        verify(repo).deleteRole(42);
        verify(cacheInvalidator).run();
        verify(auditLog).role("Deleted", "Editor");
    }

    @Test
    void delete_missingRole_throws404() {
        when(repo.getRoleById(99)).thenReturn(null);

        MirthApiException e = assertThrows(MirthApiException.class, () -> service.delete(99));
        assertEquals(Status.NOT_FOUND.getStatusCode(), e.getResponse().getStatus());
        verify(repo, never()).deleteRole(anyInt());
    }

    @Test
    void delete_adminGuardRejection_propagates() {
        Role existing = roleWithName(42, "Admin");
        when(repo.getRoleById(42)).thenReturn(existing);
        doThrow(new MirthApiException(Response.status(Status.BAD_REQUEST).entity("admin").build()))
                .when(adminGuard).validateRoleDeletion(42);

        assertThrows(MirthApiException.class, () -> service.delete(42));
        verify(repo, never()).deleteRole(anyInt());
    }

    // ========== getUserRole ==========

    @Test
    void getUserRole_returnsRepoResult() {
        Role role = roleWithName(7, "Editor");
        when(repo.getUserRole(2)).thenReturn(role);
        assertEquals(role, service.getUserRole(2));
    }

    @Test
    void getUserRole_noAssignment_returnsNull() {
        when(repo.getUserRole(2)).thenReturn(null);
        assertNull(service.getUserRole(2));
    }

    // ========== assignUserRole ==========

    @Test
    void assignUserRole_happyPath() {
        when(repo.getRoleById(7)).thenReturn(roleWithName(7, "Editor"));

        service.assignUserRole(2, 7);

        verify(adminGuard).validateUserRoleAssignment(2, 7);
        verify(repo).assignUserRole(2, 7);
        verify(cacheInvalidator).run();
        verify(auditLog).assignment("Assigned", 2, 7);
    }

    @Test
    void assignUserRole_missingRole_throws404() {
        when(repo.getRoleById(99)).thenReturn(null);

        MirthApiException e = assertThrows(MirthApiException.class, () -> service.assignUserRole(2, 99));
        assertEquals(Status.NOT_FOUND.getStatusCode(), e.getResponse().getStatus());
        verify(repo, never()).assignUserRole(anyInt(), anyInt());
    }

    @Test
    void assignUserRole_adminGuardRejection_propagates() {
        when(repo.getRoleById(7)).thenReturn(roleWithName(7, "Editor"));
        doThrow(new MirthApiException(Response.status(Status.BAD_REQUEST).entity("last admin").build()))
                .when(adminGuard).validateUserRoleAssignment(2, 7);

        assertThrows(MirthApiException.class, () -> service.assignUserRole(2, 7));
        verify(repo, never()).assignUserRole(anyInt(), anyInt());
    }

    // ========== removeUserRole ==========

    @Test
    void removeUserRole_happyPath() {
        service.removeUserRole(2);

        verify(adminGuard).validateUserRoleRemoval(2);
        verify(repo).removeUserRole(2);
        verify(cacheInvalidator).run();
        verify(auditLog).assignment("Removed", 2, null);
    }

    @Test
    void removeUserRole_adminGuardRejection_propagates() {
        doThrow(new MirthApiException(Response.status(Status.BAD_REQUEST).entity("last admin").build()))
                .when(adminGuard).validateUserRoleRemoval(1);

        assertThrows(MirthApiException.class, () -> service.removeUserRole(1));
        verify(repo, never()).removeUserRole(anyInt());
        verify(cacheInvalidator, never()).run();
    }

    // ========== effectivePermissions (getMyPermissions logic) ==========

    @Test
    void effectivePermissions_adminRole_returnsFullCatalogFromSupplier() {
        Role admin = roleWithName(5, "Administrator");
        admin.setAdmin(true);
        when(repo.getUserRole(2)).thenReturn(admin);
        Set<String> catalog = Set.of("a", "b", "c");
        assertEquals(catalog, service.effectivePermissions(2, () -> catalog));
    }

    @Test
    void effectivePermissions_nonAdminRole_returnsGrantedPerms() {
        Role role = roleWithName(5, "Editor");
        role.setPermissions(new HashSet<>(Set.of("viewChannels", "viewMessages")));
        when(repo.getUserRole(2)).thenReturn(role);
        assertEquals(Set.of("viewChannels", "viewMessages"),
                service.effectivePermissions(2, () -> Set.of("SHOULD-NOT-BE-USED")));
    }

    @Test
    void effectivePermissions_noRole_returnsEmpty() {
        when(repo.getUserRole(2)).thenReturn(null);
        assertTrue(service.effectivePermissions(2, () -> Set.of("x")).isEmpty());
    }

    @Test
    void effectivePermissions_roleWithNullPermissions_returnsEmpty() {
        Role role = roleWithName(5, "Broken");
        role.setPermissions(null);
        when(repo.getUserRole(2)).thenReturn(role);
        assertTrue(service.effectivePermissions(2, () -> Set.of("x")).isEmpty());
    }

    // ========== Helpers ==========

    private static Role roleWithName(Integer id, String name) {
        Role role = new Role();
        role.setId(id);
        role.setName(name);
        role.setPermissions(new HashSet<>());
        role.setChannelIds(new HashSet<>());
        return role;
    }

    private static String entityText(MirthApiException e) {
        Object entity = e.getResponse().getEntity();
        return entity != null ? entity.toString() : "";
    }
}
