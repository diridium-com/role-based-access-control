// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.mirth.connect.client.core.api.MirthApiException;

class UnregisteredGrantServiceTest {

    private static final Set<String> CORE = Set.of("viewChannels", "manageUsers");
    private static final Set<String> PLUGINS = Set.of(RbacServletInterface.PERMISSION_VIEW, "View Settings");

    private RbacRepository repo;
    private RbacAuditLog auditLog;
    private Runnable cacheInvalidator;
    private Set<String> core;
    private Set<String> plugins;

    @BeforeEach
    void setUp() {
        repo = mock(RbacRepository.class);
        auditLog = mock(RbacAuditLog.class);
        cacheInvalidator = mock(Runnable.class);
        core = new HashSet<>(CORE);
        plugins = new HashSet<>(PLUGINS);
    }

    private UnregisteredGrantService service() {
        return new UnregisteredGrantService(repo, auditLog, cacheInvalidator, () -> core, () -> plugins,
                () -> List.of("Data Pruner"));
    }

    private static Role role(int id, String name, String... permissions) {
        Role role = new Role();
        role.setId(id);
        role.setName(name);
        role.setPermissions(new HashSet<>(Set.of(permissions)));
        role.setChannelIds(new HashSet<>());
        return role;
    }

    private static UnregisteredGrants request(Object... roleIdAndPermission) {
        UnregisteredGrants request = new UnregisteredGrants();
        for (int i = 0; i < roleIdAndPermission.length; i += 2) {
            request.getGrants().add(new UnregisteredGrant((Integer) roleIdAndPermission[i], null,
                    (String) roleIdAndPermission[i + 1]));
        }
        return request;
    }

    private static List<String> rows(UnregisteredGrants grants) {
        List<String> rows = new ArrayList<>();
        for (UnregisteredGrant grant : grants.getGrants()) {
            rows.add(grant.getRoleId() + " " + grant.getRoleName() + ": " + grant.getPermission());
        }
        return rows;
    }

    @Test
    void list_showsOnlyPermissionsNeitherTheEngineNorAPluginRegisters_byRoleName() {
        when(repo.getAllRoles()).thenReturn(List.of(
                role(3, "lab", "viewChannels", "Old Perm", "View Settings"),
                role(2, "Billing", "manageUsers", "Use Perm Test", "Another Old"),
                role(1, "Administrator", "viewChannels", "manageUsers")));

        UnregisteredGrants result = service().list(true);

        assertEquals(List.of("2 Billing: Another Old", "2 Billing: Use Perm Test", "3 lab: Old Perm"), rows(result));
        assertEquals(List.of("Data Pruner"), result.getDisabledPlugins());
    }

    @Test
    void list_refusesAnyoneWithoutTheAdminRole() {
        MirthApiException e = assertThrows(MirthApiException.class, () -> service().list(false));
        assertEquals(403, e.getResponse().getStatus());
        assertEquals(UnregisteredGrantService.LIST_NEEDS_ADMIN, e.getResponse().getStatusInfo().getReasonPhrase());
        verify(repo, never()).getAllRoles();
    }

    @Test
    void list_listsNothingWhenTheEnginesPermissionsCouldNotBeRead() {
        core.clear();
        MirthApiException e = assertThrows(MirthApiException.class, () -> service().list(true));
        assertEquals(503, e.getResponse().getStatus());
        assertEquals(UnregisteredGrantService.NOT_READY, e.getResponse().getStatusInfo().getReasonPhrase());
        verify(repo, never()).getAllRoles();
    }

    @Test
    void list_listsNothingBeforeThePluginsPermissionsAreRegistered() {
        plugins.clear();
        MirthApiException e = assertThrows(MirthApiException.class, () -> service().list(true));
        assertEquals(503, e.getResponse().getStatus());
        verify(repo, never()).getAllRoles();
    }

    @Test
    void remove_removesOnlyRequestedGrantsThatAreStillOrphaned_andAuditsEachRole() {
        when(repo.getAllRoles()).thenReturn(List.of(
                role(2, "Billing", "manageUsers", "Use Perm Test", "Another Old"),
                role(3, "lab", "viewChannels", "Old Perm")));
        Map<Integer, Set<String>> expected = new LinkedHashMap<>();
        expected.put(2, new TreeSet<>(Set.of("Use Perm Test")));
        expected.put(3, new TreeSet<>(Set.of("Old Perm")));
        when(repo.removePermissions(expected)).thenReturn(expected);

        int removed = service().remove(true, request(2, "Use Perm Test", 3, "Old Perm",
                2, "manageUsers", 3, "View Settings", 3, "Never Held", 9, "Old Perm"));

        assertEquals(2, removed);
        verify(repo).removePermissions(expected);
        verify(cacheInvalidator).run();
        verify(auditLog).orphanedPermissionsRemoved("Billing", Set.of("Use Perm Test"));
        verify(auditLog).orphanedPermissionsRemoved("lab", Set.of("Old Perm"));
    }

    @Test
    void remove_withNothingStillOrphaned_writesNothing() {
        when(repo.getAllRoles()).thenReturn(List.of(role(2, "Billing", "manageUsers", "View Settings")));

        assertEquals(0, service().remove(true, request(2, "manageUsers", 2, "View Settings")));

        verify(repo, never()).removePermissions(any());
        verify(cacheInvalidator, never()).run();
        verify(auditLog, never()).orphanedPermissionsRemoved(anyString(), any());
    }

    @Test
    void remove_refusesAnyoneWithoutTheAdminRole() {
        MirthApiException e = assertThrows(MirthApiException.class, () -> service().remove(false, request(2, "Old")));
        assertEquals(UnregisteredGrantService.REMOVE_NEEDS_ADMIN, e.getResponse().getStatusInfo().getReasonPhrase());
        verify(repo, never()).removePermissions(any());
    }

    @Test
    void remove_removesNothingWhenTheEnginesPermissionsCouldNotBeRead() {
        core.clear();
        assertThrows(MirthApiException.class, () -> service().remove(true, request(2, "viewChannels")));
        verify(repo, never()).removePermissions(any());
    }
}
