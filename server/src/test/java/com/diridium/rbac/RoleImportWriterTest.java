// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.ibatis.session.SqlSession;
import org.apache.ibatis.session.SqlSessionManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import com.diridium.rbac.RoleImportPlanner.PlannedRole;
import com.mirth.connect.server.util.SqlConfig;

/**
 * Tests the statements an import runs ({@link RoleImportWriter}) and the
 * transaction around them ({@link RbacRepository#importRoles}), against a mocked
 * {@link SqlSession}.
 */
class RoleImportWriterTest {

    private SqlSession session;
    private MockedStatic<SqlConfig> mockedSqlConfig;

    @BeforeEach
    void setUp() {
        session = mock(SqlSession.class);
        // insertRole's useGeneratedKeys writes the new id into the params map.
        doAnswer(invocation -> {
            Map<String, Object> params = invocation.getArgument(1);
            params.put("id", 77);
            return 1;
        }).when(session).insert(eq("Rbac.insertRole"), anyMap());
    }

    @AfterEach
    void tearDown() {
        if (mockedSqlConfig != null) {
            mockedSqlConfig.close();
        }
        RbacRepository.close();
        MigrationStatus.markOk();
    }

    @Test
    void aNewRole_isInsertedWithItsPermissionsAndChannels_neverAsAdmin() {
        new RoleImportWriter().write(session, List.of(planned(null, "Lab", Set.of("viewChannels"), Set.of("c1"), true)));

        ArgumentCaptor<Map<String, Object>> role = mapCaptor();
        verify(session).insert(eq("Rbac.insertRole"), role.capture());
        assertEquals("Lab", role.getValue().get("name"));
        assertEquals(false, role.getValue().get("isAdmin"));
        verify(session).delete("Rbac.deletePermissionsForRole", 77);
        verify(session).insert(eq("Rbac.insertPermission"), eq(Map.of("roleId", 77, "permission", "viewChannels")));
        verify(session).delete("Rbac.deleteChannelIdsForRole", 77);
        verify(session).insert(eq("Rbac.insertChannelId"), eq(Map.of("roleId", 77, "channelId", "c1")));
    }

    @Test
    void anOverwrite_updatesTheRoleAndReplacesItsPermissionsAndChannels() {
        new RoleImportWriter().write(session, List.of(planned(5, "Lab", Set.of("viewChannels"), Set.of("c1"), true)));

        ArgumentCaptor<Map<String, Object>> role = mapCaptor();
        verify(session).update(eq("Rbac.updateRole"), role.capture());
        assertEquals(5, role.getValue().get("id"));
        verify(session, never()).insert(eq("Rbac.insertRole"), any());
        verify(session).delete("Rbac.deletePermissionsForRole", 5);
        verify(session).delete("Rbac.deleteChannelIdsForRole", 5);
    }

    @Test
    void anOverwriteWithChannelsKept_leavesTheChannelRowsAlone() {
        new RoleImportWriter().write(session, List.of(planned(5, "Lab", Set.of("viewChannels"), Set.of("c1"), false)));

        verify(session).delete("Rbac.deletePermissionsForRole", 5);
        verify(session, never()).delete(eq("Rbac.deleteChannelIdsForRole"), any());
        verify(session, never()).insert(eq("Rbac.insertChannelId"), any());
    }

    @Test
    void twoNewNamesTheDatabaseTreatsAsOne_stopTheImport_namingBoth() {
        // As MySQL's default collation does: after Café is inserted, looking up Cafe finds it.
        when(session.selectOne("Rbac.getRoleIdByName", "Cafe")).thenReturn(77);

        RoleImportWriter.NameClash clash = assertThrows(RoleImportWriter.NameClash.class,
                () -> new RoleImportWriter().write(session, List.of(
                        planned(null, "Café", Set.of(), Set.of(), true), planned(null, "Cafe", Set.of(), Set.of(), true))));

        assertEquals("The roles 'Café' and 'Cafe' in the file are the same role on this engine, whose database holds"
                + " them as one name. Rename one of them in the file.", clash.getMessage());
        assertEquals(false, clash.changedSincePreview());
        verify(session, times(1)).insert(eq("Rbac.insertRole"), anyMap());
    }

    @Test
    void aNewNameSomeoneTookSinceThePreview_stopsTheImportAsStale() {
        when(session.selectOne("Rbac.getRoleIdByName", "Lab")).thenReturn(5);

        RoleImportWriter.NameClash clash = assertThrows(RoleImportWriter.NameClash.class,
                () -> new RoleImportWriter().write(session, List.of(planned(null, "Lab", Set.of(), Set.of(), true))));

        assertEquals("The roles changed since the preview. Preview the import again.", clash.getMessage());
        assertEquals(true, clash.changedSincePreview());
        verify(session, never()).insert(eq("Rbac.insertRole"), anyMap());
    }

    @Test
    void importRoles_letsANameClashThrough_andWritesNothing() {
        SqlSession transaction = stubSession();
        when(transaction.selectOne("Rbac.getRoleIdByName", "Cafe")).thenReturn(77);
        RbacRepository.init(List.of());

        assertThrows(RoleImportWriter.NameClash.class, () -> RbacRepository.getInstance().importRoles(List.of(
                planned(null, "Café", Set.of(), Set.of(), true), planned(null, "Cafe", Set.of(), Set.of(), true))));

        verify(transaction, never()).commit();
        verify(transaction).close();
    }

    @Test
    void importRoles_commitsOnce_whenEveryRoleIsWritten() {
        SqlSession transaction = stubSession();
        RbacRepository.init(List.of());

        RbacRepository.getInstance().importRoles(List.of(
                planned(null, "Lab", Set.of(), Set.of(), true), planned(5, "ADT", Set.of(), Set.of(), true)));

        verify(transaction, times(1)).commit();
        verify(transaction, times(1)).close();
    }

    @Test
    void importRoles_writesNothing_whenALaterRoleFails() {
        SqlSession transaction = stubSession();
        when(transaction.update(eq("Rbac.updateRole"), anyMap())).thenThrow(new RuntimeException("deadlock"));
        RbacRepository.init(List.of());

        assertThrows(RbacRepositoryException.class, () -> RbacRepository.getInstance().importRoles(List.of(
                planned(null, "Lab", Set.of(), Set.of(), true), planned(5, "ADT", Set.of(), Set.of(), true))));

        verify(transaction).insert(eq("Rbac.insertRole"), anyMap());
        verify(transaction, never()).commit();
        verify(transaction).close(); // closing an uncommitted session rolls it back
    }

    /**
     * A session manager whose first manual-commit session is the seeder's (an existing
     * admin role, so it writes nothing) and whose second is the import's.
     */
    private SqlSession stubSession() {
        SqlSession seed = mock(SqlSession.class);
        when(seed.selectOne(eq("Rbac.getAdminRoleId"), any())).thenReturn(1);
        SqlSession transaction = mock(SqlSession.class);
        doAnswer(invocation -> {
            Map<String, Object> params = invocation.getArgument(1);
            params.put("id", 77);
            return 1;
        }).when(transaction).insert(eq("Rbac.insertRole"), anyMap());
        SqlConfig sqlConfig = mock(SqlConfig.class);
        SqlSessionManager manager = mock(SqlSessionManager.class);
        when(sqlConfig.getSqlSessionManager()).thenReturn(manager);
        when(manager.openSession(false)).thenReturn(seed, transaction);
        mockedSqlConfig = Mockito.mockStatic(SqlConfig.class);
        mockedSqlConfig.when(SqlConfig::getInstance).thenReturn(sqlConfig);
        return transaction;
    }

    private static PlannedRole planned(Integer existingId, String name, Set<String> permissions, Set<String> channelIds,
            boolean writeChannels) {
        Role role = new Role();
        role.setName(name);
        role.setDescription("d");
        role.setPermissions(new LinkedHashSet<>(permissions));
        role.setChannelIds(new LinkedHashSet<>(channelIds));
        return new PlannedRole(existingId, role, writeChannels);
    }

    @SuppressWarnings("unchecked")
    private static ArgumentCaptor<Map<String, Object>> mapCaptor() {
        return ArgumentCaptor.forClass(Map.class);
    }
}
