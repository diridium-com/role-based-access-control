// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import com.diridium.rbac.RoleImportRow.Action;
import com.mirth.connect.client.core.api.MirthApiException;

/**
 * Tests {@link RoleTransferService}: the second permission each operation needs,
 * what an export holds, and the preview-then-apply exchange of an import.
 */
class RoleTransferServiceTest {

    private static final Set<String> CATALOG = Set.of("viewChannels", "viewMessages");
    private static final Set<String> EXPORTER = Set.of("Export Roles", "View Roles");
    private static final Set<String> IMPORTER = Set.of("Import Roles", "Manage Roles");

    private RbacRepository repo;
    private RbacAuditLog auditLog;
    private Runnable cacheInvalidator;
    private Map<String, String> channels;
    private RoleTransferService service;

    @BeforeEach
    void setUp() {
        repo = mock(RbacRepository.class);
        auditLog = mock(RbacAuditLog.class);
        cacheInvalidator = mock(Runnable.class);
        channels = new LinkedHashMap<>();
        channels.put("id-lab", "Lab In");
        service = new RoleTransferService(repo, auditLog, cacheInvalidator, () -> CATALOG, () -> channels,
                () -> "1.3.0", () -> "4.7.0");

        Role admin = role(1, "Administrator", Set.of("viewChannels"), Set.of());
        admin.setAdmin(true);
        Role lab = role(5, "Lab", Set.of("viewMessages", "viewChannels"), Set.of("id-lab", "id-gone"));
        Role everyone = role(6, "Everyone", Set.of(), Set.of());
        when(repo.getAllRoles()).thenReturn(List.of(admin, lab, everyone));
        when(repo.getRoleById(1)).thenReturn(admin);
        when(repo.getRoleById(5)).thenReturn(lab);
        when(repo.getRoleById(6)).thenReturn(everyone);
        when(repo.getAdminRoleId()).thenReturn(1);
        when(repo.findRoleIdByName("Administrator")).thenReturn(1);
    }

    // ========== Export ==========

    @Test
    void export_needsViewRolesToo() {
        assertForbidden(() -> service.export(Set.of("Export Roles"), Set.of()), "Missing permission: View Roles");
    }

    @Test
    void export_withNoIds_writesEveryRoleButTheAdminRole() throws Exception {
        RoleTransferFormat.ExportFile file = RoleTransferFormat.parse(service.export(EXPORTER, Set.of()));
        assertEquals("1.3.0", file.rbacVersion());
        assertEquals("4.7.0", file.engineVersion());
        assertEquals(List.of("Lab", "Everyone"), file.roles().stream().map(RoleTransferFormat.ExportedRole::name).toList());
        RoleTransferFormat.ExportedRole lab = file.roles().get(0);
        assertEquals(List.of("viewChannels", "viewMessages"), lab.permissions(), "sorted");
        assertTrue(lab.restricted());
        assertEquals(List.of(new RoleTransferFormat.Channel("id-gone", ""), new RoleTransferFormat.Channel("id-lab", "Lab In")),
                lab.channels(), "a channel deleted here keeps its id, with no name");
        assertFalse(file.roles().get(1).restricted());
    }

    @Test
    void export_withIds_writesOnlyThoseRoles() throws Exception {
        RoleTransferFormat.ExportFile file = RoleTransferFormat.parse(service.export(EXPORTER, Set.of(6)));
        assertEquals(1, file.roles().size());
        assertEquals("Everyone", file.roles().get(0).name());
    }

    @Test
    void export_refusesAnUnknownIdOrTheAdminRole() {
        assertStatus(400, "There's no role with id 9.", () -> service.export(EXPORTER, Set.of(5, 9)));
        assertStatus(400, "The admin role is never exported.", () -> service.export(EXPORTER, Set.of(1)));
    }

    @Test
    void export_refusesWhenOnlyTheAdminRoleExists() {
        Role admin = role(1, "Administrator", Set.of(), Set.of());
        admin.setAdmin(true);
        when(repo.getAllRoles()).thenReturn(List.of(admin));
        assertStatus(400, "There are no roles to export. The admin role is never exported.",
                () -> service.export(EXPORTER, Set.of()));
    }

    // ========== Import: preview ==========

    @Test
    void import_needsManageRolesToo() {
        assertForbidden(() -> service.importRoles(Set.of("Import Roles"), file(), true, true, null, null),
                "Missing permission: Manage Roles");
        verify(repo, never()).importRoles(any());
    }

    @Test
    void preview_plansEveryRole_andWritesNothing() {
        RoleImportResult result = service.importRoles(IMPORTER, file(), true, true, null, null);
        assertTrue(result.isImportable());
        assertFalse(result.isApplied());
        assertEquals("1", result.getFormatVersion());
        assertEquals("1.2.0", result.getSourceRbacVersion());
        assertEquals("4.7.0", result.getSourceEngineVersion());
        assertEquals(List.of(Action.CREATE, Action.SKIP), result.getRows().stream().map(RoleImportRow::getAction).toList());
        assertEquals(64, result.getPlanToken().length());
        verify(repo, never()).importRoles(any());
        verify(cacheInvalidator, never()).run();
    }

    @Test
    void preview_ofARefusedFile_saysWhy() {
        RoleImportResult result = service.importRoles(IMPORTER, "<rbacRoles formatVersion=\"2\" rbacVersion=\"1.4.0\"/>",
                true, true, null, null);
        assertFalse(result.isImportable());
        assertEquals("This file is format 2, written by rbac 1.4.0. This rbac reads format 1.", result.getRefusal());
        assertTrue(result.getRows().isEmpty());
        assertNull(result.getPlanToken());
    }

    // ========== Import: apply ==========

    @Test
    void apply_writesThePickedRoles_thenClearsTheCacheAndAudits() {
        String token = service.importRoles(IMPORTER, file(), true, true, null, null).getPlanToken();

        RoleImportResult result = service.importRoles(IMPORTER, file(), false, true, List.of(0), token);

        assertTrue(result.isApplied());
        assertEquals(List.of("New"), result.getRows().stream().map(RoleImportRow::getName).toList());
        ArgumentCaptor<List<RoleImportPlanner.PlannedRole>> writes = writesCaptor();
        verify(repo).importRoles(writes.capture());
        assertEquals(1, writes.getValue().size());
        assertEquals("New", writes.getValue().get(0).role().getName());
        verify(cacheInvalidator).run();
        verify(auditLog).rolesImported(List.of("New"), List.of(), true);
    }

    @Test
    void apply_refusesAStaleToken_withoutWriting() {
        String token = service.importRoles(IMPORTER, file(), true, true, null, null).getPlanToken();
        when(repo.findRoleIdByName("New")).thenReturn(6); // someone made a role called New since the preview

        assertStatus(409, "The roles changed since the preview. Preview the import again.",
                () -> service.importRoles(IMPORTER, file(), false, true, List.of(0), token));
        verify(repo, never()).importRoles(any());
        verify(auditLog, never()).rolesImported(any(), any(), anyBoolean());
    }

    @Test
    void apply_refusesAMissingTokenOrABadPick_withoutWriting() {
        String token = service.importRoles(IMPORTER, file(), true, true, null, null).getPlanToken();
        assertStatus(400, "Preview the import first, and send the preview's planToken with the apply.",
                () -> service.importRoles(IMPORTER, file(), false, true, List.of(0), null));
        assertStatus(400, "No roles were picked.",
                () -> service.importRoles(IMPORTER, file(), false, true, List.of(), token));
        assertStatus(400, "There's no role at position 7 in the file.",
                () -> service.importRoles(IMPORTER, file(), false, true, List.of(0, 7), token));
        assertStatus(400, "The role 'Administrator' can't be imported: This is the name of this engine's admin role,"
                + " which an import never changes.",
                () -> service.importRoles(IMPORTER, file(), false, true, List.of(1), token));
        verify(repo, never()).importRoles(any());
    }

    @Test
    void apply_thatTheDatabaseRefusesForAName_saysWhy_andChangesNothing() {
        String token = service.importRoles(IMPORTER, file(), true, true, null, null).getPlanToken();
        doThrow(new RoleImportWriter.NameClash("Rename one of them in the file.", false)).when(repo).importRoles(any());
        assertStatus(400, "Rename one of them in the file.",
                () -> service.importRoles(IMPORTER, file(), false, true, List.of(0), token));

        doThrow(new RoleImportWriter.NameClash("Preview the import again.", true)).when(repo).importRoles(any());
        assertStatus(409, "Preview the import again.",
                () -> service.importRoles(IMPORTER, file(), false, true, List.of(0), token));

        verify(cacheInvalidator, never()).run();
        verify(auditLog, never()).rolesImported(any(), any(), anyBoolean());
    }

    @Test
    void apply_ofARefusedFile_is400() {
        assertStatus(400, "The file is empty.", () -> service.importRoles(IMPORTER, "", false, true, List.of(0), "t"));
    }

    // ========== Helpers ==========

    private static String file() {
        return "<rbacRoles formatVersion=\"1\" rbacVersion=\"1.2.0\" engineVersion=\"4.7.0\">"
                + "<role><name>New</name><permissions><permission>viewChannels</permission></permissions>"
                + "<channels restricted=\"true\"><channel id=\"id-lab\" name=\"Lab In\"/></channels></role>"
                + "<role><name>Administrator</name><permissions/><channels restricted=\"false\"/></role>"
                + "</rbacRoles>";
    }

    private static Role role(int id, String name, Set<String> permissions, Set<String> channelIds) {
        Role role = new Role();
        role.setId(id);
        role.setName(name);
        role.setPermissions(new HashSet<>(permissions));
        role.setChannelIds(new HashSet<>(channelIds));
        return role;
    }

    private static void assertForbidden(Runnable call, String reason) {
        MirthApiException e = assertThrows(MirthApiException.class, call::run);
        assertEquals(403, e.getResponse().getStatus());
        assertEquals(reason, e.getResponse().getStatusInfo().getReasonPhrase());
    }

    private static void assertStatus(int status, String message, Runnable call) {
        MirthApiException e = assertThrows(MirthApiException.class, call::run);
        assertEquals(status, e.getResponse().getStatus());
        assertEquals(message, e.getResponse().getEntity());
    }

    @SuppressWarnings("unchecked")
    private static ArgumentCaptor<List<RoleImportPlanner.PlannedRole>> writesCaptor() {
        return ArgumentCaptor.forClass(List.class);
    }
}
