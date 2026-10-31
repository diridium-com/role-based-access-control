// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.mirth.connect.model.ServerEvent;
import com.mirth.connect.model.ServerEvent.Level;
import com.mirth.connect.model.ServerEvent.Outcome;
import com.mirth.connect.server.controllers.EventController;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

/**
 * Verifies the shape of audit events dispatched on RBAC mutations.
 * EventController is mocked; we capture the dispatched ServerEvent and
 * inspect its attributes.
 */
class RbacAuditLogTest {

    private EventController eventController;
    private RbacAuditLog auditLog;

    @BeforeEach
    void setUp() {
        eventController = mock(EventController.class);
        auditLog = new RbacAuditLog(eventController, "test-server-id");
    }

    @Test
    void role_dispatchesEventWithExpectedAttributes() {
        auditLog.role("Created", "MyRole");

        ServerEvent event = capture();
        assertEquals(RbacServletInterface.PLUGIN_NAME, event.getName());
        assertEquals(Level.INFORMATION, event.getLevel());
        assertEquals(Outcome.SUCCESS, event.getOutcome());
        assertEquals("test-server-id", event.getServerId());

        Map<String, String> attrs = event.getAttributes();
        assertEquals("MyRole", attrs.get("Role"));
        assertEquals("Created", attrs.get("Action"));
    }

    @Test
    void role_nullName_replacedWithPlaceholder() {
        auditLog.role("Deleted", null);
        assertEquals("(unknown)", capture().getAttributes().get("Role"));
    }

    @Test
    void assignment_includesUserAndRoleId() {
        auditLog.assignment("Assigned", 42, 7);

        Map<String, String> attrs = capture().getAttributes();
        assertEquals("42", attrs.get("User ID"));
        assertEquals("7", attrs.get("Role ID"));
        assertEquals("Assigned", attrs.get("Action"));
    }

    @Test
    void assignment_nullRoleId_omittedFromAttributes() {
        auditLog.assignment("Removed", 42, null);

        Map<String, String> attrs = capture().getAttributes();
        assertEquals("42", attrs.get("User ID"));
        assertNull(attrs.get("Role ID"));
        assertEquals("Removed", attrs.get("Action"));
    }

    @Test
    void role_actionUpdated() {
        auditLog.role("Updated", "MyRole");
        assertEquals("Updated", capture().getAttributes().get("Action"));
    }

    @Test
    void rolesImported_recordsEachRolesPermissionsAndChannels() {
        RoleImportPlanner.PlannedRole created = planned(null, "Lab", Set.of("viewMessages", "viewChannels"),
                Set.of("id-lab", "id-gone"), true);
        RoleImportPlanner.PlannedRole everywhere = planned(5, "Billing", Set.of(), Set.of(), true);
        RoleImportPlanner.PlannedRole kept = planned(6, "Front desk", Set.of("viewDashboard"), Set.of("id-lab"), false);

        auditLog.rolesImported(List.of(created, everywhere, kept), Map.of("id-lab", "Lab In"), true);

        Map<String, String> attrs = capture().getAttributes();
        assertEquals("Lab", attrs.get("Created"));
        assertEquals("Billing, Front desk", attrs.get("Overwritten"));
        assertEquals("Applied from the file", attrs.get("Channel restrictions"));
        assertEquals("Permissions: viewChannels, viewMessages. Channels: Lab In (id-lab), id-gone.",
                attrs.get("Role: Lab"), "a channel with no name here has only its id");
        assertEquals("Permissions: (none). Channels: every channel.", attrs.get("Role: Billing"));
        assertEquals("Permissions: viewDashboard. Channels: unchanged.", attrs.get("Role: Front desk"));
        assertEquals("Imported", attrs.get("Action"));
    }

    private static RoleImportPlanner.PlannedRole planned(Integer existingId, String name, Set<String> permissions,
            Set<String> channelIds, boolean writeChannels) {
        Role role = new Role();
        role.setName(name);
        role.setPermissions(new HashSet<>(permissions));
        role.setChannelIds(new HashSet<>(channelIds));
        return new RoleImportPlanner.PlannedRole(existingId, role, writeChannels);
    }

    private ServerEvent capture() {
        ArgumentCaptor<ServerEvent> captor = ArgumentCaptor.forClass(ServerEvent.class);
        verify(eventController).dispatchEvent(captor.capture());
        return captor.getValue();
    }
}
