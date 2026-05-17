// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import java.util.Map;

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

    private ServerEvent capture() {
        ArgumentCaptor<ServerEvent> captor = ArgumentCaptor.forClass(ServerEvent.class);
        verify(eventController).dispatchEvent(captor.capture());
        return captor.getValue();
    }
}
