// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import java.util.LinkedHashMap;
import java.util.Map;

import com.mirth.connect.model.ServerEvent;
import com.mirth.connect.model.ServerEvent.Level;
import com.mirth.connect.model.ServerEvent.Outcome;
import com.mirth.connect.server.controllers.EventController;

/**
 * Encapsulates server-event dispatch for RBAC mutations.
 *
 * <p>Extracted from {@link RbacServlet} so the dispatch shape can be unit-tested
 * without instantiating {@code MirthServlet}'s HTTP machinery. The servlet
 * constructs one of these in its constructor and calls into it from every
 * mutating operation.</p>
 *
 * <p>All events are dispatched as {@link Level#INFORMATION} with
 * {@link Outcome#SUCCESS}. Failure dispatches are deliberately not surfaced
 * here — failures throw at the servlet boundary and are visible in the OIE
 * server log; cluttering the event log with failed-mutation noise was not
 * judged worth the cost.</p>
 */
class RbacAuditLog {

    private final EventController eventController;
    private final String serverId;

    /**
     * @param eventController the engine event controller used to dispatch
     *                        {@link ServerEvent} instances
     * @param serverId        the local OIE server id, included with every event
     *                        for cluster-aware audit trails
     */
    RbacAuditLog(EventController eventController, String serverId) {
        this.eventController = eventController;
        this.serverId = serverId;
    }

    /**
     * Dispatches an audit event describing a role-level mutation
     * (Created / Updated / Deleted).
     *
     * @param action   short verb describing what happened to the role,
     *                 e.g. {@code "Created"}; surfaced in the event log
     * @param roleName the human-readable name of the role at the time of the
     *                 action; null is normalized to {@code "(unknown)"} so the
     *                 audit row is still useful when the role's name cannot
     *                 be determined (e.g., during a deletion where the row
     *                 may already be gone)
     */
    void role(String action, String roleName) {
        Map<String, String> attributes = new LinkedHashMap<>();
        attributes.put("Role", roleName != null ? roleName : "(unknown)");
        attributes.put("Action", action);
        dispatch(attributes);
    }

    /**
     * Dispatches an audit event describing a user-role assignment change
     * (Assigned / Removed).
     *
     * @param action short verb describing what happened, e.g. {@code "Assigned"}
     * @param userId the engine user id whose assignment changed
     * @param roleId the role id involved; pass {@code null} for assignment
     *               removals where no role id is meaningful — the attribute
     *               is then omitted from the event rather than included with
     *               an empty value
     */
    void assignment(String action, int userId, Integer roleId) {
        Map<String, String> attributes = new LinkedHashMap<>();
        attributes.put("User ID", String.valueOf(userId));
        if (roleId != null) {
            attributes.put("Role ID", String.valueOf(roleId));
        }
        attributes.put("Action", action);
        dispatch(attributes);
    }

    private void dispatch(Map<String, String> attributes) {
        eventController.dispatchEvent(new ServerEvent(
                serverId, RbacServletInterface.PLUGIN_NAME, Level.INFORMATION, Outcome.SUCCESS, attributes));
    }
}
