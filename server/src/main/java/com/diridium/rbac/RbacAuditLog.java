// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

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

    /**
     * Dispatches one audit event for an applied role import: the roles it created and
     * overwrote, and for each one, the permissions and channels it was given. The file
     * itself is kept out of the engine's own audit of the call, so this is the record of
     * what the import wrote, as the event for a role created by hand records the role.
     *
     * @param writes           the roles the import wrote
     * @param channelNamesById this engine's channels, id to name
     * @param channelsApplied  whether the file's channel restrictions were applied
     */
    void rolesImported(List<RoleImportPlanner.PlannedRole> writes, Map<String, String> channelNamesById,
            boolean channelsApplied) {
        List<String> created = new ArrayList<>();
        List<String> overwritten = new ArrayList<>();
        Map<String, String> roles = new LinkedHashMap<>();
        for (RoleImportPlanner.PlannedRole write : writes) {
            String name = write.role().getName();
            (write.existingId() == null ? created : overwritten).add(name);
            roles.put("Role: " + name, describe(write, channelNamesById));
        }
        Map<String, String> attributes = new LinkedHashMap<>();
        attributes.put("Created", created.isEmpty() ? "(none)" : String.join(", ", created));
        attributes.put("Overwritten", overwritten.isEmpty() ? "(none)" : String.join(", ", overwritten));
        attributes.put("Channel restrictions", channelsApplied ? "Applied from the file" : "Not applied");
        attributes.putAll(roles);
        attributes.put("Action", "Imported");
        dispatch(attributes);
    }

    private static String describe(RoleImportPlanner.PlannedRole write, Map<String, String> channelNamesById) {
        Role role = write.role();
        String permissions = role.getPermissions().isEmpty()
                ? "(none)" : String.join(", ", new TreeSet<>(role.getPermissions()));
        String channels;
        if (!write.writeChannels()) {
            channels = "unchanged";
        } else if (role.getChannelIds().isEmpty()) {
            channels = "every channel";
        } else {
            List<String> named = new ArrayList<>();
            for (String id : role.getChannelIds()) {
                String channelName = channelNamesById.get(id);
                named.add(channelName != null ? channelName + " (" + id + ")" : id);
            }
            Collections.sort(named);
            channels = String.join(", ", named);
        }
        return "Permissions: " + permissions + ". Channels: " + channels + ".";
    }

    private void dispatch(Map<String, String> attributes) {
        eventController.dispatchEvent(new ServerEvent(
                serverId, RbacServletInterface.PLUGIN_NAME, Level.INFORMATION, Outcome.SUCCESS, attributes));
    }
}
