// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import com.mirth.connect.client.core.EntityException;
import com.mirth.connect.client.core.ForbiddenException;

/**
 * The wording and the small decisions of the role export and import dialogs, kept free of
 * Swing so they can be unit tested. The strings match the web administrator's.
 */
final class RoleImportText {

    static final String CHANNEL_NAME_HEADING = "Channels in the file that match a channel here only by name:";
    static final String CHANNEL_NAME_HINT = "Tick \"Also match channels by name\" to use them.";

    private RoleImportText() {
    }

    static String actionLabel(RoleImportRow.Action action) {
        if (action == null) {
            return "";
        }
        switch (action) {
            case CREATE:
                return "New";
            case OVERWRITE:
                return "Overwrite";
            case UNCHANGED:
                return "Unchanged";
            case SKIP:
                return "Skipped";
            default:
                return action.name();
        }
    }

    /** Only a New or an Overwrite row can be ticked. */
    static boolean tickable(RoleImportRow.Action action) {
        return action == RoleImportRow.Action.CREATE || action == RoleImportRow.Action.OVERWRITE;
    }

    /** New starts ticked; Overwrite starts unticked; the rest can't be ticked. */
    static boolean defaultTicked(RoleImportRow.Action action) {
        return action == RoleImportRow.Action.CREATE;
    }

    /**
     * The ticks for a fresh preview of the same file: a row keeps the user's tick when the
     * row at the same position had the same name and action before; any other row starts
     * at its default. The web administrator's mergeTicks follows the same rule.
     */
    static boolean[] keepTicks(List<RoleImportRow> before, boolean[] tickedBefore, List<RoleImportRow> rows) {
        boolean[] ticked = new boolean[rows.size()];
        for (int i = 0; i < rows.size(); i++) {
            RoleImportRow row = rows.get(i);
            if (!tickable(row.getAction())) {
                continue;
            }
            ticked[i] = defaultTicked(row.getAction());
            for (int j = 0; j < before.size(); j++) {
                RoleImportRow old = before.get(j);
                if (old.getIndex() == row.getIndex()) {
                    if (Objects.equals(old.getName(), row.getName()) && old.getAction() == row.getAction()) {
                        ticked[i] = tickedBefore[j];
                    }
                    break;
                }
            }
        }
        return ticked;
    }

    static String fromLine(RoleImportResult result) {
        return "From rbac " + orUnknown(result.getSourceRbacVersion())
                + " on OIE " + orUnknown(result.getSourceEngineVersion()) + ".";
    }

    /**
     * The Details cell: each part only when it applies, in a fixed order, joined with "; ".
     * "Same as the role here" appears for an Unchanged row that has no other part.
     */
    static String details(RoleImportRow row) {
        List<String> parts = new ArrayList<>();
        if (row.getReason() != null && !row.getReason().trim().isEmpty()) {
            parts.add(row.getReason());
        }
        addList(parts, "Adds permissions: ", row.getAddedPermissions());
        addList(parts, "Removes permissions: ", row.getRemovedPermissions());
        addList(parts, "Adds channels: ", row.getAddedChannels());
        addList(parts, "Removes channels: ", row.getRemovedChannels());
        if (row.isDescriptionChanged()) {
            parts.add("Changes the description");
        }
        if (row.getChannels() == RoleImportRow.Channels.KEPT) {
            parts.add("Keeps its channels here");
        }
        addList(parts, "Left out, not on this engine: ", row.getDroppedPermissions());
        addList(parts, "Channels not found: ", row.getUnmatchedChannels());
        if (parts.isEmpty() && row.getAction() == RoleImportRow.Action.UNCHANGED) {
            parts.add("Same as the role here");
        }
        return String.join("; ", parts);
    }

    /**
     * The note under the tick boxes listing channels that match only by name, or null when
     * there is nothing to show (channel restrictions not applied, or no such channels).
     */
    static String nameMatchNote(List<ChannelNameMatch> matches, boolean applyChannels, boolean matchByName) {
        if (!applyChannels || matches == null || matches.isEmpty()) {
            return null;
        }
        StringBuilder note = new StringBuilder(CHANNEL_NAME_HEADING);
        for (ChannelNameMatch match : matches) {
            note.append('\n').append(match.getName());
        }
        if (!matchByName) {
            note.append('\n').append(CHANNEL_NAME_HINT);
        }
        return note.toString();
    }

    /**
     * The text the server gave for a failed call, or null when the failure is not a server
     * answer with a message (a lost connection, say, which the caller hands to the
     * engine's own error handling). A 400 or 409 arrives as the cause's message; a 403's
     * reason is in the status line ("HTTP/1.1 403 Importing roles needs the admin role.").
     */
    static String serverMessage(Throwable t) {
        if (t instanceof ForbiddenException) {
            String reason = t.getMessage() == null ? "" : t.getMessage().replaceFirst("^HTTP/\\d(\\.\\d)? 403\\s*", "").trim();
            return reason.isEmpty() ? "You are not authorized to perform this action." : reason;
        }
        for (Throwable c = t; c != null; c = c.getCause()) {
            if (c instanceof EntityException && c.getMessage() != null && !c.getMessage().trim().isEmpty()) {
                return c.getMessage().trim();
            }
            if (c.getCause() == c) {
                break;
            }
        }
        return null;
    }

    private static void addList(List<String> parts, String label, List<String> values) {
        if (values != null && !values.isEmpty()) {
            parts.add(label + String.join(", ", values));
        }
    }

    private static String orUnknown(String value) {
        return value == null || value.isEmpty() ? "unknown" : value;
    }
}
