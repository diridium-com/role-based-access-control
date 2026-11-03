// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeSet;

import com.mirth.connect.client.core.EntityException;
import com.mirth.connect.client.core.ForbiddenException;

/**
 * The wording and the small decisions of the role export and import dialogs, kept free of
 * Swing so they can be unit tested. The strings match the web administrator's.
 */
final class RoleImportText {

    static final String EVERY_CHANNEL = "Every channel";

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
     * The Notes cell: the row's reason if any, then "Keeps its channels here" when the
     * channel restrictions were not applied to an existing role, then "Same as the role
     * here" for an Unchanged row with nothing else. Joined with "; ".
     */
    static String notes(RoleImportRow row) {
        List<String> parts = new ArrayList<>();
        if (row.getReason() != null && !row.getReason().trim().isEmpty()) {
            parts.add(row.getReason());
        }
        if (row.getChannels() == RoleImportRow.Channels.KEPT) {
            parts.add("Keeps its channels here");
        }
        if (parts.isEmpty() && row.getAction() == RoleImportRow.Action.UNCHANGED) {
            parts.add("Same as the role here");
        }
        return String.join("; ", parts);
    }

    /**
     * The line under the tick boxes saying how many channels in the file match a channel
     * here only by name, or null when there is nothing to say (channel restrictions not
     * applied, no such channels, or the match-by-name box already ticked).
     */
    static String nameMatchHint(int count, boolean applyChannels, boolean matchByName) {
        if (!applyChannels || matchByName || count <= 0) {
            return null;
        }
        return count + " channel(s) in the file match a channel here only by name. Tick the box above to use them.";
    }

    /** One entry of a Channels now cell: the channel's name, or its id and "(deleted channel)". */
    static String channelNowLabel(RoleImportChannel channel) {
        return channel.getName() != null ? channel.getName() : channel.getId() + " (deleted channel)";
    }

    /** One entry of a Channels after cell: the channel and how it was found. */
    static String channelAfterLabel(RoleImportChannel channel) {
        if (channel.getFileName() == null) {
            return channelNowLabel(channel);
        }
        RoleImportChannel.Match match = channel.getMatch();
        if (match == RoleImportChannel.Match.BY_ID) {
            if (Objects.equals(channel.getName(), channel.getFileName())) {
                return channel.getName() + " (found by id)";
            }
            return channel.getName() + " (found by id, named \"" + channel.getFileName() + "\" in the file)";
        }
        if (match == RoleImportChannel.Match.BY_NAME) {
            return channel.getName() + (channel.isUsed() ? " (found by name)" : " (found by name, not used)");
        }
        return (channel.getName() != null ? channel.getName() : channel.getId()) + " (not found here)";
    }

    /** The Channels now cell: empty with no role here, "Every channel" with no list, else a line each. */
    static String channelsNowCell(RoleImportRow row) {
        if (!row.isExistsHere()) {
            return "";
        }
        List<RoleImportChannel> list = row.getChannelsNow();
        if (list == null || list.isEmpty()) {
            return EVERY_CHANNEL;
        }
        List<String> lines = new ArrayList<>();
        for (RoleImportChannel channel : list) {
            lines.add(channelNowLabel(channel));
        }
        return String.join("\n", lines);
    }

    /** The Channels after cell; empty on a Skipped row with no list, since nothing was looked up. */
    static String channelsAfterCell(RoleImportRow row) {
        List<RoleImportChannel> list = row.getChannelsAfter();
        if (list == null || list.isEmpty()) {
            return row.getAction() == RoleImportRow.Action.SKIP ? "" : EVERY_CHANNEL;
        }
        List<String> lines = new ArrayList<>();
        for (RoleImportChannel channel : list) {
            lines.add(channelAfterLabel(channel));
        }
        return String.join("\n", lines);
    }

    /** The Permissions now cell, one permission per line. */
    static String permissionsNowCell(RoleImportRow row) {
        return row.getPermissionsNow() == null ? "" : String.join("\n", row.getPermissionsNow());
    }

    /** The Permissions after cell: one per line, then each permission left out because this engine lacks it. */
    static String permissionsAfterCell(RoleImportRow row) {
        List<String> lines = new ArrayList<>();
        if (row.getPermissionsAfter() != null) {
            lines.addAll(row.getPermissionsAfter());
        }
        if (row.getDroppedPermissions() != null) {
            for (String dropped : row.getDroppedPermissions()) {
                lines.add(dropped + " (not on this engine, left out)");
            }
        }
        return String.join("\n", lines);
    }

    /**
     * The Channels cell of the export table: "Every channel" for a role with no channel
     * ids, else one line per id, named channels first by name, then the unknown ids. A null
     * map means the channel list was not loaded.
     */
    static String exportChannelsCell(Role role, Map<String, String> channelMap) {
        if (role.getChannelIds() == null || role.getChannelIds().isEmpty()) {
            return EVERY_CHANNEL;
        }
        TreeSet<String> named = new TreeSet<>();
        TreeSet<String> unknown = new TreeSet<>();
        for (String id : role.getChannelIds()) {
            String name = channelMap == null ? null : channelMap.get(id);
            if (name != null) {
                named.add(name + "\0" + id);
            } else {
                unknown.add(id + (channelMap == null ? " (channel list not loaded)" : " (deleted channel)"));
            }
        }
        List<String> lines = new ArrayList<>();
        for (String entry : named) {
            lines.add(entry.substring(0, entry.indexOf('\0')));
        }
        lines.addAll(unknown);
        return String.join("\n", lines);
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

    private static String orUnknown(String value) {
        return value == null || value.isEmpty() ? "unknown" : value;
    }
}
