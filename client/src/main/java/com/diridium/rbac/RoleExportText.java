// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

/**
 * The counts and table rows of the Export Roles dialog, kept free of Swing so they can be
 * unit tested. Shares its wording constants with {@link RoleImportText}.
 */
final class RoleExportText {

    static final String[] CHANNEL_COLUMNS = {"Channel", "Id on this engine"};
    static final String EVERY_CHANNEL_LINE = "This role sees every channel.";
    static final String NO_CHANNEL_LINE = "This role sees no channels.";

    private RoleExportText() {
    }

    /** The Permissions count of the export table. */
    static String permissionsCount(Role role) {
        return String.valueOf(role.getPermissions() == null ? 0 : role.getPermissions().size());
    }

    /** The Channels count of the export table: "every" when not restricted, "none" when restricted to no id, else the number of ids. */
    static String channelsCount(Role role) {
        if (!role.isRestricted()) {
            return RoleImportText.EVERY;
        }
        int count = role.getChannelIds() == null ? 0 : role.getChannelIds().size();
        return count == 0 ? RoleImportText.NONE : String.valueOf(count);
    }

    /** The line in place of the channels table: the every-channel or no-channel line, "" when ids are listed. */
    static String channelsLine(Role role) {
        if (!role.isRestricted()) {
            return EVERY_CHANNEL_LINE;
        }
        return role.getChannelIds() == null || role.getChannelIds().isEmpty() ? NO_CHANNEL_LINE : "";
    }

    /** A role's permissions, sorted. */
    static List<String[]> permissionRows(Role role) {
        List<String[]> rows = new ArrayList<>();
        for (String name : new TreeSet<>(role.getPermissions() == null
                ? Collections.<String>emptySet() : role.getPermissions())) {
            rows.add(new String[] {name});
        }
        return rows;
    }

    /**
     * A role's channels as Channel and Id, in name order. An id the map lacks reads
     * "(no longer exists)"; with no map at all, "(channel list not loaded)".
     */
    static List<String[]> channelRows(Role role, Map<String, String> channelMap) {
        List<String[]> rows = new ArrayList<>();
        if (role.getChannelIds() != null) {
            for (String id : role.getChannelIds()) {
                String name = channelMap == null ? RoleImportText.CHANNEL_LIST_NOT_LOADED
                        : channelMap.containsKey(id) ? channelMap.get(id) : RoleImportText.NO_LONGER_EXISTS;
                rows.add(new String[] {RoleImportText.text(name), id});
            }
        }
        rows.sort((a, b) -> {
            int byName = String.CASE_INSENSITIVE_ORDER.compare(a[0], b[0]);
            return byName != 0 ? byName : a[1].compareTo(b[1]);
        });
        return rows;
    }
}
