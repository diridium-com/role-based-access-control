// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;

/**
 * The rows of the two detail tables of the import dialog, for the selected role, kept free
 * of Swing so they can be unit tested. The strings match the web administrator's.
 */
final class RoleDetailRows {

    static final String[] PERMISSION_COLUMNS = {"Permission", "Currently", "After import", "Note"};
    static final String[] CHANNEL_COLUMNS = {"Channel", "Id on this engine", "Currently", "After import", "Match",
            "Name in import", "Id in import"};
    static final String PERMISSIONS_LEGEND = "Currently: this role has the permission on this engine. "
            + "After import: this role will have the permission if imported.";
    static final String CHANNELS_LEGEND = "Currently: this role is restricted to the channel on this engine. "
            + "After import: this role will be restricted to the channel if imported. "
            + "Match: how the import's channel was found on this engine.";
    static final String CHANNELS_NOT_APPLIED = "Channel restrictions from the import are not applied. "
            + "Roles that already exist on this engine keep their current channels. "
            + "New roles are restricted to no channels until an administrator sets channels for them.";
    static final String NOT_ON_ENGINE = "not offered by this engine, left out";
    static final String NOT_IN_IMPORT = "not in the import";
    static final String NO_LONGER_EXISTS = "(no longer exists)";
    static final String DELETED_HERE = "deleted on this engine";

    private RoleDetailRows() {
    }

    /**
     * One row per permission, sorted by name: the union of the role's permissions here, the
     * permissions it would have after, and the ones left out. Columns: PERMISSION_COLUMNS.
     */
    static List<String[]> permissionRows(RoleImportRow row) {
        Set<String> now = new HashSet<>(RoleImportText.list(row.getPermissionsNow()));
        Set<String> after = new HashSet<>(RoleImportText.list(row.getPermissionsAfter()));
        Set<String> dropped = new HashSet<>(RoleImportText.list(row.getDroppedPermissions()));
        TreeSet<String> all = new TreeSet<>(now);
        all.addAll(after);
        all.addAll(dropped);
        List<String[]> rows = new ArrayList<>();
        for (String name : all) {
            rows.add(new String[] {name, now.contains(name) ? RoleImportText.YES : "",
                    after.contains(name) ? RoleImportText.YES : "", dropped.contains(name) ? NOT_ON_ENGINE : ""});
        }
        return rows;
    }

    /**
     * One row per channel: the import's channels in file order (or, for a role that keeps
     * its channels, the kept ones), then the role's other channels on this engine.
     * A channel in both is one row, joined on its id, except a channel the import has that is
     * not on this engine. When that channel's id is one the role is restricted to here and the
     * channel was deleted on this engine, the two are one "deleted on this engine" row.
     * Columns: CHANNEL_COLUMNS.
     */
    static List<String[]> channelRows(RoleImportRow row) {
        boolean kept = row.getChannels() == RoleImportRow.Channels.KEPT;
        Map<String, RoleImportChannel> nowById = new HashMap<>();
        for (RoleImportChannel channel : RoleImportText.list(row.getChannelsNow())) {
            nowById.put(channel.getId(), channel);
        }
        List<String[]> rows = new ArrayList<>();
        Set<String> listed = new HashSet<>();
        for (RoleImportChannel e : RoleImportText.list(row.getChannelsAfter())) {
            boolean missing = !kept && e.getMatch() == RoleImportChannel.Match.NOT_FOUND;
            RoleImportChannel deleted = missing ? nowById.get(e.getId()) : null;
            if (deleted != null && deleted.getName() == null) {
                rows.add(new String[] {NO_LONGER_EXISTS, RoleImportText.text(e.getId()), RoleImportText.YES, "",
                        DELETED_HERE, RoleImportText.text(e.getFileName()), RoleImportText.text(e.getFileId())});
                listed.add(e.getId());
                continue;
            }
            RoleImportChannel now = missing ? null : nowById.get(e.getId());
            String match = kept ? "" : matchText(e);
            rows.add(new String[] {channelName(e.getName(), e.getFileName(), e.getId()),
                    missing ? "" : RoleImportText.text(e.getId()),
                    now != null ? RoleImportText.YES : "", kept || e.isUsed() ? RoleImportText.YES : "", match,
                    RoleImportText.text(e.getFileName()), RoleImportText.text(e.getFileId())});
            listed.add(e.getId());
        }
        for (RoleImportChannel c : RoleImportText.list(row.getChannelsNow())) {
            if (!listed.contains(c.getId())) {
                rows.add(new String[] {channelName(c.getName(), null, c.getId()),
                        RoleImportText.text(c.getId()), RoleImportText.YES, "", NOT_IN_IMPORT, "", ""});
            }
        }
        return rows;
    }

    /** The Channel column: the name on this engine, else the name in the import, else the id. */
    private static String channelName(String name, String nameInImport, String id) {
        if (name != null) {
            return name;
        }
        return !isEmpty(nameInImport) ? nameInImport : RoleImportText.text(id);
    }

    // The exporter writes "" for a channel its engine lacked; the web client receives it as null.
    private static boolean isEmpty(String value) {
        return value == null || value.isEmpty();
    }

    /** The Match column for a channel in the import, from how it was looked up on this engine. */
    static String matchText(RoleImportChannel entry) {
        if (entry.getMatch() == null) {
            return "";
        }
        switch (entry.getMatch()) {
            case BY_ID:
                return isEmpty(entry.getFileName()) || Objects.equals(entry.getName(), entry.getFileName())
                        ? "by id" : "by id, renamed on this engine";
            case BY_NAME:
                return entry.isUsed() ? "by name" : "by name, not used";
            default:
                return "not on this engine";
        }
    }
}
