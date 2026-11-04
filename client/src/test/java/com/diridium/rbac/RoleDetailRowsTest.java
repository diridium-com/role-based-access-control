// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;

class RoleDetailRowsTest {

    private static RoleImportRow row(RoleImportRow.Action action) {
        RoleImportRow r = new RoleImportRow();
        r.setAction(action);
        return r;
    }

    private static RoleImportChannel ch(String id, String name, String fileName, String fileId,
            RoleImportChannel.Match match, boolean used) {
        RoleImportChannel c = new RoleImportChannel();
        c.setId(id);
        c.setName(name);
        c.setFileName(fileName);
        c.setFileId(fileId);
        c.setMatch(match);
        c.setUsed(used);
        return c;
    }

    private static List<String> cols(String[] cells) {
        return Arrays.asList(cells);
    }

    @Test
    void headers_andLegendsAreTheAgreedWording() {
        assertEquals(Arrays.asList("Permission", "Currently", "After import", "Note"),
                Arrays.asList(RoleDetailRows.PERMISSION_COLUMNS));
        assertEquals(Arrays.asList("Channel", "Id on this engine", "Currently", "After import", "Match",
                "Name in import", "Id in import"), Arrays.asList(RoleDetailRows.CHANNEL_COLUMNS));
        assertEquals("Currently: this role has the permission on this engine. "
                + "After import: this role will have the permission if imported.", RoleDetailRows.PERMISSIONS_LEGEND);
        assertEquals("Currently: this role is restricted to the channel on this engine. "
                + "After import: this role will be restricted to the channel if imported. "
                + "Match: how the import's channel was found on this engine.", RoleDetailRows.CHANNELS_LEGEND);
        assertEquals("Channel restrictions from the import are not applied. Roles that already exist on this engine "
                + "keep their current channels. New roles see every channel.", RoleDetailRows.CHANNELS_NOT_APPLIED);
    }

    @Test
    void permissionRows_unionSortedWithCurrentlyAfterAndNote() {
        RoleImportRow r = row(RoleImportRow.Action.OVERWRITE);
        r.setPermissionsNow(Arrays.asList("a", "b"));
        r.setPermissionsAfter(Arrays.asList("a", "c"));
        r.setDroppedPermissions(Arrays.asList("x"));
        List<String[]> rows = RoleDetailRows.permissionRows(r);
        assertEquals(4, rows.size());
        assertEquals(Arrays.asList("a", "yes", "yes", ""), cols(rows.get(0)));
        assertEquals(Arrays.asList("b", "yes", "", ""), cols(rows.get(1)));
        assertEquals(Arrays.asList("c", "", "yes", ""), cols(rows.get(2)));
        assertEquals(Arrays.asList("x", "", "", "not on this engine, left out"), cols(rows.get(3)));
    }

    @Test
    void matchText_everyCase() {
        assertEquals("by id", RoleDetailRows.matchText(ch("a", "Lab", "Lab", "fa", RoleImportChannel.Match.BY_ID, true)));
        assertEquals("by id, renamed on this engine",
                RoleDetailRows.matchText(ch("a", "New", "Old", "a", RoleImportChannel.Match.BY_ID, true)));
        assertEquals("by name", RoleDetailRows.matchText(ch("a", "Lab", "Lab", "fa", RoleImportChannel.Match.BY_NAME, true)));
        assertEquals("by name, not used",
                RoleDetailRows.matchText(ch("a", "Lab", "Lab", "fa", RoleImportChannel.Match.BY_NAME, false)));
        assertEquals("not on this engine",
                RoleDetailRows.matchText(ch("fa", "Gone", "Gone", "fa", RoleImportChannel.Match.NOT_FOUND, false)));
    }

    @Test
    void channelRows_importOrder_thenNotInImport_thenDeletedLast() {
        RoleImportRow r = row(RoleImportRow.Action.OVERWRITE);
        r.setExistsHere(true);
        r.setChannelsNow(Arrays.asList(
                ch("id-lab", "Lab", null, null, RoleImportChannel.Match.BY_ID, true),
                ch("id-gone", null, null, null, RoleImportChannel.Match.NOT_FOUND, true),
                ch("id-own", "Own", null, null, RoleImportChannel.Match.BY_ID, true),
                ch("file-d", null, null, null, RoleImportChannel.Match.NOT_FOUND, true)));
        r.setChannelsAfter(Arrays.asList(
                ch("id-lab", "Lab", "Lab", "id-lab", RoleImportChannel.Match.BY_ID, true),
                ch("id-ren", "Renamed here", "Old name", "id-ren", RoleImportChannel.Match.BY_ID, true),
                ch("id-n1", "Beta", "Beta", "file-n1", RoleImportChannel.Match.BY_NAME, true),
                ch("id-n2", "Gamma", "Gamma", "file-n2", RoleImportChannel.Match.BY_NAME, false),
                ch("file-x", "Missing", "Missing", "file-x", RoleImportChannel.Match.NOT_FOUND, false),
                ch("file-y", null, null, "file-y", RoleImportChannel.Match.NOT_FOUND, false),
                ch("file-d", null, "Dropped", "file-d", RoleImportChannel.Match.NOT_FOUND, false)));
        List<String[]> rows = RoleDetailRows.channelRows(r);
        assertEquals(9, rows.size());
        assertEquals(Arrays.asList("Lab", "id-lab", "yes", "yes", "by id", "Lab", "id-lab"), cols(rows.get(0)),
                "a channel both here and in the import is one row");
        assertEquals(Arrays.asList("Renamed here", "id-ren", "", "yes", "by id, renamed on this engine", "Old name",
                "id-ren"), cols(rows.get(1)));
        assertEquals(Arrays.asList("Beta", "id-n1", "", "yes", "by name", "Beta", "file-n1"), cols(rows.get(2)));
        assertEquals(Arrays.asList("Gamma", "id-n2", "", "", "by name, not used", "Gamma", "file-n2"), cols(rows.get(3)));
        assertEquals(Arrays.asList("Missing", "", "", "", "not on this engine", "Missing", "file-x"), cols(rows.get(4)));
        assertEquals(Arrays.asList("(no longer exists)", "", "", "", "not on this engine", "", "file-y"),
                cols(rows.get(5)), "no name anywhere");
        assertEquals(Arrays.asList("Dropped", "file-d", "yes", "", "deleted on this engine", "Dropped", "file-d"),
                cols(rows.get(6)), "restricted to it here, gone, and the import names it: one row, id shown");
        assertEquals(Arrays.asList("Own", "id-own", "yes", "", "not in the import", "", ""), cols(rows.get(7)));
        assertEquals(Arrays.asList("(no longer exists)", "id-gone", "yes", "", "deleted on this engine", "", ""),
                cols(rows.get(8)), "deleted and not in the import");
    }

    @Test
    void channelRows_keptChannelsAreCurrentlyAndAfterWithNoImportColumns() {
        RoleImportRow r = row(RoleImportRow.Action.OVERWRITE);
        r.setExistsHere(true);
        r.setChannels(RoleImportRow.Channels.KEPT);
        r.setChannelsNow(Arrays.asList(ch("a", "Alpha", null, null, RoleImportChannel.Match.BY_ID, true)));
        r.setChannelsAfter(Arrays.asList(ch("a", "Alpha", null, null, RoleImportChannel.Match.BY_ID, true)));
        List<String[]> rows = RoleDetailRows.channelRows(r);
        assertEquals(1, rows.size());
        assertEquals(Arrays.asList("Alpha", "a", "yes", "yes", "", "", ""), cols(rows.get(0)));
    }
}
