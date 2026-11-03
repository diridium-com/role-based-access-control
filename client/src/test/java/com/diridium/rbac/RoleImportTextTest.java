// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.mirth.connect.client.core.ClientException;
import com.mirth.connect.client.core.EntityException;
import com.mirth.connect.client.core.ForbiddenException;

class RoleImportTextTest {

    private static RoleImportRow row(RoleImportRow.Action action) {
        RoleImportRow r = new RoleImportRow();
        r.setAction(action);
        return r;
    }

    private static RoleImportRow row(int index, String name, RoleImportRow.Action action) {
        RoleImportRow r = row(action);
        r.setIndex(index);
        r.setName(name);
        return r;
    }

    @Test
    void keepTicks_keepsTheUsersTickForTheSameRow_andDefaultsTheRest() {
        List<RoleImportRow> before = Arrays.asList(
                row(0, "Lab", RoleImportRow.Action.CREATE),
                row(1, "Ops", RoleImportRow.Action.OVERWRITE),
                row(2, "Old", RoleImportRow.Action.SKIP),
                row(3, "Desk", RoleImportRow.Action.CREATE));
        boolean[] tickedBefore = { false, true, false, true };
        List<RoleImportRow> after = Arrays.asList(
                row(0, "Lab", RoleImportRow.Action.CREATE),
                row(1, "Ops", RoleImportRow.Action.OVERWRITE),
                row(2, "Old", RoleImportRow.Action.CREATE),
                row(3, "Desk", RoleImportRow.Action.OVERWRITE),
                row(4, "New", RoleImportRow.Action.CREATE),
                row(5, "Same", RoleImportRow.Action.UNCHANGED));
        boolean[] ticked = RoleImportText.keepTicks(before, tickedBefore, after);
        assertFalse(ticked[0], "the user unticked a New row; it stays unticked");
        assertTrue(ticked[1], "the user ticked an Overwrite row; it stays ticked");
        assertTrue(ticked[2], "Skipped became New: its default");
        assertFalse(ticked[3], "New became Overwrite: its default");
        assertTrue(ticked[4], "a row that wasn't there: its default");
        assertFalse(ticked[5], "Unchanged can't be ticked");
    }

    @Test
    void keepTicks_withNoEarlierPreview_givesTheDefaults() {
        boolean[] ticked = RoleImportText.keepTicks(Collections.emptyList(), new boolean[0], Arrays.asList(
                row(0, "Lab", RoleImportRow.Action.CREATE), row(1, "Ops", RoleImportRow.Action.OVERWRITE)));
        assertTrue(ticked[0]);
        assertFalse(ticked[1]);
    }

    @Test
    void actionLabels() {
        assertEquals("New", RoleImportText.actionLabel(RoleImportRow.Action.CREATE));
        assertEquals("Overwrite", RoleImportText.actionLabel(RoleImportRow.Action.OVERWRITE));
        assertEquals("Unchanged", RoleImportText.actionLabel(RoleImportRow.Action.UNCHANGED));
        assertEquals("Skipped", RoleImportText.actionLabel(RoleImportRow.Action.SKIP));
    }

    @Test
    void defaultTicksAndTickable() {
        assertTrue(RoleImportText.defaultTicked(RoleImportRow.Action.CREATE));
        assertFalse(RoleImportText.defaultTicked(RoleImportRow.Action.OVERWRITE));
        assertFalse(RoleImportText.defaultTicked(RoleImportRow.Action.UNCHANGED));
        assertFalse(RoleImportText.defaultTicked(RoleImportRow.Action.SKIP));
        assertTrue(RoleImportText.tickable(RoleImportRow.Action.CREATE));
        assertTrue(RoleImportText.tickable(RoleImportRow.Action.OVERWRITE));
        assertFalse(RoleImportText.tickable(RoleImportRow.Action.UNCHANGED));
        assertFalse(RoleImportText.tickable(RoleImportRow.Action.SKIP));
    }

    private static RoleImportChannel ch(String id, String name, String fileName, RoleImportChannel.Match match,
            boolean used) {
        RoleImportChannel c = new RoleImportChannel();
        c.setId(id);
        c.setName(name);
        c.setFileName(fileName);
        c.setMatch(match);
        c.setUsed(used);
        return c;
    }

    @Test
    void notes_reasonThenKept_thenSameForUnchanged() {
        RoleImportRow r = row(RoleImportRow.Action.OVERWRITE);
        r.setReason("The role exists here.");
        r.setChannels(RoleImportRow.Channels.KEPT);
        assertEquals("The role exists here.; Keeps its channels here", RoleImportText.notes(r));
        r.setReason(null);
        assertEquals("Keeps its channels here", RoleImportText.notes(r));
        r.setChannels(RoleImportRow.Channels.FROM_FILE);
        assertEquals("", RoleImportText.notes(r));
        assertEquals("Same as the role here", RoleImportText.notes(row(RoleImportRow.Action.UNCHANGED)));
        RoleImportRow withReason = row(RoleImportRow.Action.UNCHANGED);
        withReason.setReason("Nothing to do.");
        assertEquals("Nothing to do.", RoleImportText.notes(withReason));
        assertEquals("", RoleImportText.notes(row(RoleImportRow.Action.SKIP)));
    }

    @Test
    void channelNowLabel_nameOrDeleted() {
        assertEquals("Lab feed", RoleImportText.channelNowLabel(ch("a1", "Lab feed", null, RoleImportChannel.Match.BY_ID, true)));
        assertEquals("a2 (deleted channel)",
                RoleImportText.channelNowLabel(ch("a2", null, null, RoleImportChannel.Match.NOT_FOUND, true)));
    }

    @Test
    void channelAfterLabel_everyCase() {
        assertEquals("Lab feed", RoleImportText.channelAfterLabel(ch("a", "Lab feed", null, RoleImportChannel.Match.BY_ID, true)));
        assertEquals("a (deleted channel)",
                RoleImportText.channelAfterLabel(ch("a", null, null, RoleImportChannel.Match.NOT_FOUND, true)));
        assertEquals("Lab feed (found by id)",
                RoleImportText.channelAfterLabel(ch("a", "Lab feed", "Lab feed", RoleImportChannel.Match.BY_ID, true)));
        assertEquals("New name (found by id, named \"Old name\" in the file)",
                RoleImportText.channelAfterLabel(ch("a", "New name", "Old name", RoleImportChannel.Match.BY_ID, true)));
        assertEquals("Lab feed (found by name)",
                RoleImportText.channelAfterLabel(ch("a", "Lab feed", "Lab feed", RoleImportChannel.Match.BY_NAME, true)));
        assertEquals("Lab feed (found by name, not used)",
                RoleImportText.channelAfterLabel(ch("a", "Lab feed", "Lab feed", RoleImportChannel.Match.BY_NAME, false)));
        assertEquals("Gone (not found here)",
                RoleImportText.channelAfterLabel(ch("a", "Gone", "Gone", RoleImportChannel.Match.NOT_FOUND, false)));
        assertEquals("a (not found here)",
                RoleImportText.channelAfterLabel(ch("a", null, "x", RoleImportChannel.Match.NOT_FOUND, false)));
    }

    @Test
    void channelsNowCell() {
        RoleImportRow r = row(RoleImportRow.Action.CREATE);
        assertEquals("", RoleImportText.channelsNowCell(r), "no role here");
        r.setExistsHere(true);
        assertEquals("Every channel", RoleImportText.channelsNowCell(r));
        r.setChannelsNow(Arrays.asList(ch("a", "Alpha", null, RoleImportChannel.Match.BY_ID, true),
                ch("b", null, null, RoleImportChannel.Match.NOT_FOUND, true)));
        assertEquals("Alpha\nb (deleted channel)", RoleImportText.channelsNowCell(r));
    }

    @Test
    void channelsAfterCell() {
        RoleImportRow r = row(RoleImportRow.Action.OVERWRITE);
        assertEquals("Every channel", RoleImportText.channelsAfterCell(r));
        assertEquals("", RoleImportText.channelsAfterCell(row(RoleImportRow.Action.SKIP)), "skipped: nothing looked up");
        r.setChannelsAfter(Arrays.asList(ch("a", "Alpha", "Alpha", RoleImportChannel.Match.BY_ID, true),
                ch("b", "Beta", "Beta", RoleImportChannel.Match.BY_NAME, false)));
        assertEquals("Alpha (found by id)\nBeta (found by name, not used)", RoleImportText.channelsAfterCell(r));
    }

    @Test
    void permissionsCells() {
        RoleImportRow r = row(RoleImportRow.Action.OVERWRITE);
        assertEquals("", RoleImportText.permissionsNowCell(r));
        assertEquals("", RoleImportText.permissionsAfterCell(r));
        r.setPermissionsNow(Arrays.asList("a", "b"));
        r.setPermissionsAfter(Arrays.asList("a", "c"));
        r.setDroppedPermissions(Arrays.asList("x"));
        assertEquals("a\nb", RoleImportText.permissionsNowCell(r));
        assertEquals("a\nc\nx (not on this engine, left out)", RoleImportText.permissionsAfterCell(r));
    }

    @Test
    void exportChannelsCell() {
        Role role = new Role();
        assertEquals("Every channel", RoleImportText.exportChannelsCell(role, new HashMap<>()));
        role.setChannelIds(new HashSet<>(Arrays.asList("c", "b", "a", "z")));
        Map<String, String> map = new HashMap<>();
        map.put("a", "Zulu");
        map.put("b", "Alpha");
        map.put("c", "Mike");
        assertEquals("Alpha\nMike\nZulu\nz (deleted channel)", RoleImportText.exportChannelsCell(role, map));
        assertEquals("a (channel list not loaded)\nb (channel list not loaded)\nc (channel list not loaded)\n"
                + "z (channel list not loaded)", RoleImportText.exportChannelsCell(role, null));
    }

    @Test
    void fromLine() {
        RoleImportResult r = new RoleImportResult();
        r.setSourceRbacVersion("1.2.0");
        r.setSourceEngineVersion("4.7.0");
        assertEquals("From rbac 1.2.0 on OIE 4.7.0.", RoleImportText.fromLine(r));
        assertEquals("From rbac unknown on OIE unknown.", RoleImportText.fromLine(new RoleImportResult()));
    }

    @Test
    void nameMatchHint() {
        assertEquals("2 channel(s) in the file match a channel here only by name. Tick the box above to use them.",
                RoleImportText.nameMatchHint(2, true, false));
        assertNull(RoleImportText.nameMatchHint(2, true, true), "gone once the box is ticked");
        assertNull(RoleImportText.nameMatchHint(2, false, false));
        assertNull(RoleImportText.nameMatchHint(0, true, false));
    }

    @Test
    void serverMessage_conflictAndBadRequestBodies() {
        ClientException conflict = new ClientException("Method failed: HTTP/1.1 409 Conflict",
                new EntityException("The roles changed since the preview. Preview the import again."));
        assertEquals("The roles changed since the preview. Preview the import again.",
                RoleImportText.serverMessage(conflict));
    }

    @Test
    void serverMessage_forbiddenReasonComesFromStatusLine() {
        assertEquals("Importing roles needs the admin role.",
                RoleImportText.serverMessage(new ForbiddenException("HTTP/1.1 403 Importing roles needs the admin role.")));
        assertEquals("You are not authorized to perform this action.",
                RoleImportText.serverMessage(new ForbiddenException("HTTP/1.1 403")));
    }

    @Test
    void serverMessage_otherFailuresAreNotServerMessages() {
        assertNull(RoleImportText.serverMessage(new ClientException(new java.io.IOException("Connection reset"))));
        assertNull(RoleImportText.serverMessage(null));
    }
}
