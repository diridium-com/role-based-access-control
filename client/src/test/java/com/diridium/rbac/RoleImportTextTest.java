// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

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

    private static ChannelNameMatch match(String name) {
        ChannelNameMatch m = new ChannelNameMatch();
        m.setName(name);
        return m;
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

    @Test
    void details_everyPartInOrder() {
        RoleImportRow r = row(RoleImportRow.Action.OVERWRITE);
        r.setReason("The role exists here.");
        r.setAddedPermissions(Arrays.asList("a", "b"));
        r.setRemovedPermissions(Arrays.asList("c"));
        r.setAddedChannels(Arrays.asList("One", "Two"));
        r.setRemovedChannels(Arrays.asList("Three"));
        r.setDescriptionChanged(true);
        r.setChannels(RoleImportRow.Channels.KEPT);
        r.setDroppedPermissions(Arrays.asList("x", "y"));
        r.setUnmatchedChannels(Arrays.asList("Gone"));
        assertEquals("The role exists here.; Adds permissions: a, b; Removes permissions: c; "
                + "Adds channels: One, Two; Removes channels: Three; Changes the description; "
                + "Keeps its channels here; Left out, not on this engine: x, y; Channels not found: Gone",
                RoleImportText.details(r));
    }

    @Test
    void details_onlyWhatApplies_nullListsTolerated() {
        RoleImportRow r = row(RoleImportRow.Action.CREATE);
        r.setAddedPermissions(null);
        r.setDroppedPermissions(null);
        r.setChannels(RoleImportRow.Channels.FROM_FILE);
        assertEquals("", RoleImportText.details(r));
        r.setUnmatchedChannels(Collections.singletonList("Solo"));
        assertEquals("Channels not found: Solo", RoleImportText.details(r));
    }

    @Test
    void details_unchangedSaysSameOnlyWhenNothingElseApplies() {
        assertEquals("Same as the role here", RoleImportText.details(row(RoleImportRow.Action.UNCHANGED)));
        RoleImportRow withReason = row(RoleImportRow.Action.UNCHANGED);
        withReason.setReason("Nothing to do.");
        assertEquals("Nothing to do.", RoleImportText.details(withReason));
        // Other actions with nothing to say stay empty.
        assertEquals("", RoleImportText.details(row(RoleImportRow.Action.SKIP)));
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
    void nameMatchNote() {
        List<ChannelNameMatch> matches = Arrays.asList(match("probe one"), match("probe two"));
        assertEquals("Channels in the file that match a channel here only by name:\nprobe one\nprobe two\n"
                + "Tick \"Also match channels by name\" to use them.",
                RoleImportText.nameMatchNote(matches, true, false));
        assertEquals("Channels in the file that match a channel here only by name:\nprobe one\nprobe two",
                RoleImportText.nameMatchNote(matches, true, true));
        assertNull(RoleImportText.nameMatchNote(matches, false, false));
        assertNull(RoleImportText.nameMatchNote(Collections.emptyList(), true, false));
        assertNull(RoleImportText.nameMatchNote(null, true, false));
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
