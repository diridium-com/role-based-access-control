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
    void keepTicks_noChannelFoundRowStartsTicked_andKeepsTheUsersUntick() {
        RoleImportRow none = row(0, "Lab", RoleImportRow.Action.CREATE);
        none.setNoChannelFound(true);
        List<RoleImportRow> rows = Arrays.asList(none);
        assertTrue(RoleImportText.keepTicks(Collections.<RoleImportRow>emptyList(), new boolean[0], rows)[0],
                "restricted to no channel grants nothing, so it starts ticked like any new role");
        assertFalse(RoleImportText.keepTicks(rows, new boolean[] {false}, rows)[0], "the user unticked it");
        RoleImportRow found = row(0, "Lab", RoleImportRow.Action.CREATE);
        assertTrue(RoleImportText.keepTicks(rows, new boolean[] {false}, Arrays.asList(found))[0],
                "its channels found after matching by name: the default for a new role applies again");
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
        assertTrue(RoleImportText.defaultTicked(row(RoleImportRow.Action.CREATE)));
        assertFalse(RoleImportText.defaultTicked(row(RoleImportRow.Action.OVERWRITE)));
        assertFalse(RoleImportText.defaultTicked(row(RoleImportRow.Action.UNCHANGED)));
        assertFalse(RoleImportText.defaultTicked(row(RoleImportRow.Action.SKIP)));
        RoleImportRow none = row(RoleImportRow.Action.CREATE);
        none.setNoChannelFound(true);
        assertTrue(RoleImportText.defaultTicked(none), "no channel found: still ticked, the role sees no channel");
        RoleImportRow noneOver = row(RoleImportRow.Action.OVERWRITE);
        noneOver.setNoChannelFound(true);
        assertFalse(RoleImportText.defaultTicked(noneOver));
        assertTrue(RoleImportText.tickable(RoleImportRow.Action.CREATE));
        assertTrue(RoleImportText.tickable(RoleImportRow.Action.OVERWRITE));
        assertFalse(RoleImportText.tickable(RoleImportRow.Action.UNCHANGED));
        assertFalse(RoleImportText.tickable(RoleImportRow.Action.SKIP));
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

    @Test
    void notes_isTheServersReason_orEmpty() {
        RoleImportRow r = row(RoleImportRow.Action.OVERWRITE);
        r.setReason("The role exists here.");
        r.setChannels(RoleImportRow.Channels.KEPT);
        assertEquals("The role exists here.", RoleImportText.notes(r));
        assertEquals("", RoleImportText.notes(row(RoleImportRow.Action.UNCHANGED)), "nothing composed on the client");
        assertEquals("", RoleImportText.notes(row(RoleImportRow.Action.SKIP)));
    }

    @Test
    void countText_arrowEveryAndNone() {
        RoleImportRow created = row(RoleImportRow.Action.CREATE);
        created.setPermissionsAfter(Arrays.asList("a", "b", "c"));
        assertEquals("3", RoleImportText.permissionsCountText(created), "a role not here: the after count");
        assertEquals("every", RoleImportText.channelsCountText(created), "not restricted: every channel");
        created.setRestrictedAfter(true);
        assertEquals("none", RoleImportText.channelsCountText(created), "restricted, nothing used: none");

        RoleImportRow over = row(RoleImportRow.Action.OVERWRITE);
        over.setExistsHere(true);
        over.setPermissionsNow(Arrays.asList("a", "b", "c", "d", "e", "f"));
        over.setPermissionsAfter(Arrays.asList("a", "b", "c", "d", "e", "f", "g"));
        assertEquals("6 \u2192 7", RoleImportText.permissionsCountText(over));
        over.setPermissionsAfter(Arrays.asList("a", "b", "c", "d", "e", "g"));
        assertEquals("6", RoleImportText.permissionsCountText(over), "equal counts show once");

        over.setRestrictedNow(true);
        over.setRestrictedAfter(true);
        over.setChannelsNow(Arrays.asList(ch("a", "A", null, null, RoleImportChannel.Match.BY_ID, true),
                ch("b", "B", null, null, RoleImportChannel.Match.BY_ID, true)));
        over.setChannelsAfter(Arrays.asList(ch("a", "A", "A", "a", RoleImportChannel.Match.BY_ID, true),
                ch("c", "C", "C", "c", RoleImportChannel.Match.BY_ID, true),
                ch("d", "D", "D", "d", RoleImportChannel.Match.BY_NAME, false)));
        assertEquals("2", RoleImportText.channelsCountText(over), "only used entries count, so 2 and 2");
        over.setChannelsAfter(Arrays.asList(ch("a", "A", "A", "a", RoleImportChannel.Match.BY_ID, true)));
        assertEquals("2 \u2192 1", RoleImportText.channelsCountText(over));
        over.setChannelsAfter(Collections.<RoleImportChannel>emptyList());
        assertEquals("2 \u2192 none", RoleImportText.channelsCountText(over), "restricted, nothing used");
        over.setRestrictedAfter(false);
        assertEquals("2 \u2192 every", RoleImportText.channelsCountText(over));
        over.setRestrictedNow(false);
        over.setChannelsNow(Collections.<RoleImportChannel>emptyList());
        over.setRestrictedAfter(true);
        over.setChannelsAfter(Arrays.asList(ch("a", "A", "A", "a", RoleImportChannel.Match.BY_ID, true),
                ch("c", "C", "C", "c", RoleImportChannel.Match.BY_ID, true)));
        assertEquals("every \u2192 2", RoleImportText.channelsCountText(over));
        over.setRestrictedAfter(false);
        over.setChannelsAfter(Collections.<RoleImportChannel>emptyList());
        assertEquals("every", RoleImportText.channelsCountText(over));
        over.setRestrictedNow(true);
        assertEquals("none \u2192 every", RoleImportText.channelsCountText(over), "restricted to no channel now");
    }

    @Test
    void countText_unchangedAndSkippedShowNow_skippedNotHereShowsZero() {
        RoleImportRow same = row(RoleImportRow.Action.UNCHANGED);
        same.setExistsHere(true);
        same.setPermissionsNow(Arrays.asList("a"));
        same.setPermissionsAfter(Arrays.asList("a", "b"));
        assertEquals("1", RoleImportText.permissionsCountText(same));
        RoleImportRow skipHere = row(RoleImportRow.Action.SKIP);
        skipHere.setExistsHere(true);
        skipHere.setRestrictedNow(true);
        skipHere.setChannelsNow(Arrays.asList(ch("a", "A", null, null, RoleImportChannel.Match.BY_ID, true)));
        assertEquals("1", RoleImportText.channelsCountText(skipHere));
        skipHere.setChannelsNow(Collections.<RoleImportChannel>emptyList());
        assertEquals("none", RoleImportText.channelsCountText(skipHere));
        skipHere.setRestrictedNow(false);
        assertEquals("every", RoleImportText.channelsCountText(skipHere));
        RoleImportRow skipNotHere = row(RoleImportRow.Action.SKIP);
        skipNotHere.setRestrictedAfter(true);
        assertEquals("none", RoleImportText.channelsCountText(skipNotHere), "not here: the after value"
                + " (the server does not set restrictedAfter on a skipped row, so this is every in practice)");
    }

    @Test
    void everyChannelText_everyAndNoneNowAndAfter() {
        RoleImportRow r = row(RoleImportRow.Action.OVERWRITE);
        r.setExistsHere(true);
        assertEquals("This role sees every channel currently. This role sees every channel after the import.",
                RoleImportText.everyChannelText(r));
        r.setRestrictedAfter(true);
        r.setChannelsAfter(Arrays.asList(ch("a", "A", "A", "a", RoleImportChannel.Match.BY_ID, true)));
        assertEquals("This role sees every channel currently.", RoleImportText.everyChannelText(r));
        r.setRestrictedNow(true);
        r.setChannelsNow(Arrays.asList(ch("a", "A", null, null, RoleImportChannel.Match.BY_ID, true)));
        r.setRestrictedAfter(false);
        r.setChannelsAfter(Collections.<RoleImportChannel>emptyList());
        assertEquals("This role sees every channel after the import.", RoleImportText.everyChannelText(r));
        r.setRestrictedAfter(true);
        r.setChannelsNow(Collections.<RoleImportChannel>emptyList());
        assertEquals("This role sees no channels currently. This role sees no channels after the import.",
                RoleImportText.everyChannelText(r));
        r.setRestrictedNow(false);
        assertEquals("This role sees every channel currently. This role sees no channels after the import.",
                RoleImportText.everyChannelText(r));
        RoleImportRow created = row(RoleImportRow.Action.CREATE);
        created.setRestrictedAfter(true);
        assertEquals("This role sees no channels after the import.", RoleImportText.everyChannelText(created),
                "a new role: nothing currently");
        assertEquals("", RoleImportText.everyChannelText(row(RoleImportRow.Action.SKIP)), "skipped, not here");
    }

    @Test
    void compareCounts_numbersByValue_everyLast() {
        assertTrue(RoleImportText.compareCounts("9", "10") < 0);
        assertTrue(RoleImportText.compareCounts("10", "every") < 0);
        assertTrue(RoleImportText.compareCounts("10", "none") < 0);
        assertTrue(RoleImportText.compareCounts("6 \u2192 7", "7") < 0);
        assertEquals(0, RoleImportText.compareCounts("every", "every"));
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
        assertEquals("1 channel in the import matches a channel on this engine by name only. "
                + "Tick the box above to use them.", RoleImportText.nameMatchHint(1, true, false));
        assertEquals("2 channels in the import match a channel on this engine by name only. "
                + "Tick the box above to use them.", RoleImportText.nameMatchHint(2, true, false));
        assertNull(RoleImportText.nameMatchHint(2, true, true), "gone once the box is ticked");
        assertNull(RoleImportText.nameMatchHint(2, false, false));
        assertNull(RoleImportText.nameMatchHint(0, true, false));
    }

    @Test
    void nameMatchHint_followsTheSettingsOfThePreviewShown() {
        RoleImportResult r = new RoleImportResult();
        r.setChannelNameMatches(Arrays.asList(new ChannelNameMatch(), new ChannelNameMatch()));
        r.setApplyChannels(true);
        assertEquals("2 channels in the import match a channel on this engine by name only. "
                + "Tick the box above to use them.", RoleImportText.nameMatchHint(r));
        r.setMatchChannelsByName(true);
        assertNull(RoleImportText.nameMatchHint(r), "that preview matched by name");
        r.setMatchChannelsByName(false);
        r.setApplyChannels(false);
        assertNull(RoleImportText.nameMatchHint(r), "that preview did not apply channel restrictions");
        assertNull(RoleImportText.nameMatchHint(new RoleImportResult()), "no matches");
    }

    @Test
    void previewAgainAfter_onlyAFailureTheServerAnswered() {
        assertTrue(RoleImportText.previewAgainAfter(new ClientException("Method failed: HTTP/1.1 409 Conflict",
                new EntityException("The roles changed since the preview. Preview the import again."))));
        assertTrue(RoleImportText.previewAgainAfter(
                new ForbiddenException("HTTP/1.1 403 Importing roles needs the admin role.")));
        assertFalse(RoleImportText.previewAgainAfter(new ClientException(new java.io.IOException("Connection reset"))),
                "a lost connection: one error, no preview");
        assertFalse(RoleImportText.previewAgainAfter(new IllegalStateException("not a server answer")));
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
