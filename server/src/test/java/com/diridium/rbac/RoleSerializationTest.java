// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;

import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.io.xml.DomDriver;
import com.thoughtworks.xstream.security.WildcardTypePermission;

import org.junit.jupiter.api.Test;

/**
 * Guards the XStream whitelist contract the plugin relies on. {@code Role} is
 * returned over REST, so it must (a) live in the package the {@code allowTypes}
 * wildcard covers, and (b) survive a serialize/deserialize round-trip once that
 * wildcard is registered — otherwise every REST call returning a role throws
 * {@code ForbiddenClassException}.
 *
 * <p>The round-trip uses a plain {@link XStream} with the same wildcard the plugin
 * registers (rather than the engine's {@code ObjectXMLSerializer}, which needs
 * engine static init unavailable in a unit test) and a JDK-only {@link DomDriver}.</p>
 */
class RoleSerializationTest {

    private static final String WILDCARD = "com.diridium.rbac.**";

    @Test
    void roleIsCoveredByTheAllowTypesWildcard() {
        // The plugin registers allowTypes(Role.class.getPackage().getName() + ".**").
        // A package rename that moved Role out of com.diridium.rbac would silently drop
        // it from the whitelist; pin the invariant.
        assertEquals(WILDCARD, Role.class.getPackage().getName() + ".**");
    }

    @Test
    void roleSurvivesXStreamRoundTripUnderTheWildcard() {
        XStream xstream = new XStream(new DomDriver());
        xstream.addPermission(new WildcardTypePermission(new String[] { WILDCARD }));

        Role original = new Role();
        original.setId(42);
        original.setName("Auditor");
        original.setDescription("Read-only with channel limits");
        original.setPermissions(new HashSet<>(Arrays.asList("viewChannels", "viewMessages")));
        original.setChannelIds(new HashSet<>(Arrays.asList("ch-a", "ch-b")));
        original.setRestricted(true);
        original.setAdmin(true);

        String xml = xstream.toXML(original);
        Role restored = (Role) xstream.fromXML(xml);

        // Role has no equals(), so compare field-by-field.
        assertEquals(original.getId(), restored.getId());
        assertEquals(original.getName(), restored.getName());
        assertEquals(original.getDescription(), restored.getDescription());
        assertEquals(original.isAdmin(), restored.isAdmin());
        assertEquals(original.getPermissions(), restored.getPermissions());
        assertEquals(original.getChannelIds(), restored.getChannelIds());
        assertEquals(original.isRestricted(), restored.isRestricted());
        assertTrue(xml.contains("<restricted>"), "the field name is the element name, like isAdmin");
    }

    @Test
    void importResultSurvivesXStreamRoundTripUnderTheWildcard() {
        // Returned by importRoles; its rows carry two nested enums, which the wildcard must cover too.
        XStream xstream = new XStream(new DomDriver());
        xstream.addPermission(new WildcardTypePermission(new String[] { WILDCARD }));

        RoleImportRow row = new RoleImportRow();
        row.setIndex(3);
        row.setName("Lab");
        row.setAction(RoleImportRow.Action.OVERWRITE);
        row.setReason("note");
        row.setDroppedPermissions(new ArrayList<>(Arrays.asList("Run Lab Reports")));
        row.setMatchedChannelCount(2);
        row.setChannels(RoleImportRow.Channels.KEPT);
        row.setNoChannelFound(true);
        row.setExistsHere(true);
        row.setRestrictedNow(true);
        row.setRestrictedAfter(true);
        row.setDescriptionNow("old");
        row.setDescriptionAfter("new");
        row.setPermissionsNow(new ArrayList<>(Arrays.asList("viewMessages")));
        row.setPermissionsAfter(new ArrayList<>(Arrays.asList("viewChannels")));
        RoleImportChannel now = new RoleImportChannel();
        now.setId("id-adt");
        now.setName("ADT Out");
        now.setMatch(RoleImportChannel.Match.BY_ID);
        now.setUsed(true);
        row.setChannelsNow(new ArrayList<>(Arrays.asList(now)));
        RoleImportChannel after = new RoleImportChannel();
        after.setId("id-lab");
        after.setName("Lab In");
        after.setFileId("id-elsewhere");
        after.setFileName("Lab Results In");
        after.setMatch(RoleImportChannel.Match.BY_NAME);
        after.setUsed(false);
        row.setChannelsAfter(new ArrayList<>(Arrays.asList(after)));
        RoleImportResult original = new RoleImportResult();
        original.setImportable(true);
        original.setFormatVersion("1");
        original.setSourceRbacVersion("1.3.0");
        original.setSourceEngineVersion("4.7.0");
        original.setApplyChannels(true);
        original.setPlanToken("abc");
        original.setRows(new ArrayList<>(Arrays.asList(row)));
        ChannelNameMatch match = new ChannelNameMatch();
        match.setName("Lab In");
        match.setFileChannelId("id-elsewhere");
        match.setChannelId("id-lab");
        original.setChannelNameMatches(new ArrayList<>(Arrays.asList(match)));
        original.setMatchChannelsByName(true);

        RoleImportResult restored = (RoleImportResult) xstream.fromXML(xstream.toXML(original));

        assertEquals(original.isImportable(), restored.isImportable());
        assertEquals(original.getFormatVersion(), restored.getFormatVersion());
        assertEquals(original.getSourceRbacVersion(), restored.getSourceRbacVersion());
        assertEquals(original.getSourceEngineVersion(), restored.getSourceEngineVersion());
        assertEquals(original.isApplyChannels(), restored.isApplyChannels());
        assertEquals(original.getPlanToken(), restored.getPlanToken());
        RoleImportRow back = restored.getRows().get(0);
        assertEquals(3, back.getIndex());
        assertEquals("Lab", back.getName());
        assertEquals(RoleImportRow.Action.OVERWRITE, back.getAction());
        assertEquals("note", back.getReason());
        assertEquals(row.getDroppedPermissions(), back.getDroppedPermissions());
        assertEquals(2, back.getMatchedChannelCount());
        assertEquals(RoleImportRow.Channels.KEPT, back.getChannels());
        assertEquals(true, back.isNoChannelFound());
        assertEquals(true, back.isExistsHere());
        assertEquals(true, back.isRestrictedNow());
        assertEquals(true, back.isRestrictedAfter());
        assertEquals("old", back.getDescriptionNow());
        assertEquals("new", back.getDescriptionAfter());
        assertEquals(row.getPermissionsNow(), back.getPermissionsNow());
        assertEquals(row.getPermissionsAfter(), back.getPermissionsAfter());
        RoleImportChannel nowBack = back.getChannelsNow().get(0);
        assertEquals("id-adt", nowBack.getId());
        assertEquals("ADT Out", nowBack.getName());
        assertNull(nowBack.getFileName());
        assertEquals(RoleImportChannel.Match.BY_ID, nowBack.getMatch());
        assertEquals(true, nowBack.isUsed());
        RoleImportChannel afterBack = back.getChannelsAfter().get(0);
        assertEquals("id-lab", afterBack.getId());
        assertEquals("Lab In", afterBack.getName());
        assertEquals("id-elsewhere", afterBack.getFileId());
        assertEquals("Lab Results In", afterBack.getFileName());
        assertNull(nowBack.getFileId());
        assertEquals(RoleImportChannel.Match.BY_NAME, afterBack.getMatch());
        assertEquals(false, afterBack.isUsed());
        ChannelNameMatch matchBack = restored.getChannelNameMatches().get(0);
        assertEquals("Lab In", matchBack.getName());
        assertEquals("id-elsewhere", matchBack.getFileChannelId());
        assertEquals("id-lab", matchBack.getChannelId());
        assertEquals(true, restored.isMatchChannelsByName());
    }
}
