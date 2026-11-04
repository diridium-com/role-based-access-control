// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.diridium.rbac.RoleImportChannel.Match;
import com.diridium.rbac.RoleImportPlanner.Plan;
import com.diridium.rbac.RoleImportPlanner.PlannedRole;
import com.diridium.rbac.RoleImportRow.Action;
import com.diridium.rbac.RoleImportRow.Channels;
import com.diridium.rbac.RoleTransferFormat.Channel;
import com.diridium.rbac.RoleTransferFormat.ExportFile;
import com.diridium.rbac.RoleTransferFormat.ExportedRole;
import com.diridium.rbac.RoleTransferFormat.Refusal;

/**
 * Tests the import rules in {@link RoleImportPlanner} against an in-memory set of
 * roles and channels: what each role in a file becomes, and the plan token.
 */
class RoleImportPlannerTest {

    private static final int ADMIN_ID = 1;
    private static final Set<String> CATALOG = Set.of("viewChannels", "viewMessages", "View Roles");

    private Map<Integer, Role> roles;
    private Map<String, String> channels;
    private boolean caseAndAccentInsensitiveNames;

    @BeforeEach
    void setUp() {
        roles = new HashMap<>();
        roles.put(ADMIN_ID, role(ADMIN_ID, "Administrator", "admin", Set.of("viewChannels"), Set.of()));
        channels = new LinkedHashMap<>();
        channels.put("id-lab", "Lab In");
        channels.put("id-adt", "ADT Out");
        channels.put("id-dup1", "Twin");
        channels.put("id-dup2", "Twin");
        caseAndAccentInsensitiveNames = false;
    }

    // ========== Actions ==========

    @Test
    void aRoleNotHere_isCreated_withItsChannels() throws Exception {
        Plan plan = plan(true, fileRole("Lab", List.of("viewChannels"), true, new Channel("id-lab", "Lab In")));
        RoleImportRow row = plan.rows().get(0);
        assertEquals(Action.CREATE, row.getAction());
        assertEquals(Channels.FROM_FILE, row.getChannels());
        assertEquals(1, row.getMatchedChannelCount());
        PlannedRole write = plan.writes().get(0);
        assertNull(write.existingId());
        assertEquals("Lab", write.role().getName());
        assertEquals(Set.of("viewChannels"), write.role().getPermissions());
        assertEquals(Set.of("id-lab"), write.role().getChannelIds());
        assertTrue(write.writeChannels());
        assertFalse(row.isExistsHere(), "no role here: the now fields are empty");
        assertNull(row.getDescriptionNow());
        assertTrue(row.getPermissionsNow().isEmpty() && row.getChannelsNow().isEmpty());
        assertEquals("d", row.getDescriptionAfter());
        assertEquals(List.of("viewChannels"), row.getPermissionsAfter());
        assertEquals(1, row.getChannelsAfter().size());
        assertChannel(row.getChannelsAfter().get(0), "id-lab", "Lab In", "Lab In", Match.BY_ID, true);
    }

    @Test
    void aDifferentRoleHere_isOverwritten_keepingItsOwnName() throws Exception {
        caseAndAccentInsensitiveNames = true;
        roles.put(5, role(5, "LAB", "old", Set.of("viewMessages"), Set.of("id-adt")));
        Plan plan = plan(true, fileRole("Lab", List.of("viewChannels"), true, new Channel("id-lab", "Lab In")));
        assertEquals(Action.OVERWRITE, plan.rows().get(0).getAction());
        PlannedRole write = plan.writes().get(0);
        assertEquals(5, write.existingId());
        assertEquals("LAB", write.role().getName(), "the existing role keeps its name");
        assertEquals("d", write.role().getDescription());
        assertEquals(Set.of("id-lab"), write.role().getChannelIds());
    }

    @Test
    void anIdenticalRoleHere_isUnchanged_andNotWritable() throws Exception {
        roles.put(5, role(5, "Lab", "d", Set.of("viewChannels"), Set.of("id-lab")));
        Plan plan = plan(true, fileRole("Lab", List.of("viewChannels"), true, new Channel("id-lab", "Lab In")));
        assertEquals(Action.UNCHANGED, plan.rows().get(0).getAction());
        assertEquals("Identical to the role on this engine.", plan.rows().get(0).getReason());
        assertFalse(plan.writes().containsKey(0));
    }

    @Test
    void aNullDescriptionHere_equalsAnEmptyOneInTheFile() throws Exception {
        roles.put(5, role(5, "Lab", null, Set.of(), Set.of()));
        ExportedRole fileRole = new ExportedRole("Lab", "", List.of(), false, List.of());
        assertEquals(Action.UNCHANGED, plan(true, fileRole).rows().get(0).getAction());
    }

    @Test
    void theAdminRolesName_isSkipped() throws Exception {
        Plan plan = plan(true, fileRole("Administrator", List.of("viewChannels"), false));
        RoleImportRow row = plan.rows().get(0);
        assertEquals(Action.SKIP, row.getAction());
        assertEquals("The admin role on this engine has this name. An import never changes the admin role.", row.getReason());
        assertTrue(plan.writes().isEmpty());
        assertTrue(row.isExistsHere(), "the file's content and the admin role are still described");
        assertEquals(List.of("viewChannels"), row.getPermissionsNow());
        assertEquals(List.of("viewChannels"), row.getPermissionsAfter());
    }

    @Test
    void theAdminRolesName_isSkipped_whateverTheCaseOnACaseInsensitiveDatabase() throws Exception {
        caseAndAccentInsensitiveNames = true;
        assertEquals(Action.SKIP, plan(true, fileRole("ADMINISTRATOR", List.of(), false)).rows().get(0).getAction());
    }

    @Test
    void twoFileRolesThatAreOneRoleHere_refuseTheFile() {
        caseAndAccentInsensitiveNames = true;
        roles.put(5, role(5, "Cafe", "d", Set.of(), Set.of()));
        Refusal refusal = assertThrows(Refusal.class, () -> plan(true,
                fileRole("Café", List.of(), false), fileRole("Cafe", List.of(), false)));
        assertEquals("The roles 'Café' and 'Cafe' in the file are the same role on this engine, whose database holds"
                + " them as one name. Rename one of them in the file.", refusal.getMessage());
    }

    @Test
    void twoFileRolesThatDifferOnlyInCase_areTwoRoles_whereTheDatabaseHoldsTwo() throws Exception {
        roles.put(5, role(5, "Lab", "d", Set.of(), Set.of()));
        roles.put(6, role(6, "LAB", "d", Set.of(), Set.of()));
        Plan plan = plan(true, fileRole("Lab", List.of(), false), fileRole("LAB", List.of(), false));
        assertEquals(List.of(Action.UNCHANGED, Action.UNCHANGED),
                plan.rows().stream().map(RoleImportRow::getAction).toList());
    }

    // ========== The role now and after ==========

    @Test
    void anOverwrite_showsTheDescriptionAndPermissions_nowAndAfter() throws Exception {
        roles.put(5, role(5, "Lab", "old", Set.of("viewMessages", "View Roles"), Set.of()));
        RoleImportRow row = plan(true, fileRole("Lab", List.of("viewMessages", "viewChannels"), false)).rows().get(0);
        assertEquals(Action.OVERWRITE, row.getAction());
        assertTrue(row.isExistsHere());
        assertEquals("old", row.getDescriptionNow());
        assertEquals("d", row.getDescriptionAfter());
        assertEquals(List.of("View Roles", "viewMessages"), row.getPermissionsNow(), "sorted");
        assertEquals(List.of("viewChannels", "viewMessages"), row.getPermissionsAfter(), "sorted");
        assertTrue(row.getChannelsNow().isEmpty() && row.getChannelsAfter().isEmpty(), "every channel, both");
        assertNull(row.getReason(), "nothing to say: both see every channel, every permission exists");
    }

    @Test
    void anOverwrite_showsTheChannels_nowByNameWithDeletedOnesLast_andAfterInFileOrder() throws Exception {
        roles.put(5, role(5, "Lab", "d", Set.of(), Set.of("id-adt", "id-deleted-here", "id-lab")));
        RoleImportRow row = plan(true, fileRole("Lab", List.of(), true,
                new Channel("id-lab", "Lab In"), new Channel("id-adt", "ADT Out"))).rows().get(0);
        assertEquals(Action.OVERWRITE, row.getAction());
        assertEquals(3, row.getChannelsNow().size());
        assertChannel(row.getChannelsNow().get(0), "id-adt", "ADT Out", null, Match.BY_ID, true);
        assertChannel(row.getChannelsNow().get(1), "id-lab", "Lab In", null, Match.BY_ID, true);
        assertChannel(row.getChannelsNow().get(2), "id-deleted-here", null, null, Match.NOT_FOUND, true);
        assertEquals(2, row.getChannelsAfter().size());
        assertChannel(row.getChannelsAfter().get(0), "id-lab", "Lab In", "Lab In", Match.BY_ID, true);
        assertChannel(row.getChannelsAfter().get(1), "id-adt", "ADT Out", "ADT Out", Match.BY_ID, true);
    }

    @Test
    void aNullDescriptionHere_isShownEmpty() throws Exception {
        roles.put(5, role(5, "Lab", null, Set.of(), Set.of()));
        RoleImportRow row = plan(true, fileRole("Lab", List.of("viewChannels"), false)).rows().get(0);
        assertEquals("", row.getDescriptionNow());
    }

    @Test
    void anOverwriteThatLetsARestrictedRoleSeeEveryChannel_saysSo() throws Exception {
        roles.put(5, role(5, "Lab", "d", Set.of(), Set.of("id-lab", "id-adt")));
        RoleImportRow row = plan(true, fileRole("Lab", List.of(), false)).rows().get(0);
        assertEquals(Action.OVERWRITE, row.getAction());
        assertEquals("On this engine this role is restricted to 2 channels. The import removes the restriction, so after"
                + " the import this role will see every channel.", row.getReason());
        assertEquals(2, row.getChannelsNow().size());
        assertTrue(row.getChannelsAfter().isEmpty(), "every channel has no list");
    }

    @Test
    void anOverwriteThatRestrictsARoleSeeingEveryChannel_saysSo() throws Exception {
        roles.put(5, role(5, "Lab", "d", Set.of(), Set.of()));
        RoleImportRow row = plan(true, fileRole("Lab", List.of(), true, new Channel("id-lab", "Lab In"))).rows().get(0);
        assertEquals(Action.OVERWRITE, row.getAction());
        assertEquals("On this engine this role sees every channel. The import restricts this role to 1 channel.",
                row.getReason());
        assertTrue(row.getChannelsNow().isEmpty(), "every channel has no list");
        assertEquals(1, row.getChannelsAfter().size());
    }

    // ========== Permissions ==========

    @Test
    void permissionsThisEngineDoesNotOffer_areLeftOutAndListed() throws Exception {
        Plan plan = plan(true, fileRole("Lab", List.of("viewChannels", "Run Lab Reports", "viewMessages"), false));
        assertEquals(List.of("Run Lab Reports"), plan.rows().get(0).getDroppedPermissions());
        assertEquals(List.of("viewChannels", "viewMessages"), plan.rows().get(0).getPermissionsAfter());
        assertEquals(Set.of("viewChannels", "viewMessages"), plan.writes().get(0).role().getPermissions());
    }

    // ========== Channels, applied ==========

    @Test
    void channels_matchById_andListMatchesByName_usedOnlyWhenMatchingByName() throws Exception {
        ExportedRole lab = fileRole("Lab", List.of(), true,
                new Channel("id-lab", "Renamed since"),
                new Channel("id-elsewhere", "ADT Out"),
                new Channel("id-gone", "Twin"),
                new Channel("id-gone2", "Nowhere"),
                new Channel("id-gone3", ""));
        Plan plan = plan(true, lab);
        RoleImportRow row = plan.rows().get(0);
        assertEquals(Set.of("id-lab"), plan.writes().get(0).role().getChannelIds(), "by id, whatever its name now");
        assertEquals(1, row.getMatchedChannelCount());
        List<RoleImportChannel> after = row.getChannelsAfter();
        assertEquals(5, after.size(), "every file channel, in file order");
        assertChannel(after.get(0), "id-lab", "Lab In", "Renamed since", Match.BY_ID, true);
        assertChannel(after.get(1), "id-adt", "ADT Out", "ADT Out", Match.BY_NAME, false);
        assertEquals("id-elsewhere", after.get(1).getFileId());
        assertChannel(after.get(2), "id-gone", "Twin", "Twin", Match.NOT_FOUND, false);
        assertChannel(after.get(3), "id-gone2", "Nowhere", "Nowhere", Match.NOT_FOUND, false);
        assertChannel(after.get(4), "id-gone3", null, "", Match.NOT_FOUND, false);
        assertEquals(1, plan.channelNameMatches().size());
        ChannelNameMatch match = plan.channelNameMatches().get(0);
        assertEquals("ADT Out", match.getName());
        assertEquals("id-elsewhere", match.getFileChannelId());
        assertEquals("id-adt", match.getChannelId());

        Plan byName = planMatchingByName(lab);
        assertEquals(Set.of("id-lab", "id-adt"), byName.writes().get(0).role().getChannelIds());
        assertEquals(2, byName.rows().get(0).getMatchedChannelCount());
        assertChannel(byName.rows().get(0).getChannelsAfter().get(1), "id-adt", "ADT Out", "ADT Out", Match.BY_NAME, true);
        assertEquals(1, byName.channelNameMatches().size(), "listed whether or not it is used");
    }

    @Test
    void aMatchByName_isListedOnce_andUsedForEveryRoleThatNamesIt() throws Exception {
        Plan plan = planMatchingByName(
                fileRole("Lab", List.of(), true, new Channel("id-elsewhere", "ADT Out")),
                fileRole("ADT", List.of(), true,
                        new Channel("id-elsewhere", "ADT Out"), new Channel("id-lab", "Lab In")));
        assertEquals(1, plan.channelNameMatches().size(), "listed once");
        assertEquals(Set.of("id-adt"), plan.writes().get(0).role().getChannelIds());
        assertEquals(Set.of("id-adt", "id-lab"), plan.writes().get(1).role().getChannelIds());
    }

    @Test
    void aRestrictedRoleWhoseChannelsMatchOnlyByName_isOfferedWithNoChannelFound_andSaysHowManyCould()
            throws Exception {
        ExportedRole lab = fileRole("Lab", List.of(), true,
                new Channel("id-elsewhere", "Lab In"), new Channel("id-gone", "Gone"));
        RoleImportRow row = plan(true, lab).rows().get(0);
        assertEquals(Action.CREATE, row.getAction());
        assertTrue(row.isNoChannelFound());
        assertEquals("The import restricts this role to 2 channels. None of those channels exist on this engine. If"
                + " imported, this role will see every channel until an administrator sets channels for this role."
                + " 1 of those channels matches a channel on this engine by name.", row.getReason());

        Plan byName = planMatchingByName(lab);
        assertEquals(Action.CREATE, byName.rows().get(0).getAction());
        assertFalse(byName.rows().get(0).isNoChannelFound());
        assertEquals("Of the 2 channels in the import, 1 is not on this engine.", byName.rows().get(0).getReason());
        assertEquals(Set.of("id-lab"), byName.writes().get(0).role().getChannelIds());
    }

    @Test
    void aRestrictedRoleWithNoChannelFound_isOffered_seeingEveryChannel() throws Exception {
        Plan plan = plan(true, fileRole("Lab", List.of("viewChannels"), true,
                new Channel("id-gone", "Gone"), new Channel("id-gone2", "Also gone")));
        RoleImportRow row = plan.rows().get(0);
        assertEquals(Action.CREATE, row.getAction());
        assertTrue(row.isNoChannelFound());
        assertEquals("The import restricts this role to 2 channels. None of those channels exist on this engine. If"
                + " imported, this role will see every channel until an administrator sets channels for this role.",
                row.getReason());
        assertChannel(row.getChannelsAfter().get(0), "id-gone", "Gone", "Gone", Match.NOT_FOUND, false);
        assertChannel(row.getChannelsAfter().get(1), "id-gone2", "Also gone", "Also gone", Match.NOT_FOUND, false);
        assertEquals(List.of("viewChannels"), row.getPermissionsAfter());
        assertEquals(Set.of(), plan.writes().get(0).role().getChannelIds(), "written as every channel if picked");
    }

    @Test
    void anOverwriteWithNoChannelFound_saysWhatTheRoleLoses() throws Exception {
        roles.put(5, role(5, "Lab", "d", Set.of(), Set.of("id-lab", "id-adt")));
        RoleImportRow row = plan(true, fileRole("Lab", List.of(), true, new Channel("id-gone", "Gone"))).rows().get(0);
        assertEquals(Action.OVERWRITE, row.getAction());
        assertTrue(row.isNoChannelFound());
        assertEquals("The import restricts this role to 1 channel. None of those channels exist on this engine. If"
                + " imported, this role will see every channel instead of the 2 channels currently set on this engine,"
                + " until an administrator sets channels for this role.", row.getReason());
    }

    @Test
    void permissionsLeftOut_areCounted_inTheNotes() throws Exception {
        RoleImportRow one = plan(true, fileRole("Lab", List.of("viewChannels", "Run Lab Reports"), false)).rows().get(0);
        assertEquals("1 permission in the import is not offered by this engine and is left out.", one.getReason());
        RoleImportRow two = plan(true, fileRole("Lab", List.of("Run Lab Reports", "Sign Lab Reports"), false)).rows().get(0);
        assertEquals("2 permissions in the import are not offered by this engine and are left out.", two.getReason());
        assertNull(plan(true, fileRole("Lab", List.of("viewChannels"), false)).rows().get(0).getReason(),
                "nothing to say about a new role whose channels and permissions all exist");
    }

    @Test
    void anUnrestrictedRole_seesEveryChannel() throws Exception {
        roles.put(5, role(5, "Lab", "d", Set.of(), Set.of("id-lab")));
        Plan plan = plan(true, fileRole("Lab", List.of(), false));
        assertEquals(Action.OVERWRITE, plan.rows().get(0).getAction());
        assertEquals(Set.of(), plan.writes().get(0).role().getChannelIds());
        assertTrue(plan.writes().get(0).writeChannels());
    }

    // ========== Channels, not applied ==========

    @Test
    void channelsNotApplied_anExistingRoleKeepsItsOwn() throws Exception {
        roles.put(5, role(5, "Lab", "old", Set.of(), Set.of("id-adt")));
        Plan plan = plan(false, fileRole("Lab", List.of("viewChannels"), true, new Channel("id-lab", "Lab In")));
        RoleImportRow row = plan.rows().get(0);
        assertEquals(Action.OVERWRITE, row.getAction());
        assertEquals(Channels.KEPT, row.getChannels());
        assertEquals("This role keeps the channels currently set on this engine.", row.getReason());
        assertEquals(1, row.getChannelsNow().size());
        assertChannel(row.getChannelsNow().get(0), "id-adt", "ADT Out", null, Match.BY_ID, true);
        assertEquals(1, row.getChannelsAfter().size(), "its channels don't change");
        assertChannel(row.getChannelsAfter().get(0), "id-adt", "ADT Out", null, Match.BY_ID, true);
        assertTrue(row.getPermissionsNow().isEmpty());
        assertEquals(List.of("viewChannels"), row.getPermissionsAfter());
        PlannedRole write = plan.writes().get(0);
        assertFalse(write.writeChannels());
        assertEquals(Set.of("id-adt"), write.role().getChannelIds());
    }

    @Test
    void channelsNotApplied_aNewRestrictedRoleSeesEveryChannel_andSaysSo() throws Exception {
        Plan plan = plan(false, fileRole("Lab", List.of(), true, new Channel("id-gone", "Gone")));
        RoleImportRow row = plan.rows().get(0);
        assertEquals(Action.CREATE, row.getAction(), "not skipped: the user chose not to apply channels");
        assertEquals(Channels.EVERY_CHANNEL, row.getChannels());
        assertEquals("The import restricts this role to 1 channel. Restrictions are not applied, so this role will"
                + " see every channel on this engine until an administrator sets channels for this role.",
                row.getReason());
        assertEquals(Set.of(), plan.writes().get(0).role().getChannelIds());
        assertTrue(row.getChannelsAfter().isEmpty(), "every channel: the file's channels aren't looked up");
    }

    @Test
    void channelsNotApplied_listNoMatchesByName() throws Exception {
        Plan plan = plan(false, fileRole("Lab", List.of(), true, new Channel("id-elsewhere", "ADT Out")));
        assertTrue(plan.channelNameMatches().isEmpty());
    }

    @Test
    void channelsNotApplied_aNewUnrestrictedRoleNeedsNoNote() throws Exception {
        RoleImportRow row = plan(false, fileRole("Lab", List.of(), false)).rows().get(0);
        assertEquals(Channels.EVERY_CHANNEL, row.getChannels());
        assertNull(row.getReason());
    }

    // ========== Plan token ==========

    @Test
    void theToken_isStable_forTheSameFileAndState() throws Exception {
        roles.put(5, role(5, "Lab", "old", Set.of(), Set.of("id-adt")));
        ExportedRole lab = fileRole("Lab", List.of("viewChannels"), true, new Channel("id-lab", "Lab In"));
        assertEquals(plan(true, lab).token(), plan(true, lab).token());
    }

    @Test
    void theToken_changes_whenARoleTheFileNamesChanges() throws Exception {
        roles.put(5, role(5, "Lab", "old", Set.of(), Set.of("id-adt")));
        ExportedRole lab = fileRole("Lab", List.of("viewChannels"), true, new Channel("id-lab", "Lab In"));
        String before = plan(true, lab).token();
        roles.put(5, role(5, "Lab", "old", Set.of("viewMessages"), Set.of("id-adt")));
        assertNotEquals(before, plan(true, lab).token());
    }

    @Test
    void theToken_changes_whenARoleTheFileNamesIsCreatedHere() throws Exception {
        ExportedRole lab = fileRole("Lab", List.of("viewChannels"), false);
        String before = plan(true, lab).token();
        roles.put(5, role(5, "Lab", "d", Set.of("viewChannels"), Set.of()));
        assertNotEquals(before, plan(true, lab).token());
    }

    @Test
    void theToken_changes_withTheChannelChoice() throws Exception {
        ExportedRole lab = fileRole("Lab", List.of(), true, new Channel("id-lab", "Lab In"));
        assertNotEquals(plan(true, lab).token(), plan(false, lab).token());
    }

    @Test
    void theToken_changes_withMatchingByName() throws Exception {
        ExportedRole lab = fileRole("Lab", List.of(), true, new Channel("id-elsewhere", "ADT Out"),
                new Channel("id-lab", "Lab In"));
        assertNotEquals(plan(true, lab).token(), planMatchingByName(lab).token());
    }

    @Test
    void theToken_changes_whenAChannelIsDeletedHere() throws Exception {
        ExportedRole lab = fileRole("Lab", List.of(), true, new Channel("id-lab", "Lab In"),
                new Channel("id-adt", "ADT Out"));
        String before = plan(true, lab).token();
        channels.remove("id-adt");
        assertNotEquals(before, plan(true, lab).token());
    }

    // ========== Helpers ==========

    private Plan plan(boolean applyChannels, ExportedRole... fileRoles) throws Refusal {
        return new RoleImportPlanner(this::findRoleIdByName, roles::get, ADMIN_ID, CATALOG, channels)
                .plan(new ExportFile("1", "1.3.0", "4.7.0", List.of(fileRoles)), applyChannels, false);
    }

    private Plan planMatchingByName(ExportedRole... fileRoles) throws Refusal {
        return new RoleImportPlanner(this::findRoleIdByName, roles::get, ADMIN_ID, CATALOG, channels)
                .plan(new ExportFile("1", "1.3.0", "4.7.0", List.of(fileRoles)), true, true);
    }

    /** Matches like Postgres (exact), or like MySQL's default collation (no case, no accents). */
    private Integer findRoleIdByName(String name) {
        for (Role role : roles.values()) {
            if (caseAndAccentInsensitiveNames ? fold(role.getName()).equals(fold(name)) : role.getName().equals(name)) {
                return role.getId();
            }
        }
        return null;
    }

    private static String fold(String name) {
        return java.text.Normalizer.normalize(name, java.text.Normalizer.Form.NFD)
                .replaceAll("\\p{M}", "").toLowerCase(Locale.ROOT);
    }

    private static ExportedRole fileRole(String name, List<String> permissions, boolean restricted,
            Channel... channels) {
        return new ExportedRole(name, "d", permissions, restricted, List.of(channels));
    }

    private static void assertChannel(RoleImportChannel channel, String id, String name, String fileName, Match match,
            boolean used) {
        assertEquals(id, channel.getId());
        assertEquals(name, channel.getName());
        assertEquals(fileName, channel.getFileName());
        if (fileName == null) {
            assertNull(channel.getFileId(), "a now list has no file id");
        } else if (match == Match.BY_NAME) {
            assertNotEquals(id, channel.getFileId(), "a match by name has another id in the file");
        } else {
            assertEquals(id, channel.getFileId(), "found by id, or not found: the id is the file's");
        }
        assertEquals(match, channel.getMatch());
        assertEquals(used, channel.isUsed());
    }

    private static Role role(int id, String name, String description, Set<String> permissions, Set<String> channelIds) {
        Role role = new Role();
        role.setId(id);
        role.setName(name);
        role.setDescription(description);
        role.setPermissions(new java.util.HashSet<>(permissions));
        role.setChannelIds(new java.util.HashSet<>(channelIds));
        role.setAdmin(id == ADMIN_ID);
        return role;
    }
}
