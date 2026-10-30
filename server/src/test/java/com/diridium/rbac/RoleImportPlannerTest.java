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
        assertEquals("This is the name of this engine's admin role, which an import never changes.", row.getReason());
        assertTrue(plan.writes().isEmpty());
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
        assertTrue(refusal.getMessage().startsWith("The roles 'Café' and 'Cafe' in the file are the same role on"
                + " this engine"), refusal.getMessage());
    }

    // ========== Permissions ==========

    @Test
    void permissionsThisEngineDoesNotOffer_areLeftOutAndListed() throws Exception {
        Plan plan = plan(true, fileRole("Lab", List.of("viewChannels", "Run Lab Reports", "viewMessages"), false));
        assertEquals(List.of("Run Lab Reports"), plan.rows().get(0).getDroppedPermissions());
        assertEquals(Set.of("viewChannels", "viewMessages"), plan.writes().get(0).role().getPermissions());
    }

    // ========== Channels, applied ==========

    @Test
    void channels_matchById_thenByAUniqueName_andListTheRest() throws Exception {
        Plan plan = plan(true, fileRole("Lab", List.of(), true,
                new Channel("id-lab", "Renamed since"),
                new Channel("id-elsewhere", "ADT Out"),
                new Channel("id-gone", "Twin"),
                new Channel("id-gone2", "Nowhere"),
                new Channel("id-gone3", "")));
        RoleImportRow row = plan.rows().get(0);
        assertEquals(Set.of("id-lab", "id-adt"), plan.writes().get(0).role().getChannelIds());
        assertEquals(2, row.getMatchedChannelCount());
        assertEquals(List.of("Twin (id-gone)", "Nowhere (id-gone2)", "id-gone3"), row.getUnmatchedChannels(),
                "a name two channels share matches neither");
    }

    @Test
    void aRestrictedRoleWithNoChannelFound_isSkipped_notLetIntoEveryChannel() throws Exception {
        Plan plan = plan(true, fileRole("Lab", List.of("viewChannels"), true,
                new Channel("id-gone", "Gone"), new Channel("id-gone2", "Also gone")));
        RoleImportRow row = plan.rows().get(0);
        assertEquals(Action.SKIP, row.getAction());
        assertEquals("None of its 2 channels exist on this engine, and a role with no channels sees every channel.",
                row.getReason());
        assertEquals(List.of("Gone (id-gone)", "Also gone (id-gone2)"), row.getUnmatchedChannels());
        assertTrue(plan.writes().isEmpty());
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
        assertNull(row.getReason());
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
        assertEquals("Sees every channel here; where it was exported it was restricted to 1 channel(s)."
                + " Set its channels before assigning users.", row.getReason());
        assertEquals(Set.of(), plan.writes().get(0).role().getChannelIds());
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
                .plan(new ExportFile("1", "1.3.0", "4.7.0", List.of(fileRoles)), applyChannels);
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
