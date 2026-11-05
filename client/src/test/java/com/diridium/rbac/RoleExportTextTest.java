// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

class RoleExportTextTest {

    @Test
    void counts_permissionsAndChannelsEveryNoneOrCount() {
        Role role = new Role();
        assertEquals("0", RoleExportText.permissionsCount(role));
        assertEquals("every", RoleExportText.channelsCount(role));
        role.setPermissions(new HashSet<>(Arrays.asList("a", "b")));
        role.setChannelIds(new HashSet<>(Arrays.asList("x", "y", "z")));
        assertEquals("2", RoleExportText.permissionsCount(role));
        assertEquals("every", RoleExportText.channelsCount(role), "the flag decides, not the list");
        role.setRestricted(true);
        assertEquals("3", RoleExportText.channelsCount(role));
        role.setChannelIds(new HashSet<String>());
        assertEquals("none", RoleExportText.channelsCount(role));
    }

    @Test
    void channelsLine_everyNoneOrNothing() {
        Role role = new Role();
        assertEquals("This role sees every channel.", RoleExportText.channelsLine(role));
        role.setRestricted(true);
        assertEquals("This role sees no channels.", RoleExportText.channelsLine(role));
        role.setChannelIds(new HashSet<>(Arrays.asList("x")));
        assertEquals("", RoleExportText.channelsLine(role));
    }

    @Test
    void permissionRows_sorted() {
        Role role = new Role();
        role.setPermissions(new HashSet<>(Arrays.asList("b", "a")));
        List<String[]> rows = RoleExportText.permissionRows(role);
        assertEquals(2, rows.size());
        assertEquals("a", rows.get(0)[0]);
        assertEquals("b", rows.get(1)[0]);
    }

    @Test
    void channelRows_nameOrder_unknownIdShowsAsId() {
        Role role = new Role();
        role.setChannelIds(new HashSet<>(Arrays.asList("c", "b", "a", "z")));
        Map<String, String> map = new HashMap<>();
        map.put("a", "Zulu");
        map.put("b", "Alpha");
        map.put("c", "Mike");
        List<String[]> rows = RoleExportText.channelRows(role, map);
        assertEquals(Arrays.asList("Alpha", "b"), Arrays.asList(rows.get(0)));
        assertEquals(Arrays.asList("Mike", "c"), Arrays.asList(rows.get(1)));
        assertEquals(Arrays.asList("z", "z"), Arrays.asList(rows.get(2)), "an id the map lacks shows as the id");
        assertEquals(Arrays.asList("Zulu", "a"), Arrays.asList(rows.get(3)));
        List<String[]> unloaded = RoleExportText.channelRows(role, null);
        assertEquals(4, unloaded.size());
        assertEquals(Arrays.asList("a", "a"), Arrays.asList(unloaded.get(0)));
        assertEquals(0, RoleExportText.channelRows(new Role(), map).size());
    }
}
