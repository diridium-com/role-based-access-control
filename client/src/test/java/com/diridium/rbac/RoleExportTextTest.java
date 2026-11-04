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
    void counts_permissionsAndChannelsOrEvery() {
        Role role = new Role();
        assertEquals("0", RoleExportText.permissionsCount(role));
        assertEquals("every", RoleExportText.channelsCount(role));
        role.setPermissions(new HashSet<>(Arrays.asList("a", "b")));
        role.setChannelIds(new HashSet<>(Arrays.asList("x", "y", "z")));
        assertEquals("2", RoleExportText.permissionsCount(role));
        assertEquals("3", RoleExportText.channelsCount(role));
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
    void channelRows_nameOrder_deletedAndNotLoaded() {
        Role role = new Role();
        role.setChannelIds(new HashSet<>(Arrays.asList("c", "b", "a", "z")));
        Map<String, String> map = new HashMap<>();
        map.put("a", "Zulu");
        map.put("b", "Alpha");
        map.put("c", "Mike");
        List<String[]> rows = RoleExportText.channelRows(role, map);
        assertEquals(Arrays.asList("(no longer exists)", "z"), Arrays.asList(rows.get(0)));
        assertEquals(Arrays.asList("Alpha", "b"), Arrays.asList(rows.get(1)));
        assertEquals(Arrays.asList("Mike", "c"), Arrays.asList(rows.get(2)));
        assertEquals(Arrays.asList("Zulu", "a"), Arrays.asList(rows.get(3)));
        List<String[]> unloaded = RoleExportText.channelRows(role, null);
        assertEquals(4, unloaded.size());
        assertEquals(Arrays.asList("(channel list not loaded)", "a"), Arrays.asList(unloaded.get(0)));
        assertEquals(0, RoleExportText.channelRows(new Role(), map).size());
    }
}
