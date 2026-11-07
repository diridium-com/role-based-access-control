// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.mirth.connect.client.core.ClientException;
import com.mirth.connect.model.User;

/**
 * The user-assignments half of the RBAC tab: each user's role is looked up off the event thread,
 * a failed lookup shows "(unknown)" and a user with no role "(none)", and the table shows names
 * as plain text.
 */
class UserAssignmentsPanelTest {

    private static User user(int id, String name) {
        User u = new User();
        u.setId(id);
        u.setUsername(name);
        return u;
    }

    private static Role role(String name) {
        Role r = new Role();
        r.setName(name);
        return r;
    }

    private static final List<User> USERS = Arrays.asList(user(1, "admin"), user(2, "nobody"), user(3, "lost"),
            user(4, "broken"));

    @Test
    void lookUpRoleNames_roleNoneOrUnknown_oneCallPerUser() {
        List<Integer> asked = new ArrayList<>();
        Map<Integer, String> names = UserAssignmentsPanel.lookUpRoleNames(USERS, id -> {
            asked.add(id);
            switch (id) {
                case 1:
                    return role("Administrator");
                case 2:
                    return null;
                case 3:
                    throw new ClientException("Method failed: HTTP/1.1 500 Server Error");
                default:
                    throw new IllegalStateException("not a ClientException");
            }
        });
        assertEquals(Arrays.asList(1, 2, 3, 4), asked);
        Map<Integer, String> expected = new LinkedHashMap<>();
        expected.put(1, "Administrator");
        expected.put(2, "(none)");
        expected.put(3, "(unknown)");
        expected.put(4, "(unknown)");
        assertEquals(expected, names);
        assertTrue(UserAssignmentsPanel.lookUpRoleNames(null, id -> role("x")).isEmpty());
    }

    @Test
    void showUsers_fillsTheTable_plainText() {
        UserAssignmentsPanel panel = new UserAssignmentsPanel(null, Collections::emptyList, Collections::emptyMap,
                call -> { });
        Map<Integer, String> names = new LinkedHashMap<>();
        names.put(1, "<html><b>Admins</b></html>");
        names.put(2, "(none)");
        panel.showUsers(USERS, names);
        assertEquals(4, panel.usersTable.getRowCount());
        assertEquals(Arrays.asList(1, "admin", "<html><b>Admins</b></html>"), rowValues(panel, 0));
        assertEquals(Arrays.asList(2, "nobody", "(none)"), rowValues(panel, 1));
        assertEquals(Arrays.asList(3, "lost", "(unknown)"), rowValues(panel, 2), "no name looked up: unknown");
        assertTrue(panel.usersTable.getDefaultRenderer(Object.class) instanceof PlainCellRenderer);
        panel.showUsers(Collections.<User>emptyList(), null);
        assertEquals(0, panel.usersTable.getRowCount());
    }

    private static List<Object> rowValues(UserAssignmentsPanel panel, int row) {
        List<Object> values = new ArrayList<>();
        for (int c = 0; c < panel.usersTable.getColumnCount(); c++) {
            values.add(panel.usersTable.getValueAt(row, c));
        }
        return values;
    }
}
