// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Font;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.Supplier;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.ListSelectionModel;
import javax.swing.border.TitledBorder;
import javax.swing.table.DefaultTableModel;

import com.mirth.connect.client.core.ClientException;
import com.mirth.connect.client.ui.Frame;
import com.mirth.connect.model.User;

/**
 * The User-Role Assignments half of the RBAC settings tab: the users with each one's role, and
 * Assign Role and Remove Role, with a review of what a role grants before it is assigned.
 *
 * <p>Each user's role is looked up by the tab's refresh worker, off the event thread, with
 * {@link #lookUpRoleNames}; {@link #showUsers} then fills the table on the event thread. A lookup
 * that fails shows "(unknown)", not "(none)", which on this tab means no role.</p>
 */
class UserAssignmentsPanel extends JPanel {

    static final String NO_ROLE = "(none)";
    static final String UNKNOWN_ROLE = "(unknown)";
    private static final String[] USER_COLUMNS = {"User ID", "Username", "Assigned Role"};

    /** Looks up one user's role; null when the user has none. */
    @FunctionalInterface
    interface RoleLookup {
        Role roleOf(int userId) throws ClientException;
    }

    private final Frame parent;
    private final Supplier<List<Role>> roles;
    private final Supplier<Map<String, String>> channelMap;
    private final Consumer<RbacSettingsPanel.MutationCall> runMutation;
    // Package-private for the unit test.
    final JTable usersTable;

    /**
     * @param parent      the administrator's main frame
     * @param roles       the tab's roles, for the Assign Role list
     * @param channelMap  the tab's channel id to name map, for the review before an assignment
     * @param runMutation runs a change on the server, then refreshes the tab
     */
    UserAssignmentsPanel(Frame parent, Supplier<List<Role>> roles, Supplier<Map<String, String>> channelMap,
            Consumer<RbacSettingsPanel.MutationCall> runMutation) {
        super(new BorderLayout(5, 5));
        this.parent = parent;
        this.roles = roles;
        this.channelMap = channelMap;
        this.runMutation = runMutation;
        setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), "User-Role Assignments",
                TitledBorder.DEFAULT_JUSTIFICATION, TitledBorder.DEFAULT_POSITION));

        usersTable = new JTable(new DefaultTableModel(new Object[0][3], USER_COLUMNS) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        });
        usersTable.setDefaultRenderer(Object.class, new PlainCellRenderer(null));
        usersTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        usersTable.getColumnModel().getColumn(0).setMaxWidth(80);
        usersTable.getColumnModel().getColumn(0).setPreferredWidth(60);
        add(new JScrollPane(usersTable), BorderLayout.CENTER);

        JPanel userButtonPanel = new JPanel();
        userButtonPanel.setLayout(new BoxLayout(userButtonPanel, BoxLayout.Y_AXIS));
        JButton assignRoleButton = new JButton("Assign Role");
        assignRoleButton.setMaximumSize(new Dimension(Integer.MAX_VALUE, assignRoleButton.getPreferredSize().height));
        assignRoleButton.addActionListener(e -> assignRoleToUser());
        JButton removeRoleButton = new JButton("Remove Role");
        removeRoleButton.setMaximumSize(new Dimension(Integer.MAX_VALUE, removeRoleButton.getPreferredSize().height));
        removeRoleButton.addActionListener(e -> removeRoleFromUser());

        userButtonPanel.add(assignRoleButton);
        userButtonPanel.add(Box.createVerticalStrut(5));
        userButtonPanel.add(removeRoleButton);
        userButtonPanel.add(Box.createVerticalGlue());
        add(userButtonPanel, BorderLayout.EAST);
    }

    /**
     * Each user's role name by user id: the role's name, {@link #NO_ROLE} for a user with no role,
     * or {@link #UNKNOWN_ROLE} when the lookup failed. One call per user (the servlet has no bulk
     * read); runs on the refresh worker's thread.
     */
    static Map<Integer, String> lookUpRoleNames(List<User> users, RoleLookup lookup) {
        Map<Integer, String> names = new LinkedHashMap<>();
        for (User user : users != null ? users : new ArrayList<User>()) {
            String name;
            try {
                Role role = lookup.roleOf(user.getId());
                name = role != null ? role.getName() : NO_ROLE;
            } catch (Exception e) {
                name = UNKNOWN_ROLE;
            }
            names.put(user.getId(), name);
        }
        return names;
    }

    /** Fills the table, on the event thread, with the names from {@link #lookUpRoleNames}. */
    void showUsers(List<User> users, Map<Integer, String> roleNames) {
        DefaultTableModel model = (DefaultTableModel) usersTable.getModel();
        model.setRowCount(0);
        for (User user : users) {
            String roleName = roleNames == null ? null : roleNames.get(user.getId());
            model.addRow(new Object[]{user.getId(), user.getUsername(), roleName != null ? roleName : UNKNOWN_ROLE});
        }
    }

    private void assignRoleToUser() {
        int row = usersTable.getSelectedRow();
        if (row < 0) {
            parent.alertWarning(parent, "Please select a user to assign a role to.");
            return;
        }

        int userId = (int) usersTable.getValueAt(row, 0);

        List<Role> available = roles.get();
        if (available.isEmpty()) {
            parent.alertWarning(parent, "No roles available. Create a role first.");
            return;
        }

        // A combo box with a plain renderer, so a role name is never rendered as markup.
        JComboBox<Role> roleChoice = new JComboBox<>(available.toArray(new Role[0]));
        roleChoice.setRenderer(new PlainCellRenderer.ForList());
        JPanel choicePanel = new JPanel(new BorderLayout(0, 6));
        choicePanel.add(new JLabel("Select a role for user " + usersTable.getValueAt(row, 1) + ":"), BorderLayout.NORTH);
        choicePanel.add(roleChoice, BorderLayout.CENTER);
        int choice = JOptionPane.showConfirmDialog(parent, choicePanel, "Assign Role",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);

        Role selectedRole = choice == JOptionPane.OK_OPTION ? (Role) roleChoice.getSelectedItem() : null;
        if (selectedRole != null) {
            String username = (String) usersTable.getValueAt(row, 1);
            String currentRoleName = (String) usersTable.getValueAt(row, 2);
            if (!confirmAssignment(username, currentRoleName, selectedRole)) {
                return;
            }
            runMutation.accept(() -> parent.mirthClient.getServlet(RbacServletInterface.class)
                    .assignUserRole(userId, selectedRole.getId()));
        }
    }

    /**
     * Shows what a role grants: the user's current role, the new role, its channel scope, and
     * the full permission list, so the admin can review the impact before committing an
     * assignment. Role assignment is easy to get wrong, so this preview is the safeguard.
     *
     * @param username        the target user's display name
     * @param currentRoleName the user's current role name, "(none)" or "(unknown)"
     * @param role            the role about to be assigned, fully populated
     * @return {@code true} if the admin confirms the assignment
     */
    private boolean confirmAssignment(String username, String currentRoleName, Role role) {
        StringBuilder details = new StringBuilder();
        details.append("User:         ").append(username).append('\n');
        details.append("Current role: ").append(currentRoleName != null ? currentRoleName : NO_ROLE).append('\n');
        details.append("New role:     ").append(role.getName()).append("\n\n");

        Set<String> channelIds = role.getChannelIds();
        if (!role.isRestricted()) {
            details.append("Channel access: All channels\n\n");
        } else if (channelIds == null || channelIds.isEmpty()) {
            details.append("Channel access: No channels\n\n");
        } else {
            details.append("Channel access: restricted to ").append(channelIds.size()).append(" channel(s):\n");
            Map<String, String> names = channelMap.get();
            List<String> channelLabels = new ArrayList<>();
            for (String id : channelIds) {
                String name = names.get(id);
                channelLabels.add("  " + (name != null ? name : id));
            }
            channelLabels.sort(null);
            for (String label : channelLabels) {
                details.append(label).append('\n');
            }
            details.append('\n');
        }

        List<String> sortedPerms = new ArrayList<>();
        if (role.getPermissions() != null) {
            sortedPerms.addAll(role.getPermissions());
        }
        sortedPerms.sort(null);
        details.append("Permissions (").append(sortedPerms.size()).append("):\n");
        if (sortedPerms.isEmpty()) {
            // Same text as the web Administrator's (rbac-core.js, preview-golden.test.mjs).
            details.append("  (none \u2014 the user could log in but perform no actions)\n");
        } else {
            for (String perm : sortedPerms) {
                details.append("  ").append(perm).append('\n');
            }
        }

        JTextArea area = new JTextArea(details.toString());
        area.setEditable(false);
        area.setCaretPosition(0);
        JScrollPane scroll = new JScrollPane(area);
        scroll.setPreferredSize(new Dimension(420, 260));

        JPanel panel = new JPanel(new BorderLayout(0, 6));
        panel.add(new JLabel("Review the access this role grants before assigning:"), BorderLayout.NORTH);
        panel.add(scroll, BorderLayout.CENTER);
        JLabel immediateLabel = new JLabel("This assignment takes effect immediately.");
        immediateLabel.setFont(immediateLabel.getFont().deriveFont(Font.ITALIC));
        panel.add(immediateLabel, BorderLayout.SOUTH);

        int choice = JOptionPane.showConfirmDialog(parent, panel, "Confirm Role Assignment",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.QUESTION_MESSAGE);
        return choice == JOptionPane.OK_OPTION;
    }

    private void removeRoleFromUser() {
        int row = usersTable.getSelectedRow();
        if (row < 0) {
            parent.alertWarning(parent, "Please select a user to remove their role.");
            return;
        }

        int userId = (int) usersTable.getValueAt(row, 0);
        String username = (String) usersTable.getValueAt(row, 1);
        int confirm = JOptionPane.showConfirmDialog(parent,
                "Remove the role from user \"" + username + "\"?\nThey will lose all access.\n\nThis change takes effect immediately.",
                "Confirm Remove", JOptionPane.YES_NO_OPTION);

        // The admin floor (don't strip the last admin) is enforced server-side
        // by AdminRoleGuard, which returns a clear message surfaced below.
        if (confirm == JOptionPane.YES_OPTION) {
            runMutation.accept(() -> parent.mirthClient.getServlet(RbacServletInterface.class).removeUserRole(userId));
        }
    }
}
