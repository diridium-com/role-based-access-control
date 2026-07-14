// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.ListSelectionModel;
import javax.swing.SwingWorker;
import javax.swing.border.TitledBorder;
import javax.swing.table.DefaultTableModel;

import com.mirth.connect.client.core.ClientException;
import com.mirth.connect.client.core.api.servlets.ChannelServletInterface;
import com.mirth.connect.client.core.api.servlets.UserServletInterface;
import com.mirth.connect.client.ui.AbstractSettingsPanel;
import com.mirth.connect.client.ui.Frame;
import com.mirth.connect.client.ui.PlatformUI;
import com.mirth.connect.model.User;

/**
 * Settings tab that lists roles and user-role assignments, with buttons to
 * add/edit/delete roles and assign/remove role assignments.
 *
 * <p>Lives under the administrator client's Settings view (one tab per
 * registered {@code SettingsPanelPlugin}). All mutating operations are
 * performed via the {@link RbacServletInterface} REST endpoint; the server
 * side does the actual permission and admin-floor checks.</p>
 *
 * <p>Refresh state is guarded by an {@link AtomicBoolean} so rapid clicks
 * on the panel don't queue overlapping background loads.</p>
 */
public class RbacSettingsPanel extends AbstractSettingsPanel {

    private static final String[] ROLE_COLUMNS = {"ID", "Name", "Description"};
    private static final String[] USER_COLUMNS = {"User ID", "Username", "Assigned Role"};

    private final Frame parent;
    private final AtomicBoolean refreshing = new AtomicBoolean(false);
    // Set when a refresh is requested while one is already in flight, so the
    // in-flight worker re-runs one refresh on completion instead of dropping it
    // (which could leave the table showing pre-mutation state).
    private final AtomicBoolean refreshPending = new AtomicBoolean(false);

    private JTable rolesTable;
    private JTable usersTable;

    private List<Role> cachedRoles = new ArrayList<>();
    private List<User> cachedUsers = new ArrayList<>();
    private Set<String> cachedPermissions;
    private Map<String, String> cachedExtensionGroups = new LinkedHashMap<>();
    private Map<String, String> cachedChannelMap = new LinkedHashMap<>();

    /**
     * @param tabName the label displayed for this tab in the Settings view
     */
    public RbacSettingsPanel(String tabName) {
        super(tabName);
        this.parent = PlatformUI.MIRTH_FRAME;
        initComponents();
    }

    private void initComponents() {
        setLayout(new BorderLayout());

        // Unlike the other settings tabs, this tab does not stage edits behind
        // the Save task — every confirmed action is committed via REST on the
        // spot. Say so up front, before the first click.
        JLabel immediateNotice = new JLabel("Changes on this tab are applied to the server immediately"
                + " when you confirm each action. The Save button does not stage changes here.");
        immediateNotice.setFont(immediateNotice.getFont().deriveFont(Font.ITALIC));
        immediateNotice.setForeground(Color.GRAY);
        immediateNotice.setBorder(BorderFactory.createEmptyBorder(2, 5, 4, 5));
        add(immediateNotice, BorderLayout.NORTH);

        // ========== Roles Panel (Top) ==========
        JPanel rolesPanel = new JPanel(new BorderLayout(5, 5));
        rolesPanel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), "Roles",
                TitledBorder.DEFAULT_JUSTIFICATION, TitledBorder.DEFAULT_POSITION));

        rolesTable = new JTable(new DefaultTableModel(new Object[0][3], ROLE_COLUMNS) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        });
        rolesTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        rolesTable.getColumnModel().getColumn(0).setMaxWidth(60);
        rolesTable.getColumnModel().getColumn(0).setPreferredWidth(50);
        rolesTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2 && rolesTable.getSelectedRow() >= 0) {
                    editSelectedRole();
                }
            }
        });

        JScrollPane rolesScroll = new JScrollPane(rolesTable);
        rolesPanel.add(rolesScroll, BorderLayout.CENTER);

        JPanel roleButtonPanel = new JPanel();
        roleButtonPanel.setLayout(new BoxLayout(roleButtonPanel, BoxLayout.Y_AXIS));
        JButton addRoleButton = new JButton("Add");
        addRoleButton.setMaximumSize(new Dimension(Integer.MAX_VALUE, addRoleButton.getPreferredSize().height));
        addRoleButton.addActionListener(e -> addRole());
        JButton editRoleButton = new JButton("Edit");
        editRoleButton.setMaximumSize(new Dimension(Integer.MAX_VALUE, editRoleButton.getPreferredSize().height));
        editRoleButton.addActionListener(e -> editSelectedRole());
        JButton deleteRoleButton = new JButton("Delete");
        deleteRoleButton.setMaximumSize(new Dimension(Integer.MAX_VALUE, deleteRoleButton.getPreferredSize().height));
        deleteRoleButton.addActionListener(e -> deleteSelectedRole());

        roleButtonPanel.add(addRoleButton);
        roleButtonPanel.add(Box.createVerticalStrut(5));
        roleButtonPanel.add(editRoleButton);
        roleButtonPanel.add(Box.createVerticalStrut(5));
        roleButtonPanel.add(deleteRoleButton);
        roleButtonPanel.add(Box.createVerticalGlue());
        rolesPanel.add(roleButtonPanel, BorderLayout.EAST);

        // ========== Users Panel (Bottom) ==========
        JPanel usersPanel = new JPanel(new BorderLayout(5, 5));
        usersPanel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), "User-Role Assignments",
                TitledBorder.DEFAULT_JUSTIFICATION, TitledBorder.DEFAULT_POSITION));

        usersTable = new JTable(new DefaultTableModel(new Object[0][3], USER_COLUMNS) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        });
        usersTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        usersTable.getColumnModel().getColumn(0).setMaxWidth(80);
        usersTable.getColumnModel().getColumn(0).setPreferredWidth(60);

        JScrollPane usersScroll = new JScrollPane(usersTable);
        usersPanel.add(usersScroll, BorderLayout.CENTER);

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
        usersPanel.add(userButtonPanel, BorderLayout.EAST);

        // ========== Split Pane ==========
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, rolesPanel, usersPanel);
        splitPane.setDividerLocation(250);
        splitPane.setResizeWeight(0.5);
        add(splitPane, BorderLayout.CENTER);
    }

    /**
     * {@inheritDoc}
     * <p>Loads roles, users, permission catalog, and channel id-to-name
     * map from the server on a {@link SwingWorker} background thread; the
     * EDT-bound {@code done} hook then repopulates both tables and surfaces
     * any error. Concurrent refresh calls are dropped via the
     * {@code refreshing} guard.</p>
     */
    @Override
    public void doRefresh() {
        if (refreshing.compareAndSet(false, true)) {
            new SwingWorker<Void, Void>() {
                private List<Role> roles;
                private List<User> users;
                private Set<String> permissions;
                private Map<String, String> channelMap;
                private Map<String, String> extensionGroups;
                private ClientException error;

                @Override
                protected Void doInBackground() {
                    try {
                        roles = parent.mirthClient.getServlet(RbacServletInterface.class).getRoles();
                        users = parent.mirthClient.getServlet(UserServletInterface.class).getAllUsers();
                        permissions = parent.mirthClient.getServlet(RbacServletInterface.class).getAvailablePermissions();
                        channelMap = parent.mirthClient.getServlet(ChannelServletInterface.class).getChannelIdsAndNames();
                        try {
                            // Grouping is cosmetic — a pre-1.1.2 server (404) just
                            // leaves plugin permissions under "Other".
                            extensionGroups = parent.mirthClient.getServlet(RbacServletInterface.class).getExtensionPermissionGroups();
                        } catch (ClientException ignore) {
                            extensionGroups = new LinkedHashMap<>();
                        }
                    } catch (ClientException e) {
                        error = e;
                    }
                    return null;
                }

                @Override
                protected void done() {
                    try {
                        if (error != null) {
                            parent.alertThrowable(parent, error);
                        }
                        if (roles != null) {
                            cachedRoles = roles;
                            refreshRolesTable();
                        }
                        if (users != null) {
                            cachedUsers = users;
                            refreshUsersTable();
                        }
                        if (permissions != null) {
                            cachedPermissions = permissions;
                        }
                        if (extensionGroups != null) {
                            cachedExtensionGroups = extensionGroups;
                        }
                        if (channelMap != null) {
                            cachedChannelMap = channelMap;
                        }
                    } finally {
                        // Always release the guard, even if a repaint above threw, so the
                        // panel can never wedge permanently. Then honor a refresh that was
                        // requested while this one was in flight.
                        refreshing.set(false);
                        if (refreshPending.compareAndSet(true, false)) {
                            doRefresh();
                        }
                    }
                }
            }.execute();
        } else {
            // A refresh is already running; remember to run one more afterward so a
            // post-mutation refresh is not silently lost.
            refreshPending.set(true);
        }
    }

    /**
     * {@inheritDoc}
     * <p>No-op: every role/assignment change is committed via REST in its
     * own dialog confirm. The Save button on the settings tab is a no-op
     * (returning {@code true} so the engine treats the panel as clean).</p>
     *
     * @return always {@code true}
     */
    @Override
    public boolean doSave() {
        // Nothing to save - all changes are immediate via REST
        return true;
    }

    private void refreshRolesTable() {
        DefaultTableModel model = (DefaultTableModel) rolesTable.getModel();
        model.setRowCount(0);
        for (Role role : cachedRoles) {
            model.addRow(new Object[]{role.getId(), role.getName(), role.getDescription()});
        }
    }

    private void refreshUsersTable() {
        DefaultTableModel model = (DefaultTableModel) usersTable.getModel();
        model.setRowCount(0);
        for (User user : cachedUsers) {
            String roleName = getRoleNameForUser(user.getId());
            model.addRow(new Object[]{user.getId(), user.getUsername(), roleName != null ? roleName : "(none)"});
        }
    }

    private String getRoleNameForUser(int userId) {
        try {
            Role role = parent.mirthClient.getServlet(RbacServletInterface.class).getUserRole(userId);
            if (role != null) {
                return role.getName();
            }
        } catch (ClientException e) {
            // Ignore - just show (none)
        }
        return null;
    }

    /**
     * @param roleId the database id to look up among the roles currently loaded
     * @return the cached {@link Role} with that id, or {@code null} if none match
     */
    private Role findCachedRole(int roleId) {
        for (Role r : cachedRoles) {
            if (r.getId() != null && r.getId() == roleId) {
                return r;
            }
        }
        return null;
    }

    /**
     * Guards the role editor against opening without a permission catalog. If a
     * partial refresh failure left {@code cachedPermissions} null/empty, opening
     * the editor would render zero checkboxes and Apply would then persist an
     * empty permission set — silently wiping the role. Core permissions are
     * always non-empty when the server is reachable, so null/empty reliably means
     * "not loaded yet".
     *
     * @return {@code true} (after warning the user) if the catalog is not loaded
     */
    private boolean permissionCatalogNotLoaded() {
        if (cachedPermissions == null || cachedPermissions.isEmpty()) {
            parent.alertWarning(parent, "The permission list has not finished loading. Click Refresh and try again.");
            return true;
        }
        return false;
    }

    private void addRole() {
        if (permissionCatalogNotLoaded()) {
            return;
        }
        RoleEditorDialog dialog = new RoleEditorDialog(parent, null, cachedPermissions, cachedExtensionGroups, cachedChannelMap);
        dialog.setVisible(true);

        Role result = dialog.getResult();
        if (result != null) {
            runMutation(() -> parent.mirthClient.getServlet(RbacServletInterface.class).createRole(result));
        }
    }

    private void editSelectedRole() {
        int row = rolesTable.getSelectedRow();
        if (row < 0) {
            parent.alertWarning(parent, "Please select a role to edit.");
            return;
        }

        if (permissionCatalogNotLoaded()) {
            return;
        }

        int roleId = (int) rolesTable.getValueAt(row, 0);
        Role existingRole = findCachedRole(roleId);
        if (existingRole == null) {
            return;
        }

        RoleEditorDialog dialog = new RoleEditorDialog(parent, existingRole, cachedPermissions, cachedExtensionGroups, cachedChannelMap);
        dialog.setVisible(true);

        Role result = dialog.getResult();
        if (result != null) {
            runMutation(() -> parent.mirthClient.getServlet(RbacServletInterface.class).updateRole(roleId, result));
        }
    }

    private void deleteSelectedRole() {
        int row = rolesTable.getSelectedRow();
        if (row < 0) {
            parent.alertWarning(parent, "Please select a role to delete.");
            return;
        }

        int roleId = (int) rolesTable.getValueAt(row, 0);
        // Identify the admin role by its flag, not its name — the admin role
        // can be renamed, so a name match would be unreliable. The server's
        // AdminRoleGuard enforces this too; this is the friendly client guard.
        Role selectedRole = findCachedRole(roleId);
        if (selectedRole != null && selectedRole.isAdmin()) {
            parent.alertWarning(parent, "The admin role cannot be deleted.");
            return;
        }

        String roleName = (String) rolesTable.getValueAt(row, 1);
        int confirm = JOptionPane.showConfirmDialog(parent,
                "Are you sure you want to delete role \"" + roleName + "\"?\nUsers with this role will lose all access.\n\nThis change takes effect immediately.",
                "Confirm Delete", JOptionPane.YES_NO_OPTION);

        if (confirm == JOptionPane.YES_OPTION) {
            runMutation(() -> parent.mirthClient.getServlet(RbacServletInterface.class).deleteRole(roleId));
        }
    }

    private void assignRoleToUser() {
        int row = usersTable.getSelectedRow();
        if (row < 0) {
            parent.alertWarning(parent, "Please select a user to assign a role to.");
            return;
        }

        int userId = (int) usersTable.getValueAt(row, 0);

        if (cachedRoles.isEmpty()) {
            parent.alertWarning(parent, "No roles available. Create a role first.");
            return;
        }

        String[] roleNames = cachedRoles.stream().map(Role::getName).toArray(String[]::new);
        String selected = (String) JOptionPane.showInputDialog(parent,
                "Select a role for user " + usersTable.getValueAt(row, 1) + ":",
                "Assign Role", JOptionPane.PLAIN_MESSAGE, null, roleNames, roleNames[0]);

        if (selected != null) {
            Role selectedRole = cachedRoles.stream()
                    .filter(r -> r.getName().equals(selected))
                    .findFirst().orElse(null);
            if (selectedRole != null) {
                String username = (String) usersTable.getValueAt(row, 1);
                String currentRoleName = (String) usersTable.getValueAt(row, 2);
                if (!confirmAssignment(username, currentRoleName, selectedRole)) {
                    return;
                }
                runMutation(() -> parent.mirthClient.getServlet(RbacServletInterface.class)
                        .assignUserRole(userId, selectedRole.getId()));
            }
        }
    }

    /**
     * Shows what a role grants — the user's current role, the new role, its
     * channel scope, and the full permission list — so the admin can review
     * the impact before committing an assignment. Role assignment is easy to
     * get wrong, so this preview is the safeguard.
     *
     * @param username        the target user's display name
     * @param currentRoleName the user's current role name (or "(none)")
     * @param role            the role about to be assigned, fully populated
     * @return {@code true} if the admin confirms the assignment
     */
    private boolean confirmAssignment(String username, String currentRoleName, Role role) {
        StringBuilder details = new StringBuilder();
        details.append("User:         ").append(username).append('\n');
        details.append("Current role: ").append(currentRoleName != null ? currentRoleName : "(none)").append('\n');
        details.append("New role:     ").append(role.getName()).append("\n\n");

        Set<String> channelIds = role.getChannelIds();
        if (channelIds == null || channelIds.isEmpty()) {
            details.append("Channel access: All channels\n\n");
        } else {
            details.append("Channel access: restricted to ").append(channelIds.size()).append(" channel(s):\n");
            List<String> channelLabels = new ArrayList<>();
            for (String id : channelIds) {
                String name = cachedChannelMap.get(id);
                channelLabels.add(name != null ? "  " + name : "  " + id + " (deleted)");
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
            details.append("  (none — the user could log in but perform no actions)\n");
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

    /**
     * A single mutating REST call, allowed to throw {@link ClientException}.
     */
    @FunctionalInterface
    private interface MutationCall {
        void run() throws ClientException;
    }

    /**
     * Runs a mutating REST call off the EDT, then on the EDT either surfaces a
     * {@link ClientException} to the user or refreshes the panel on success.
     * Centralizes the error/refresh policy shared by every role and assignment
     * mutation.
     *
     * @param call the REST mutation to perform
     */
    private void runMutation(MutationCall call) {
        new SwingWorker<Void, Void>() {
            private ClientException error;

            @Override
            protected Void doInBackground() {
                try {
                    call.run();
                } catch (ClientException e) {
                    error = e;
                }
                return null;
            }

            @Override
            protected void done() {
                if (error != null) {
                    parent.alertThrowable(parent, error);
                    return;
                }
                doRefresh();
            }
        }.execute();
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
            runMutation(() -> parent.mirthClient.getServlet(RbacServletInterface.class).removeUserRole(userId));
        }
    }
}
