// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.table.DefaultTableModel;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import com.mirth.connect.client.core.ClientException;
import com.mirth.connect.client.core.api.servlets.ChannelServletInterface;
import com.mirth.connect.client.core.api.servlets.UserServletInterface;
import com.mirth.connect.client.ui.AbstractSettingsPanel;
import com.mirth.connect.client.ui.Frame;
import com.mirth.connect.client.ui.PlatformUI;
import com.mirth.connect.model.User;

public class RbacSettingsPanel extends AbstractSettingsPanel {

    private static final String[] ROLE_COLUMNS = {"ID", "Name", "Description"};
    private static final String[] USER_COLUMNS = {"User ID", "Username", "Assigned Role"};

    private final Frame parent;
    private final AtomicBoolean refreshing = new AtomicBoolean(false);
    private final AtomicBoolean refreshPending = new AtomicBoolean(false);

    private JTable rolesTable;
    private JTable usersTable;

    private List<Role> cachedRoles = new ArrayList<>();
    private List<User> cachedUsers = new ArrayList<>();
    private Set<String> cachedPermissions;
    private Map<String, String> cachedExtensionGroups = new LinkedHashMap<>();
    private Map<String, String> cachedChannelMap = new LinkedHashMap<>();
    // Whether the last refresh fetched the channel list (read and written on the EDT).
    private boolean channelListLoaded;

    public RbacSettingsPanel(String tabName) {
        super(tabName);
        this.parent = PlatformUI.MIRTH_FRAME;
        this.addTask("doExportRolesXML", "Export XML", "Export Roles in XML.","", new ImageIcon(Frame.class.getResource("images/report_disk.png")));
        this.addTask("doImportRolesXML", "Import XML", "Import Roles in XML.","", new ImageIcon(Frame.class.getResource("images/report_go.png")));
        initComponents();

    }

    private void initComponents() {
        setLayout(new BorderLayout());

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
                        // A failed fetch keeps the old list, and the editor would show the
                        // missing channels as deleted, so add and edit wait for a fresh one.
                        channelListLoaded = channelMap != null;
                        if (channelMap != null) {
                            cachedChannelMap = channelMap;
                        }
                    } finally {
                        refreshing.set(false);
                        if (refreshPending.compareAndSet(true, false)) {
                            doRefresh();
                        }
                    }
                }
            }.execute();
        } else {
            refreshPending.set(true);
        }
    }

    @Override
    public boolean doSave() {
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
            // Ignore
        }
        return null;
    }

    private Role findCachedRole(int roleId) {
        for (Role r : cachedRoles) {
            if (r.getId() != null && r.getId() == roleId) {
                return r;
            }
        }
        return null;
    }

    private Role findRoleByName(String name) {
        for (Role r : cachedRoles) {
            if (r.getName() != null && r.getName().equalsIgnoreCase(name)) {
                return r;
            }
        }
        return null;
    }

    private boolean permissionCatalogNotLoaded() {
        if (cachedPermissions == null || cachedPermissions.isEmpty()) {
            parent.alertWarning(parent, "The permission list has not finished loading. Click Refresh and try again.");
            return true;
        }
        return false;
    }

    /**
     * Guards the role editor against opening when the last refresh did not fetch
     * the channel list. The editor lists every restricted channel missing from
     * the list as deleted, with a Purge checkbox, so a stale or empty list would
     * show live channels as deleted.
     *
     * @return {@code true} (after warning the user) if the channel list is not loaded
     */
    private boolean channelListNotLoaded() {
        if (!channelListLoaded) {
            parent.alertWarning(parent, "The channel list didn't load. Click Refresh and try again.");
            return true;
        }
        return false;
    }

    private void addRole() {
        if (permissionCatalogNotLoaded() || channelListNotLoaded()) {
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

        if (permissionCatalogNotLoaded() || channelListNotLoaded()) {
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

    @FunctionalInterface
    private interface MutationCall {
        void run() throws ClientException;
    }

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

        if (confirm == JOptionPane.YES_OPTION) {
            runMutation(() -> parent.mirthClient.getServlet(RbacServletInterface.class).removeUserRole(userId));
        }
    }

    public void doExportRolesXML() {
        if (cachedRoles.isEmpty()) {
            parent.alertWarning(parent, "No roles available to export.");
            return;
        }
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setSelectedFile(new File("rbac-roles-export.xml"));
        if (fileChooser.showSaveDialog(parent) == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();
            try {
                StringBuilder xml = new StringBuilder();
                xml.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<roles>\n");

                for (Role role : cachedRoles) {
                    xml.append("  <role>\n");
                    xml.append("    <name>").append(escapeXml(role.getName())).append("</name>\n");
                    xml.append("    <description>").append(escapeXml(role.getDescription())).append("</description>\n");

                    xml.append("    <permissions>\n");
                    if (role.getPermissions() != null) {
                        for (String perm : role.getPermissions()) {
                            xml.append("      <permission>").append(escapeXml(perm)).append("</permission>\n");
                        }
                    }
                    xml.append("    </permissions>\n");

                    if (role.getChannelIds() != null && !role.getChannelIds().isEmpty()) {
                        xml.append("    <channels>\n");
                        for (String ch : role.getChannelIds()) {
                            xml.append("      <channel>").append(escapeXml(ch)).append("</channel>\n");
                        }
                        xml.append("    </channels>\n");
                    }

                    xml.append("  </role>\n");
                }
                xml.append("</roles>");

                java.nio.file.Files.write(file.toPath(), xml.toString().getBytes(StandardCharsets.UTF_8));
                JOptionPane.showMessageDialog(parent, "Roles and permissions exported successfully.", "Export", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception ex) {
                parent.alertThrowable(parent, ex);
            }
        }
    }

    public void doImportRolesXML() {
        if (permissionCatalogNotLoaded()) {
            return;
        }
        JFileChooser fileChooser = new JFileChooser();
        if (fileChooser.showOpenDialog(parent) == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();
            try {
                DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
                DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
                Document doc = dBuilder.parse(file);
                doc.getDocumentElement().normalize();

                NodeList roleNodes = doc.getElementsByTagName("role");
                if (roleNodes.getLength() == 0) {
                    parent.alertWarning(parent, "No roles found in XML file.");
                    return;
                }

                for (int i = 0; i < roleNodes.getLength(); i++) {
                    Node nNode = roleNodes.item(i);
                    if (nNode.getNodeType() == Node.ELEMENT_NODE) {
                        Element eElement = (Element) nNode;
                        String name = getTagValue("name", eElement);
                        String description = getTagValue("description", eElement);

                        Set<String> permissions = new HashSet<>();
                        NodeList permNodes = eElement.getElementsByTagName("permission");
                        for (int j = 0; j < permNodes.getLength(); j++) {
                            permissions.add(permNodes.item(j).getTextContent().trim());
                        }

                        Set<String> channels = new HashSet<>();
                        NodeList channelNodes = eElement.getElementsByTagName("channel");
                        for (int j = 0; j < channelNodes.getLength(); j++) {
                            channels.add(channelNodes.item(j).getTextContent().trim());
                        }

                        Role existingRole = findRoleByName(name);
                        if (existingRole != null) {
                            if (existingRole.isAdmin()) {
                                JOptionPane.showMessageDialog(parent, "Skipping admin role '" + name + "': cannot overwrite admin role.", "Warning", JOptionPane.WARNING_MESSAGE);
                                continue;
                            }
                            int option = JOptionPane.showConfirmDialog(parent,
                                    "Role '" + name + "' already exists. Do you want to overwrite it?",
                                    "Role Already Exists", JOptionPane.YES_NO_OPTION);
                            if (option != JOptionPane.YES_OPTION) {
                                continue;
                            }

                            existingRole.setDescription(description);
                            existingRole.setPermissions(permissions);
                            existingRole.setChannelIds(channels);
                            runMutation(() -> parent.mirthClient.getServlet(RbacServletInterface.class).updateRole(existingRole.getId(), existingRole));
                        } else {
                            Role newRole = new Role();
                            newRole.setName(name);
                            newRole.setDescription(description);
                            newRole.setPermissions(permissions);
                            newRole.setChannelIds(channels);
                            runMutation(() -> parent.mirthClient.getServlet(RbacServletInterface.class).createRole(newRole));
                        }
                    }
                }
                JOptionPane.showMessageDialog(parent, "Import process triggered successfully.", "Import", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception ex) {
                parent.alertThrowable(parent, ex);
            }
        }
    }

    private String getTagValue(String tag, Element element) {
        NodeList nlList = element.getElementsByTagName(tag);
        if (nlList.getLength() > 0 && nlList.item(0).getChildNodes().getLength() > 0) {
            Node nValue = nlList.item(0).getChildNodes().item(0);
            return nValue == null ? "" : nValue.getNodeValue().trim();
        }
        return "";
    }

    private String escapeXml(String str) {
        if (str == null) return "";
        return str.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&apos;");
    }
}