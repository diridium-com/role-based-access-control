// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.KeyEvent;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.border.TitledBorder;

import com.mirth.connect.client.ui.Frame;

/**
 * Modal dialog used to add a new role or edit an existing one.
 *
 * <p>The editor has two tabs: <b>Permissions</b> (grouped checkboxes for
 * the engine's core permission constants plus any extension permissions
 * the server reports), and <b>Channel Restrictions</b> (radio choice
 * between "all channels" or a whitelist with per-channel checkboxes).</p>
 *
 * <p>The dialog is modal — when {@link #setVisible(boolean) setVisible(true)}
 * returns, the caller reads the result via {@link #getResult()}. A null
 * return means the user cancelled; a non-null {@link Role} means the user
 * accepted the changes and the caller should persist them via REST.</p>
 *
 * <p>The admin role's name field (identified by {@link Role#isAdmin()}, not
 * by name) is disabled on entry so it can't be renamed from the UI; the
 * substantive admin-role protections live in the server-side
 * {@code AdminRoleGuard}.</p>
 */
public class RoleEditorDialog extends JDialog {

    private Role result = null;
    private final Role existingRole;

    private JTextField nameField;
    private JTextField descriptionField;
    private final Map<String, JCheckBox> permissionCheckboxes = new LinkedHashMap<>();
    private JRadioButton allChannelsRadio;
    private JRadioButton specificChannelsRadio;
    private final Map<String, JCheckBox> channelCheckboxes = new LinkedHashMap<>();
    // channelId -> "Purge" checkbox, for channels this role references that no
    // longer exist. Default unchecked: the reference is kept (and re-persisted
    // on save) unless the admin positively checks Purge.
    private final Map<String, JCheckBox> orphanPurgeCheckboxes = new LinkedHashMap<>();
    // Granted permissions that are not in the fetched catalog (e.g. an extension
    // was temporarily uninstalled). No checkbox is rendered for them; they are
    // preserved by default on save so an unrelated edit doesn't silently revoke
    // them, mirroring the keep-by-default policy for deleted-channel references.
    private final Set<String> orphanPermissions = new HashSet<>();
    // True when the dialog was opened with no permission catalog. A save in this
    // state on an existing role would persist an empty permission set (a silent
    // wipe), so save() refuses it as a belt-and-suspenders behind the panel guard.
    private final boolean permissionCatalogEmpty;

    // Minimum permissions required for a user to log in and use the UI
    private static final Set<String> BASE_PERMISSIONS = new HashSet<>(Arrays.asList(
            "viewDashboard", "viewChannels", "viewChannelGroups", "viewTags"));

    // Read-only preset: all "view" permissions
    private static final Set<String> READ_ONLY_PERMISSIONS = new HashSet<>(Arrays.asList(
            "viewDashboard", "viewChannels", "viewChannelGroups", "viewTags",
            "viewMessages", "viewAlerts", "viewCodeTemplates", "viewGlobalScripts",
            "viewEvents", "viewServerSettings", "viewConfigurationMap",
            "viewDatabaseTasks", "viewResources"));

    // Group permissions by category for display
    private static final Map<String, List<String>> PERMISSION_GROUPS = new LinkedHashMap<>();

    static {
        PERMISSION_GROUPS.put("Channels", Arrays.asList(
                "viewChannels", "viewChannelGroups", "manageChannels",
                "clearStatistics", "startStopChannels", "deployUndeployChannels"));
        PERMISSION_GROUPS.put("Messages", Arrays.asList(
                "viewMessages", "removeMessages", "removeResults", "removeAllMessages",
                "processMessages", "reprocessMessages", "reprocessResults",
                "importMessages", "exportMessagesServer"));
        PERMISSION_GROUPS.put("Dashboard", Arrays.asList("viewDashboard"));
        PERMISSION_GROUPS.put("Alerts", Arrays.asList("viewAlerts", "manageAlerts"));
        PERMISSION_GROUPS.put("Code Templates", Arrays.asList("viewCodeTemplates", "manageCodeTemplates"));
        PERMISSION_GROUPS.put("Global Scripts", Arrays.asList("viewGlobalScripts", "editGlobalScripts"));
        PERMISSION_GROUPS.put("Tags", Arrays.asList("viewTags", "manageTags"));
        PERMISSION_GROUPS.put("Events", Arrays.asList("viewEvents", "removeEvents"));
        PERMISSION_GROUPS.put("Users", Arrays.asList("manageUsers"));
        PERMISSION_GROUPS.put("Extensions", Arrays.asList("manageExtensions"));
        PERMISSION_GROUPS.put("Server Settings", Arrays.asList(
                "viewServerSettings", "editServerSettings",
                "backupServerConfiguration", "restoreServerConfiguration",
                "clearLifetimeStats", "sendTestEmail"));
        PERMISSION_GROUPS.put("Configuration Map", Arrays.asList("viewConfigurationMap", "editConfigurationMap"));
        PERMISSION_GROUPS.put("Database", Arrays.asList(
                "editDatabaseDrivers", "viewDatabaseTasks", "manageDatabaseTasks"));
        PERMISSION_GROUPS.put("Resources", Arrays.asList("viewResources", "editResources", "reloadResources"));
    }

    /**
     * @param parent              the owning frame; used to position the dialog
     *                            and as the modal parent
     * @param existingRole        the role to edit, or {@code null} when adding
     *                            a new role
     * @param allPermissions      every permission identifier the role editor
     *                            should offer as a checkbox; this is the
     *                            union of core + extension permissions
     *                            fetched from the server. Permissions not in
     *                            {@link #PERMISSION_GROUPS} render under their
     *                            publishing plugin's header (or "Other" when
     *                            the plugin is unknown)
     * @param extensionGroups     permission display name → publishing plugin
     *                            name (from {@code GET /permissions/extensions});
     *                            {@code null} tolerated — every uncategorized
     *                            permission then falls back to "Other"
     * @param channelIdsAndNames  ordered map of channel id → display name;
     *                            populates the channel-restriction checklist
     */
    public RoleEditorDialog(Frame parent, Role existingRole, Set<String> allPermissions,
            Map<String, String> extensionGroups, Map<String, String> channelIdsAndNames) {
        super(parent, existingRole == null ? "Add Role" : "Edit Role", true);
        this.existingRole = existingRole;
        this.permissionCatalogEmpty = (allPermissions == null || allPermissions.isEmpty());
        initComponents(allPermissions, extensionGroups, channelIdsAndNames);
        if (existingRole != null) {
            populateFromRole(existingRole);
        }
        // Escape closes the dialog as a cancel (result stays null), matching the
        // getResult() contract and the OIE house style for plugin dialogs.
        getRootPane().registerKeyboardAction(e -> dispose(),
                KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
                JComponent.WHEN_IN_FOCUSED_WINDOW);
        setSize(700, 600);
        setLocationRelativeTo(parent);
    }

    private void initComponents(Set<String> allPermissions, Map<String, String> extensionGroups,
            Map<String, String> channelIdsAndNames) {
        setLayout(new BorderLayout());

        // ========== Top: Name & Description ==========
        JPanel topPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 10, 5, 10);
        gbc.anchor = GridBagConstraints.WEST;

        gbc.gridx = 0; gbc.gridy = 0;
        topPanel.add(new JLabel("Name:"), gbc);
        nameField = new JTextField(30);
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0;
        topPanel.add(nameField, gbc);

        gbc.gridx = 0; gbc.gridy = 1; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        topPanel.add(new JLabel("Description:"), gbc);
        descriptionField = new JTextField(30);
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0;
        topPanel.add(descriptionField, gbc);
        add(topPanel, BorderLayout.NORTH);

        // ========== Center: Tabbed Pane ==========
        JTabbedPane tabbedPane = new JTabbedPane();

        // --- Permissions Tab ---
        JPanel permissionsPanel = new JPanel(new BorderLayout());

        // Preset buttons
        JPanel selectPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton selectAllBtn = new JButton("Select All");
        selectAllBtn.addActionListener(e -> setAllPermissions(true));
        JButton deselectAllBtn = new JButton("Deselect All");
        deselectAllBtn.addActionListener(e -> setAllPermissions(false));
        JButton readOnlyBtn = new JButton("Read-Only");
        readOnlyBtn.setToolTipText("Select all view-only permissions (minimum for a functional read-only user)");
        readOnlyBtn.addActionListener(e -> applyPreset(READ_ONLY_PERMISSIONS));
        selectPanel.add(selectAllBtn);
        selectPanel.add(deselectAllBtn);
        selectPanel.add(readOnlyBtn);
        // The admin role's permissions are locked (re-sent as-is on save), so its preset
        // buttons would only produce spurious "missing base permissions" warnings. Disable
        // them alongside the per-permission checkboxes (disabled in populateFromRole).
        if (existingRole != null && existingRole.isAdmin()) {
            selectAllBtn.setEnabled(false);
            deselectAllBtn.setEnabled(false);
            readOnlyBtn.setEnabled(false);
        }
        permissionsPanel.add(selectPanel, BorderLayout.NORTH);

        // Build grouped permission panels
        Set<String> allPermsSet = allPermissions != null ? allPermissions : new TreeSet<>();
        Set<String> categorized = new HashSet<>();
        List<JPanel> groupPanels = new ArrayList<>();

        for (Map.Entry<String, List<String>> group : PERMISSION_GROUPS.entrySet()) {
            JPanel groupPanel = new JPanel();
            groupPanel.setLayout(new BoxLayout(groupPanel, BoxLayout.Y_AXIS));
            groupPanel.setBorder(BorderFactory.createTitledBorder(
                    BorderFactory.createEtchedBorder(), group.getKey(),
                    TitledBorder.DEFAULT_JUSTIFICATION, TitledBorder.DEFAULT_POSITION));

            for (String perm : group.getValue()) {
                if (allPermsSet.contains(perm)) {
                    JCheckBox cb = new JCheckBox(perm);
                    applyPermissionWarning(cb, perm);
                    permissionCheckboxes.put(perm, cb);
                    groupPanel.add(cb);
                    categorized.add(perm);
                }
            }

            if (groupPanel.getComponentCount() > 0) {
                groupPanels.add(groupPanel);
            }
        }

        // Uncategorized catalog entries are plugin-published (ExtensionPermission
        // display names): render one titled panel per publishing plugin, in
        // plugin-name order, with anything unattributed in a trailing "Other".
        Set<String> uncategorized = new TreeSet<>(allPermsSet);
        uncategorized.removeAll(categorized);
        if (!uncategorized.isEmpty()) {
            Map<String, String> extGroups = extensionGroups != null ? extensionGroups : new HashMap<>();
            Map<String, List<String>> byPlugin = new TreeMap<>();
            List<String> other = new ArrayList<>();
            for (String perm : uncategorized) {
                String plugin = extGroups.get(perm);
                if (plugin != null && !plugin.isEmpty()) {
                    byPlugin.computeIfAbsent(plugin, k -> new ArrayList<>()).add(perm);
                } else {
                    other.add(perm);
                }
            }
            if (!other.isEmpty()) {
                byPlugin.put("Other", other);
            }
            for (Map.Entry<String, List<String>> pluginGroup : byPlugin.entrySet()) {
                JPanel pluginPanel = new JPanel();
                pluginPanel.setLayout(new BoxLayout(pluginPanel, BoxLayout.Y_AXIS));
                pluginPanel.setBorder(BorderFactory.createTitledBorder(
                        BorderFactory.createEtchedBorder(), pluginGroup.getKey(),
                        TitledBorder.DEFAULT_JUSTIFICATION, TitledBorder.DEFAULT_POSITION));

                for (String perm : pluginGroup.getValue()) {
                    JCheckBox cb = new JCheckBox(perm);
                    applyPermissionWarning(cb, perm);
                    permissionCheckboxes.put(perm, cb);
                    pluginPanel.add(cb);
                }
                groupPanels.add(pluginPanel);
            }
        }

        // Lay out group panels in a 2-column grid
        int cols = 2;
        int rows = (groupPanels.size() + cols - 1) / cols;
        JPanel permGridPanel = new JPanel(new GridBagLayout());
        GridBagConstraints pgbc = new GridBagConstraints();
        pgbc.fill = GridBagConstraints.BOTH;
        pgbc.weightx = 1.0;
        pgbc.insets = new Insets(2, 2, 2, 2);
        pgbc.anchor = GridBagConstraints.NORTH;

        for (int i = 0; i < groupPanels.size(); i++) {
            pgbc.gridx = i % cols;
            pgbc.gridy = i / cols;
            pgbc.weighty = 0;
            permGridPanel.add(groupPanels.get(i), pgbc);
        }
        // Add filler at bottom to push groups to top
        pgbc.gridx = 0;
        pgbc.gridy = rows;
        pgbc.gridwidth = cols;
        pgbc.weighty = 1.0;
        permGridPanel.add(new JPanel(), pgbc);

        JScrollPane permScroll = new JScrollPane(permGridPanel);
        permissionsPanel.add(permScroll, BorderLayout.CENTER);
        tabbedPane.addTab("Permissions", permissionsPanel);

        // --- Channel Restrictions Tab ---
        JPanel channelsPanel = new JPanel(new BorderLayout());

        JPanel radioPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        ButtonGroup channelGroup = new ButtonGroup();
        allChannelsRadio = new JRadioButton("All Channels", true);
        specificChannelsRadio = new JRadioButton("Specific Channels");
        channelGroup.add(allChannelsRadio);
        channelGroup.add(specificChannelsRadio);
        radioPanel.add(allChannelsRadio);
        radioPanel.add(specificChannelsRadio);
        channelsPanel.add(radioPanel, BorderLayout.NORTH);

        JPanel channelCheckboxPanel = new JPanel();
        channelCheckboxPanel.setLayout(new BoxLayout(channelCheckboxPanel, BoxLayout.Y_AXIS));

        // Channels this role references that no longer exist (deleted since the
        // restriction was set). Listed at the top, read-only, with a per-row Purge
        // checkbox so the admin can deliberately drop a reference, while keeping it
        // by default (the same channel id returns if the channel is re-imported from
        // export). All children use LEFT_ALIGNMENT so the BoxLayout lines them up
        // flush-left with the live channel checkboxes below.
        Set<String> liveChannelIds = channelIdsAndNames != null ? channelIdsAndNames.keySet() : new HashSet<>();
        List<String> orphanChannelIds = new ArrayList<>();
        if (existingRole != null && existingRole.getChannelIds() != null) {
            for (String channelId : existingRole.getChannelIds()) {
                if (!liveChannelIds.contains(channelId)) {
                    orphanChannelIds.add(channelId);
                }
            }
        }
        if (!orphanChannelIds.isEmpty()) {
            JPanel orphanPanel = new JPanel();
            orphanPanel.setLayout(new BoxLayout(orphanPanel, BoxLayout.Y_AXIS));
            orphanPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
            orphanPanel.setBorder(BorderFactory.createTitledBorder(
                    BorderFactory.createEtchedBorder(), "Deleted channels (no longer exist)",
                    TitledBorder.DEFAULT_JUSTIFICATION, TitledBorder.DEFAULT_POSITION));
            JLabel orphanHint = new JLabel("Still referenced by this role. Check Purge to remove a reference on Apply.");
            orphanHint.setAlignmentX(Component.LEFT_ALIGNMENT);
            orphanPanel.add(orphanHint);
            for (String channelId : orphanChannelIds) {
                JPanel row = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
                row.setAlignmentX(Component.LEFT_ALIGNMENT);
                JCheckBox purge = new JCheckBox("Purge");
                purge.setEnabled(false);
                orphanPurgeCheckboxes.put(channelId, purge);
                row.add(purge);
                row.add(new JLabel(channelId + "  (deleted)"));
                orphanPanel.add(row);
            }
            channelCheckboxPanel.add(orphanPanel);
        }

        if (channelIdsAndNames != null) {
            for (Map.Entry<String, String> entry : channelIdsAndNames.entrySet()) {
                String channelId = entry.getKey();
                String channelName = entry.getValue();
                String displayLabel = channelName + " (" + channelId + ")";
                JCheckBox cb = new JCheckBox(displayLabel);
                cb.setAlignmentX(Component.LEFT_ALIGNMENT);
                channelCheckboxes.put(channelId, cb);
                cb.setEnabled(false);
                channelCheckboxPanel.add(cb);
            }
        }

        JScrollPane channelScroll = new JScrollPane(channelCheckboxPanel);
        channelsPanel.add(channelScroll, BorderLayout.CENTER);

        // Enable/disable channel checkboxes based on radio selection
        allChannelsRadio.addActionListener(e -> setChannelCheckboxesEnabled(false));
        specificChannelsRadio.addActionListener(e -> setChannelCheckboxesEnabled(true));

        tabbedPane.addTab("Channel Restrictions", channelsPanel);
        add(tabbedPane, BorderLayout.CENTER);

        // ========== Bottom: Apply/Cancel ==========
        // "Apply" rather than "Save": the panel commits the result via REST the
        // moment this dialog confirms, unlike the staged Save on other settings tabs.
        JPanel bottomPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton applyButton = new JButton("Apply");
        applyButton.addActionListener(e -> save());
        JButton cancelButton = new JButton("Cancel");
        cancelButton.addActionListener(e -> dispose());
        bottomPanel.add(applyButton);
        bottomPanel.add(cancelButton);
        add(bottomPanel, BorderLayout.SOUTH);
    }

    private void populateFromRole(Role role) {
        nameField.setText(role.getName());
        descriptionField.setText(role.getDescription());

        // Disable renaming the admin role. Identify it by its flag, not its
        // name — the admin role can be renamed, so a name match is unreliable.
        if (role.isAdmin()) {
            nameField.setEnabled(false);
            // The admin role's permissions and channel access cannot be reduced
            // (AdminRoleGuard rejects it), so disable those controls rather than
            // inviting an edit the server will always reject. Only the description
            // stays editable; save() re-sends the stored perms/channels for admin.
            for (JCheckBox cb : permissionCheckboxes.values()) {
                cb.setEnabled(false);
            }
            allChannelsRadio.setEnabled(false);
            specificChannelsRadio.setEnabled(false);
            setChannelCheckboxesEnabled(false);
        }

        // Check granted permissions
        if (role.getPermissions() != null) {
            for (String perm : role.getPermissions()) {
                JCheckBox cb = permissionCheckboxes.get(perm);
                if (cb != null) {
                    cb.setSelected(true);
                } else {
                    // Granted permission with no checkbox (not in the fetched catalog,
                    // e.g. a temporarily-uninstalled extension). Preserve it on save
                    // instead of silently dropping it.
                    orphanPermissions.add(perm);
                }
            }
        }

        // Channel restrictions
        if (role.getChannelIds() != null && !role.getChannelIds().isEmpty()) {
            specificChannelsRadio.setSelected(true);
            setChannelCheckboxesEnabled(true);
            for (String channelId : role.getChannelIds()) {
                JCheckBox cb = channelCheckboxes.get(channelId);
                if (cb != null) {
                    cb.setSelected(true);
                }
            }
        }
    }

    /**
     * Adds a warning tooltip to especially privileged permissions so the person
     * assigning them understands the blast radius. {@code manageExtensions} in
     * particular can disable RBAC itself and revert the engine to allow-all.
     */
    private static void applyPermissionWarning(JCheckBox cb, String perm) {
        if ("manageExtensions".equals(perm)) {
            cb.setToolTipText("<html>Manage Extensions grants full control over installed plugins,"
                    + "<br>including disabling RBAC itself. A user with this permission can"
                    + "<br>effectively remove all access control after a server restart."
                    + "<br>Grant only to fully trusted administrators.</html>");
        }
    }

    private void setAllPermissions(boolean selected) {
        for (JCheckBox cb : permissionCheckboxes.values()) {
            cb.setSelected(selected);
        }
    }

    private void applyPreset(Set<String> preset) {
        for (Map.Entry<String, JCheckBox> entry : permissionCheckboxes.entrySet()) {
            entry.getValue().setSelected(preset.contains(entry.getKey()));
        }
    }

    private void setChannelCheckboxesEnabled(boolean enabled) {
        for (JCheckBox cb : channelCheckboxes.values()) {
            cb.setEnabled(enabled);
        }
        for (JCheckBox cb : orphanPurgeCheckboxes.values()) {
            cb.setEnabled(enabled);
        }
    }

    private void save() {
        String name = nameField.getText().trim();
        if (name.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Role name is required.", "Validation Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        // Refuse to save an existing role when no permission catalog was available: with
        // no checkboxes rendered, the collected set would be empty and Apply would wipe
        // the role's permissions. The panel guards against this too; this is a backstop.
        if (permissionCatalogEmpty && existingRole != null) {
            JOptionPane.showMessageDialog(this,
                    "The permission list did not load, so this role cannot be edited safely.\n"
                            + "Close this dialog, click Refresh, and try again.",
                    "Permissions Unavailable", JOptionPane.ERROR_MESSAGE);
            return;
        }

        // Collect selected permissions
        Set<String> selectedPerms = new HashSet<>();
        for (Map.Entry<String, JCheckBox> entry : permissionCheckboxes.entrySet()) {
            if (entry.getValue().isSelected()) {
                selectedPerms.add(entry.getKey());
            }
        }
        // Preserve grants that have no checkbox (catalog gaps), matching the
        // keep-by-default policy used for deleted-channel references.
        selectedPerms.addAll(orphanPermissions);

        // Warn if base permissions are missing
        Set<String> missingBase = new HashSet<>(BASE_PERMISSIONS);
        missingBase.removeAll(selectedPerms);
        if (!missingBase.isEmpty()) {
            int choice = JOptionPane.showConfirmDialog(this,
                    "This role is missing base permissions needed for login:\n" + missingBase
                            + "\n\nUsers with this role may not be able to use the UI.\nApply anyway?",
                    "Missing Base Permissions", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
            if (choice != JOptionPane.YES_OPTION) {
                return;
            }
        }

        // Collect channel restrictions
        Set<String> selectedChannels = new HashSet<>();
        if (specificChannelsRadio.isSelected()) {
            for (Map.Entry<String, JCheckBox> entry : channelCheckboxes.entrySet()) {
                if (entry.getValue().isSelected()) {
                    selectedChannels.add(entry.getKey());
                }
            }
            // Keep references to deleted channels unless the admin checked Purge.
            for (Map.Entry<String, JCheckBox> entry : orphanPurgeCheckboxes.entrySet()) {
                if (!entry.getValue().isSelected()) {
                    selectedChannels.add(entry.getKey());
                }
            }
            // Flip guard: "Specific Channels" with an empty set means unrestricted
            // (all channels), not "no access". Make that explicit before saving.
            if (selectedChannels.isEmpty()) {
                int choice = JOptionPane.showConfirmDialog(this,
                        "This role will no longer be restricted to specific channels.\n"
                                + "Users with this role will be able to access ALL channels.\n\nContinue?",
                        "No Channel Restrictions", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
                if (choice != JOptionPane.YES_OPTION) {
                    return;
                }
            }
        }

        // All validation/confirmation passed — build the result only now, so an
        // earlier cancel can't leave a stale non-null result for getResult().
        Role built = new Role();
        if (existingRole != null) {
            built.setId(existingRole.getId());
        }
        built.setName(name);
        built.setDescription(descriptionField.getText().trim());
        if (existingRole != null && existingRole.isAdmin()) {
            // Admin role: permission and channel controls are locked, so re-send the
            // stored values unchanged. Only the description (or name) can differ, and the
            // guard's retention floor is always satisfied.
            built.setPermissions(existingRole.getPermissions() != null
                    ? new HashSet<>(existingRole.getPermissions()) : new HashSet<>());
            built.setChannelIds(existingRole.getChannelIds() != null
                    ? new HashSet<>(existingRole.getChannelIds()) : new HashSet<>());
        } else {
            built.setPermissions(selectedPerms);
            built.setChannelIds(selectedChannels);
        }

        result = built;
        dispose();
    }

    /**
     * Returns the user's selection after the dialog has closed. Call this
     * after {@link #setVisible(boolean) setVisible(true)} returns control.
     *
     * @return the role the user wanted to save (Add → new Role, Edit → the
     *         updated Role with the original id preserved), or {@code null}
     *         if the user cancelled or pressed Escape
     */
    public Role getResult() {
        return result;
    }
}
