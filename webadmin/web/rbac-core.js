// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

/*
 * Framework-agnostic core for the RBAC web UI: the permission grouping, presets,
 * orphan-permission helpers, the assignment-preview text builder, and every dialog
 * string — all ported 1:1 from the Swing client's RoleEditorDialog /
 * RbacSettingsPanel so the web administrator shows byte-identical texts.
 *
 * No DOM/React here — just data and strings. roles-panel.jsx / role-editor.jsx
 * build on top of this; it is unit-testable with plain `node --test`.
 */

/* ---- permission catalog grouping (RoleEditorDialog.PERMISSION_GROUPS, 1:1) -- */

// The exact ordered 14-group map from the Swing static initializer. Catalog
// entries in none of these groups are bucketed under the publishing plugin's
// own header (via the /permissions/extensions map) or a trailing "Other".
export const PERMISSION_GROUPS = {
    'Channels': [
        'viewChannels', 'viewChannelGroups', 'manageChannels',
        'clearStatistics', 'startStopChannels', 'deployUndeployChannels'],
    'Messages': [
        'viewMessages', 'removeMessages', 'removeResults', 'removeAllMessages',
        'processMessages', 'reprocessMessages', 'reprocessResults',
        'importMessages', 'exportMessagesServer'],
    'Dashboard': ['viewDashboard'],
    'Alerts': ['viewAlerts', 'manageAlerts'],
    'Code Templates': ['viewCodeTemplates', 'manageCodeTemplates'],
    'Global Scripts': ['viewGlobalScripts', 'editGlobalScripts'],
    'Tags': ['viewTags', 'manageTags'],
    'Events': ['viewEvents', 'removeEvents'],
    'Users': ['manageUsers'],
    'Extensions': ['manageExtensions'],
    'Server Settings': [
        'viewServerSettings', 'editServerSettings',
        'backupServerConfiguration', 'restoreServerConfiguration',
        'clearLifetimeStats', 'sendTestEmail'],
    'Configuration Map': ['viewConfigurationMap', 'editConfigurationMap'],
    'Database': [
        'editDatabaseDrivers', 'viewDatabaseTasks', 'manageDatabaseTasks'],
    'Resources': ['viewResources', 'editResources', 'reloadResources']
};

// Minimum permissions required for a user to log in and use the UI.
export const BASE_PERMISSIONS = [
    'viewDashboard', 'viewChannels', 'viewChannelGroups', 'viewTags'];

// Read-only preset: all "view" permissions (13).
export const READ_ONLY_PERMISSIONS = [
    'viewDashboard', 'viewChannels', 'viewChannelGroups', 'viewTags',
    'viewMessages', 'viewAlerts', 'viewCodeTemplates', 'viewGlobalScripts',
    'viewEvents', 'viewServerSettings', 'viewConfigurationMap',
    'viewDatabaseTasks', 'viewResources'];

/* ---- input tolerance helpers ------------------------------------------------ */

// Roles/catalogs may arrive as arrays (normalizeRole) or Sets; tolerate both.
function toArray(v) {
    if (v == null) return [];
    if (Array.isArray(v)) return v;
    if (v instanceof Set) return [...v];
    return [v];
}

function toSet(v) {
    return v instanceof Set ? v : new Set(toArray(v));
}

// channelIdToName may be a Map or a plain object.
function lookupName(map, id) {
    if (map == null) return undefined;
    if (map instanceof Map) return map.get(id);
    return Object.prototype.hasOwnProperty.call(map, id) ? map[id] : undefined;
}

/* ---- grouping + orphan logic (RoleEditorDialog, 1:1) ------------------------ */

// Buckets the fetched permission catalog into the ordered display groups.
// Groups with no member present in the catalog are skipped (Swing renders no
// panel for them). Uncategorized catalog entries named in extensionGroups
// (permission → publishing plugin, from /permissions/extensions) get one
// header per plugin, in plugin-name order; anything still left lands in a
// trailing, sorted "Other" group. Returns [{ name, permissions }] in render
// order.
export function groupPermissions(catalog, extensionGroups) {
    const all = toSet(catalog);
    const ext = extensionGroups || {};
    const categorized = new Set();
    const groups = [];
    for (const [name, members] of Object.entries(PERMISSION_GROUPS)) {
        const present = members.filter((perm) => all.has(perm));
        present.forEach((perm) => categorized.add(perm));
        if (present.length > 0) {
            groups.push({ name, permissions: present });
        }
    }
    const uncategorized = [...all].filter((perm) => !categorized.has(perm)).sort();
    const byPlugin = new Map();
    const other = [];
    for (const perm of uncategorized) {
        const plugin = Object.prototype.hasOwnProperty.call(ext, perm) ? ext[perm] : null;
        if (plugin) {
            if (!byPlugin.has(plugin)) byPlugin.set(plugin, []);
            byPlugin.get(plugin).push(perm);
        } else {
            other.push(perm);
        }
    }
    for (const plugin of [...byPlugin.keys()].sort()) {
        groups.push({ name: plugin, permissions: byPlugin.get(plugin) });
    }
    if (other.length > 0) {
        groups.push({ name: 'Other', permissions: other });
    }
    return groups;
}

// Granted permissions that are not in the fetched catalog (e.g. an extension
// was temporarily uninstalled). No checkbox is rendered for them; they are
// preserved by default on save so an unrelated edit doesn't silently revoke
// them. Sorted for determinism (Swing keeps them in an unordered HashSet).
export function orphanPermissionsOf(role, catalog) {
    const all = toSet(catalog);
    return toArray(role && role.permissions).filter((perm) => !all.has(perm)).sort();
}

// Base permissions absent from the selection, in declaration order. (Swing
// shows a HashSet's iteration order in the warning; we are deterministic.)
export function missingBase(selected) {
    const sel = toSet(selected);
    return BASE_PERMISSIONS.filter((perm) => !sel.has(perm));
}

/* ---- channels saved by the role editor ------------------------------------- */

// The channel ids a "Specific Channels" save sends: the ticked ones plus every
// stored id the editor's channel list does not contain. The engine redacts the
// list by the editing user's own restriction, so those channels are kept unseen
// rather than dropped. With "All Channels" the caller sends no ids.
export function editorChannelIds(ticked, storedIds, liveIds) {
    const saved = new Set(ticked);
    for (const id of storedIds) {
        if (!liveIds.has(id)) saved.add(id);
    }
    return saved;
}

// A copy of the set with value removed if it was there, added if it was not (a tick
// box in the role editor and the export and import dialogs).
export function toggleIn(set, value) {
    const next = new Set(set);
    if (next.has(value)) next.delete(value); else next.add(value);
    return next;
}

// The line under the role editor's channel list, or null. Only while "Specific
// Channels" is selected and no listed channel is ticked: the role sees no channels,
// unless it keeps stored channels the list does not show (editorChannelIds keeps
// them on Apply), and then it says how many.
export function noChannelsTickedLine(mode, tickedCount, storedIds, liveIds) {
    if (mode !== 'specific' || tickedCount > 0) return null;
    const unseen = [...storedIds].filter((id) => !liveIds.has(id)).length;
    return unseen === 0 ? MSG_NO_CHANNELS_TICKED : keptChannelsText(unseen);
}

// What the editor shows ticked: the whole catalog for the admin role, whose holders
// have every permission whatever its stored list says (issue #28); otherwise the
// role's stored permissions that the catalog has. role is the stored role or null.
export function editorPermissions(role, catalog) {
    if (!role) return new Set();
    if (role.isAdmin) return new Set(catalog);
    return new Set([...role.permissions].filter((p) => catalog.has(p)));
}

export const MSG_ADMIN_EVERY_PERMISSION =
    'The admin role has every permission, including those of plugins installed later.';

// The restricted flag a save sends: the admin role keeps its stored flag, any
// other role is restricted exactly when Specific Channels is selected. role is
// the stored role or null for a new one; mode is 'all' or 'specific'.
export function editorRestricted(role, mode) {
    return role && role.isAdmin ? role.restricted : mode === 'specific';
}

/* ---- assignment preview (RbacSettingsPanel.confirmAssignment, 1:1) ---------- */

// Builds the exact details text Swing shows in the Confirm Role Assignment
// dialog: User/Current role/New role header (labels padded to a common column),
// channel scope ("All channels" vs "restricted to N channel(s):" with sorted
// labels, an id without a name as the id), then the sorted permission
// list — or the explicit "(none — …)" line for an empty role.
export function buildAssignmentPreview(username, currentRoleName, role, channelIdToName) {
    let details = '';
    details += 'User:         ' + username + '\n';
    details += 'Current role: ' + (currentRoleName != null ? currentRoleName : '(none)') + '\n';
    details += 'New role:     ' + role.name + '\n\n';

    const channelIds = toArray(role.channelIds);
    if (!role.restricted) {
        details += 'Channel access: All channels\n\n';
    } else if (channelIds.length === 0) {
        details += 'Channel access: No channels\n\n';
    } else {
        details += 'Channel access: restricted to ' + channelIds.length + ' channel(s):\n';
        const channelLabels = channelIds.map((id) => {
            const name = lookupName(channelIdToName, id);
            return '  ' + (name != null ? name : id);
        });
        channelLabels.sort();
        for (const label of channelLabels) {
            details += label + '\n';
        }
        details += '\n';
    }

    const sortedPerms = toArray(role.permissions).slice().sort();
    details += 'Permissions (' + sortedPerms.length + '):\n';
    if (sortedPerms.length === 0) {
        details += '  (none — the user could log in but perform no actions)\n';
    } else {
        for (const perm of sortedPerms) {
            details += '  ' + perm + '\n';
        }
    }
    return details;
}

/* ---- dialog strings (Swing texts verbatim) ---------------------------------- */

// RoleEditorDialog.applyPermissionWarning — tooltip on the manageExtensions
// checkbox (Swing renders it as <html> with <br> line breaks; \n here).
export const MANAGE_EXTENSIONS_WARNING =
    'Manage Extensions grants full control over installed plugins,\n'
    + 'including disabling RBAC itself. A user with this permission can\n'
    + 'effectively remove all access control after a server restart.\n'
    + 'Grant only to fully trusted administrators.';

// RoleEditorDialog.applyPermissionWarning — tooltip on the Manage Roles checkbox.
export const MANAGE_ROLES_WARNING =
    'Manage Roles is for delegating user management. On its own it gives\n'
    + 'no access to channels or server settings, but a holder can give their\n'
    + 'own account any role, the admin role included.\n'
    + 'Grant it only to someone you would trust as an administrator.';

// The warning tooltip for a permission's checkbox, or null.
export function permissionWarning(perm) {
    if (perm === 'manageExtensions') return MANAGE_EXTENSIONS_WARNING;
    if (perm === 'Manage Roles') return MANAGE_ROLES_WARNING;
    return null;
}

// RoleEditorDialog — Read-Only preset button tooltip.
export const READ_ONLY_TOOLTIP =
    'Select all view-only permissions (minimum for a functional read-only user)';

// RoleEditorDialog — dialog titles.
export const TITLE_ADD_ROLE = 'Add Role';
export const TITLE_EDIT_ROLE = 'Edit Role';

// RoleEditorDialog.save() — empty name (title "Validation Error").
export const MSG_NAME_REQUIRED = 'Role name is required.';
export const TITLE_VALIDATION_ERROR = 'Validation Error';

// RoleEditorDialog.save() — refusal to edit an existing role with no permission
// catalog loaded (title "Permissions Unavailable").
export const MSG_CATALOG_EMPTY_EDIT =
    'The permission list did not load, so this role cannot be edited safely.\n'
    + 'Close this dialog, click Refresh, and try again.';
export const TITLE_PERMISSIONS_UNAVAILABLE = 'Permissions Unavailable';

// RoleEditorDialog.save() — missing-base-permissions warning (Yes/No, title
// "Missing Base Permissions"). Swing embeds the Set's toString ("[a, b]").
export function missingBaseWarningText(missing) {
    return 'This role is missing base permissions needed for login:\n'
        + '[' + toArray(missing).join(', ') + ']'
        + '\n\nUsers with this role may not be able to use the UI.\nApply anyway?';
}
export const TITLE_MISSING_BASE_PERMISSIONS = 'Missing Base Permissions';

// RoleEditorDialog, the line under the channel list while "Specific Channels"
// is selected, nothing is ticked and no channel the list does not show is kept.
export const MSG_NO_CHANNELS_TICKED = 'This role sees no channels until some are ticked.';

// RoleEditorDialog, the same line when channels the list does not show are kept.
export function keptChannelsText(count) {
    return 'This role keeps ' + (count === 1 ? '1 channel' : count + ' channels') + ' this list does not show.';
}

// RbacSettingsPanel — italic notice above the tables.
export const IMMEDIATE_NOTICE =
    'Changes on this tab are applied to the server immediately'
    + ' when you confirm each action. The Save button does not stage changes here.';

// RbacSettingsPanel — table columns and the unassigned-role placeholder.
export const ROLE_COLUMNS = ['ID', 'Name', 'Description'];
export const USER_COLUMNS = ['User ID', 'Username', 'Assigned Role'];
export const NONE_ROLE_LABEL = '(none)';
export const UNKNOWN_ROLE_LABEL = '(unknown)';

// RbacSettingsPanel (UserAssignmentsPanel.lookUpRoleNames): each user's Assigned
// Role text by user id, from one getUserRole(id) call per user (the servlet has no
// bulk read). The role's name; "(none)" for a user with no role (getUserRole
// resolves null); "(unknown)" when the lookup failed, since "(none)" means no role.
export async function lookUpRoleNames(users, getUserRole) {
    const names = {};
    await Promise.all(users.map(async (user) => {
        try {
            const role = await getUserRole(user.id);
            names[user.id] = role ? role.name : NONE_ROLE_LABEL;
        } catch {
            names[user.id] = UNKNOWN_ROLE_LABEL;
        }
    }));
    return names;
}

// RbacSettingsPanel.permissionCatalogNotLoaded() — add/edit guard.
export const MSG_CATALOG_NOT_LOADED =
    'The permission list has not finished loading. Click Refresh and try again.';

// RbacSettingsPanel.channelListNotLoaded() — add/edit guard.
export const MSG_CHANNELS_NOT_LOADED =
    "The channel list didn't load. Click Refresh and try again.";

// RbacSettingsPanel — selection warnings.
export const MSG_SELECT_ROLE_EDIT = 'Please select a role to edit.';
export const MSG_SELECT_ROLE_DELETE = 'Please select a role to delete.';
export const MSG_SELECT_USER_ASSIGN = 'Please select a user to assign a role to.';
export const MSG_SELECT_USER_REMOVE = 'Please select a user to remove their role.';

// RbacSettingsPanel.deleteSelectedRole() — admin-role client guard.
export const MSG_ADMIN_ROLE_CANNOT_DELETE = 'The admin role cannot be deleted.';

// RbacSettingsPanel.deleteSelectedRole() — delete confirm (Yes/No, title
// "Confirm Delete").
export function deleteRoleConfirmText(roleName) {
    return 'Are you sure you want to delete role "' + roleName + '"?\n'
        + 'Users with this role will lose all access.\n\nThis change takes effect immediately.';
}
export const TITLE_CONFIRM_DELETE = 'Confirm Delete';

// RbacSettingsPanel.removeRoleFromUser() — remove confirm (Yes/No, title
// "Confirm Remove").
export function removeRoleConfirmText(username) {
    return 'Remove the role from user "' + username + '"?\n'
        + 'They will lose all access.\n\nThis change takes effect immediately.';
}
export const TITLE_CONFIRM_REMOVE = 'Confirm Remove';

// RbacSettingsPanel.assignRoleToUser() — no roles yet.
export const MSG_NO_ROLES = 'No roles available. Create a role first.';

// RbacSettingsPanel.assignRoleToUser() — role picker prompt (title "Assign Role").
export function assignRolePromptText(username) {
    return 'Select a role for user ' + username + ':';
}
export const TITLE_ASSIGN_ROLE = 'Assign Role';

// RbacSettingsPanel.confirmAssignment() — labels around the preview text
// (OK/Cancel, title "Confirm Role Assignment"); the footer is italic in Swing.
export const ASSIGN_PREVIEW_HEADER = 'Review the access this role grants before assigning:';
export const ASSIGN_PREVIEW_FOOTER = 'This assignment takes effect immediately.';
export const TITLE_CONFIRM_ASSIGNMENT = 'Confirm Role Assignment';
