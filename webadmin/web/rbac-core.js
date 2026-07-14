// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

/*
 * Framework-agnostic core for the RBAC web UI: the permission grouping, presets,
 * orphan-reference helpers, the assignment-preview text builder, and every dialog
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

// Channels this role references that no longer exist (deleted since the
// restriction was set). Order follows the role's channel-id order, as in Swing.
export function orphanChannelIdsOf(role, liveChannelIds) {
    const live = toSet(liveChannelIds);
    return toArray(role && role.channelIds).filter((id) => !live.has(id));
}

// Base permissions absent from the selection, in declaration order. (Swing
// shows a HashSet's iteration order in the warning; we are deterministic.)
export function missingBase(selected) {
    const sel = toSet(selected);
    return BASE_PERMISSIONS.filter((perm) => !sel.has(perm));
}

/* ---- assignment preview (RbacSettingsPanel.confirmAssignment, 1:1) ---------- */

// Builds the exact details text Swing shows in the Confirm Role Assignment
// dialog: User/Current role/New role header (labels padded to a common column),
// channel scope ("All channels" vs "restricted to N channel(s):" with sorted
// labels, deleted channels as "<id> (deleted)"), then the sorted permission
// list — or the explicit "(none — …)" line for an empty role.
export function buildAssignmentPreview(username, currentRoleName, role, channelIdToName) {
    let details = '';
    details += 'User:         ' + username + '\n';
    details += 'Current role: ' + (currentRoleName != null ? currentRoleName : '(none)') + '\n';
    details += 'New role:     ' + role.name + '\n\n';

    const channelIds = toArray(role.channelIds);
    if (channelIds.length === 0) {
        details += 'Channel access: All channels\n\n';
    } else {
        details += 'Channel access: restricted to ' + channelIds.length + ' channel(s):\n';
        const channelLabels = channelIds.map((id) => {
            const name = lookupName(channelIdToName, id);
            return name != null ? '  ' + name : '  ' + id + ' (deleted)';
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

// RoleEditorDialog.save() — flip guard when "Specific Channels" is selected
// with an empty set (Yes/No, title "No Channel Restrictions").
export const MSG_EMPTY_WHITELIST_FLIP =
    'This role will no longer be restricted to specific channels.\n'
    + 'Users with this role will be able to access ALL channels.\n\nContinue?';
export const TITLE_NO_CHANNEL_RESTRICTIONS = 'No Channel Restrictions';

// RoleEditorDialog — Channel Restrictions tab strings. Live channels render as
// "<name> (<id>)"; deleted-channel rows use TWO spaces before "(deleted)"
// (unlike the single space in the assignment preview).
export const ORPHAN_CHANNELS_TITLE = 'Deleted channels (no longer exist)';
export const ORPHAN_CHANNELS_HINT =
    'Still referenced by this role. Check Purge to remove a reference on Apply.';
export function channelDisplayLabel(name, id) {
    return name + ' (' + id + ')';
}
export function orphanChannelRowLabel(id) {
    return id + '  (deleted)';
}

// RbacSettingsPanel — italic notice above the tables.
export const IMMEDIATE_NOTICE =
    'Changes on this tab are applied to the server immediately'
    + ' when you confirm each action. The Save button does not stage changes here.';

// RbacSettingsPanel — table columns and the unassigned-role placeholder.
export const ROLE_COLUMNS = ['ID', 'Name', 'Description'];
export const USER_COLUMNS = ['User ID', 'Username', 'Assigned Role'];
export const NONE_ROLE_LABEL = '(none)';

// RbacSettingsPanel.permissionCatalogNotLoaded() — add/edit guard.
export const MSG_CATALOG_NOT_LOADED =
    'The permission list has not finished loading. Click Refresh and try again.';

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
