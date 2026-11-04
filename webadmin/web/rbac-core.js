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
    if (!role.restricted) {
        details += 'Channel access: All channels\n\n';
    } else if (channelIds.length === 0) {
        details += 'Channel access: No channels\n\n';
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
// is selected and nothing is ticked.
export const MSG_NO_CHANNELS_TICKED = 'This role sees no channels until some are ticked.';

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

/* ---- role export and import (strings and logic match the Swing client) ------ */

// Settings panel tasks.
export const TASK_EXPORT_ROLES = 'Export Roles';
export const TASK_EXPORT_ROLES_TOOLTIP = 'Export roles to a file.';
export const TASK_IMPORT_ROLES = 'Import Roles';
export const TASK_IMPORT_ROLES_TOOLTIP = 'Import roles from a file.';

// Export dialog.
export const TITLE_EXPORT_ROLES = 'Export Roles';
export const EXPORT_PROMPT = 'Pick the roles to export. The admin role is never exported.';
export const EXPORT_CHANNELS_NOTE = 'Channel restrictions are included. ';
export const EXPORT_CHANNELS_BOLD = 'When importing, you can choose not to apply them.';
export const EXPORT_CHANNELS_LINE = EXPORT_CHANNELS_NOTE + EXPORT_CHANNELS_BOLD;
export const EXPORT_COLUMNS = ['Export', 'Role', 'Description', 'Permissions', 'Channels'];
export const MSG_NO_ROLES_TO_EXPORT = 'There are no roles to export. The admin role is never exported.';
export const EXPORT_FILE_NAME = 'rbac-roles.xml';
export function exportedText(count) {
    return 'Exported ' + count + ' role(s).';
}

// Import dialog.
export const TITLE_IMPORT_ROLES = 'Import Roles';
export const IMPORT_APPLY_CHANNELS = 'Apply channel restrictions from the import';
export const IMPORT_MATCH_BY_NAME = "Also match channels by name when the id isn't found";
export const IMPORT_COLUMNS = [
    'Import', 'Role', 'Action', 'Description currently', 'Description after import', 'Permissions', 'Channels', 'Notes'
];
export const PERMISSION_COLUMNS = ['Permission', 'Currently', 'After import', 'Note'];
export const CHANNEL_COLUMNS = [
    'Channel', 'Id on this engine', 'Currently', 'After import', 'Match', 'Name in import', 'Id in import'
];
export const PERMISSIONS_LEGEND = 'Currently: this role has the permission on this engine. After import: this role will have'
    + ' the permission if imported.';
export const CHANNELS_LEGEND = 'Currently: this role is restricted to the channel on this engine. After import: this role will'
    + ' be restricted to the channel if imported. Match: how the import\'s channel was found on this engine.';
export const CHANNELS_NOT_APPLIED = 'Channel restrictions from the import are not applied. Roles that already exist on this'
    + ' engine keep their current channels. New roles are restricted to no channels until an administrator sets'
    + ' channels for them.';
// The channel columns that hold ids (shown in a monospace font).
export const CHANNEL_ID_COLUMNS = [1, 6];
export const EXPORT_PERMISSION_COLUMNS = ['Permission'];
export const EXPORT_CHANNEL_COLUMNS = ['Channel', 'Id on this engine'];
export const EXPORT_CHANNEL_ID_COLUMNS = [1];
const EVERY = 'every';
const NONE = 'none';
const YES = 'yes';
const NO_LONGER_EXISTS = '(no longer exists)';
const DELETED = 'deleted on this engine';
const NOT_IN_IMPORT = 'not in the import';
export const EXPORT_EVERY_CHANNEL = 'This role sees every channel.';
export const EXPORT_NO_CHANNEL = 'This role sees no channels.';
export function importRefusedText(refusal) {
    return "This file can't be imported: " + refusal;
}
export function importSourceText(sourceRbacVersion, sourceEngineVersion) {
    return 'From rbac ' + sourceRbacVersion + ' on OIE ' + sourceEngineVersion + '.';
}
export function importedText(count) {
    return 'Imported ' + count + ' role(s).';
}

const ACTION_LABELS = { CREATE: 'New', OVERWRITE: 'Overwrite', UNCHANGED: 'Unchanged', SKIP: 'Skipped' };

// The Action column text for a row's action.
export function actionLabel(action) {
    return Object.hasOwn(ACTION_LABELS, action) ? ACTION_LABELS[action] : String(action);
}

// Only New and Overwrite rows can be picked.
export function canTick(row) {
    return row.action === 'CREATE' || row.action === 'OVERWRITE';
}

// New starts ticked; Overwrite starts unticked.
export function defaultTick(row) {
    return row.action === 'CREATE';
}

// Ticks for a fresh preview of the same file. A row keeps the user's choice if
// it was shown before with the same name, action and no-channel-found state;
// any other row starts at its default. Returns a Set of row index values.
export function mergeTicks(previousRows, previousTicks, rows) {
    const next = new Set();
    for (const row of rows) {
        if (!canTick(row)) continue;
        const before = previousRows.find((p) => p.index === row.index);
        const same = before && before.name === row.name && before.action === row.action
            && before.noChannelFound === row.noChannelFound;
        if (same ? previousTicks.has(row.index) : defaultTick(row)) next.add(row.index);
    }
    return next;
}

// The ticked rows' index values, in ascending order, for the pick parameter.
export function pickedIndexes(rows, ticks) {
    return rows.filter((row) => canTick(row) && ticks.has(row.index)).map((row) => row.index).sort((a, b) => a - b);
}

// The Notes column text: the server composes it in the row's reason.
export function notesText(row) {
    return row.reason || '';
}

// The hint under the tick boxes: shown while channel restrictions are applied,
// some channels match only by name and the match-by-name box is unticked.
// Returns null when nothing is shown.
export function nameMatchHint(count, applyChannels, matchChannelsByName) {
    if (!applyChannels || matchChannelsByName || count === 0) return null;
    const what = count === 1 ? '1 channel in the import matches' : count + ' channels in the import match';
    return what + ' a channel on this engine by name only. Tick the box above to use them.';
}

export function permissionsHeading(roleName) {
    return 'Permissions of ' + roleName;
}
export function channelsHeading(roleName) {
    return 'Channels of ' + roleName;
}

// Sort rows by a column. key is a column index or property name, or a function
// of the row. Ascending or descending; the sort is stable and returns a copy.
export function sortRows(rows, key, dir) {
    const sign = dir === 'desc' ? -1 : 1;
    const of = typeof key === 'function' ? key : (r) => r[key];
    return rows.map((r, i) => [r, i]).sort((a, b) => {
        const x = of(a[0]);
        const y = of(b[0]);
        return (x > y ? sign : x < y ? -sign : 0) || a[1] - b[1];
    }).map((p) => p[0]);
}

// The Permissions and Channels columns of the roles table. now and after are
// numbers or "every". A role not here shows the after count; an Unchanged row,
// a Skipped row for a role here, or two equal counts show one value; otherwise
// "<now> -> <after>" with the arrow U+2192.
export function countText(row, now, after) {
    if (!row.existsHere) return String(after);
    if (row.action === 'UNCHANGED' || row.action === 'SKIP' || String(now) === String(after)) return String(now);
    return now + ' \u2192 ' + after;
}

const usedCount = (row) => row.channelsAfter.filter((c) => c.used).length;

// The number of channels the role is restricted to, "every" for a role that is
// not restricted, or "none" for a restricted role with no channel, here now
// (null when there is no role here) and after the import. From the flags, never
// from whether a list is empty.
export function channelsNowCount(row) {
    if (!row.existsHere) return null;
    if (!row.restrictedNow) return EVERY;
    return row.channelsNow.length === 0 ? NONE : row.channelsNow.length;
}
export function channelsAfterCount(row) {
    const used = usedCount(row);
    if (row.action === 'SKIP') return used;
    if (!row.restrictedAfter) return EVERY;
    return used === 0 ? NONE : used;
}

export function permissionsCountText(row) {
    return countText(row, row.permissionsNow.length, row.permissionsAfter.length);
}
export function channelsCountText(row) {
    return countText(row, channelsNowCount(row), channelsAfterCount(row));
}

// The line above the channel table when the role sees every channel or no
// channel now, after the import, or both. Empty when it does neither.
export function everyChannelText(row) {
    const parts = [];
    const now = channelsNowCount(row);
    const after = channelsAfterCount(row);
    if (now === EVERY) parts.push('This role sees every channel currently.');
    if (now === NONE) parts.push('This role sees no channels currently.');
    if (after === EVERY) parts.push('This role sees every channel after the import.');
    if (after === NONE) parts.push('This role sees no channels after the import.');
    return parts.join(' ');
}

// How a channel in the import was found on this engine. Empty for an entry that
// is not from the import (a kept copy of the channels here has no id in it).
export function foundText(channel) {
    if (channel.fileId === null) return '';
    if (channel.match === 'BY_ID') {
        return channel.fileName === null || channel.name === channel.fileName ? 'by id' : 'by id, renamed on this engine';
    }
    if (channel.match === 'BY_NAME') return channel.used ? 'by name' : 'by name, not used';
    return 'not on this engine';
}

// One row per permission: the role's current, after-import and left-out permissions, by name.
// A row is [Permission, Currently, After import, Note].
export function permissionRows(row) {
    const now = new Set(row.permissionsNow);
    const after = new Set(row.permissionsAfter);
    const dropped = new Set(row.droppedPermissions);
    return [...new Set([...now, ...after, ...dropped])].sort().map((p) => [
        p, now.has(p) ? YES : '', after.has(p) ? YES : '',
        dropped.has(p) ? 'not offered by this engine, left out' : ''
    ]);
}

// One row per channel: the import's channels in the import's order, then the
// role's other channels on this engine. An import channel that is also one the
// role has on this engine (same id) is one row. A channel the role has that
// no longer exists on this engine reads "deleted on this engine", whether or not
// the import names it; one that exists but is not in the import reads "not in
// the import". A row is [Channel, Id on this engine, Currently, After import,
// Match, Name in import, Id in import].
export function channelRows(row) {
    const nowIds = new Set(row.channelsNow.map((c) => c.id));
    const joined = new Set();
    const rows = row.channelsAfter.map((c) => {
        const fromImport = c.fileId !== null;
        const missing = fromImport && c.match === 'NOT_FOUND';
        const isNow = nowIds.has(c.id);
        if (isNow) joined.add(c.id);
        const name = c.name !== null ? c.name : (c.fileName !== null ? c.fileName : NO_LONGER_EXISTS);
        const match = missing && isNow ? DELETED : foundText(c);
        return [name, missing && !isNow ? '' : c.id, isNow ? YES : '', c.used || !fromImport ? YES : '',
            match, c.fileName === null ? '' : c.fileName, c.fileId === null ? '' : c.fileId];
    });
    for (const c of row.channelsNow) {
        if (!joined.has(c.id)) {
            rows.push([c.name !== null ? c.name : NO_LONGER_EXISTS, c.id, YES, '',
                c.name !== null ? NOT_IN_IMPORT : DELETED, '', '']);
        }
    }
    return rows;
}

// The export dialog's detail rows: [Permission], sorted; [Channel, Id] by name,
// then the ids the channel map does not have. channelMap is a Map of channel id
// to name, or null when the channel list isn't loaded. Names sort in code-unit
// order (the same order as the Swing Administrator's).
export function exportPermissionRows(role) {
    return [...role.permissions].sort().map((p) => [p]);
}
export function exportChannelRows(role, channelMap) {
    const ids = [...role.channelIds];
    if (!channelMap) return ids.sort().map((id) => ['(channel list not loaded)', id]);
    const known = ids.filter((id) => channelMap.has(id)).map((id) => [channelMap.get(id), id]);
    const unknown = ids.filter((id) => !channelMap.has(id)).sort().map((id) => [NO_LONGER_EXISTS, id]);
    return [...known.sort((a, b) => (a[0] > b[0] ? 1 : a[0] < b[0] ? -1 : 0)), ...unknown];
}

// The export table's counts.
export function exportPermissionsCount(role) {
    return role.permissions.size;
}
export function exportChannelsCount(role) {
    if (!role.restricted) return EVERY;
    return role.channelIds.size === 0 ? NONE : role.channelIds.size;
}
