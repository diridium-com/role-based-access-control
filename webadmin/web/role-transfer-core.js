// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

/*
 * The strings and pure logic of Export Roles and Import Roles: the dialog texts,
 * the count columns, the row builders for the detail tables, sorting and the
 * export rows. They match the Swing client (RoleImportText, RoleDetailRows,
 * RoleExportText); a change here is a change there. No DOM or React.
 */

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

// Orders count texts by their first number, with "every" and "none" after any
// number, so "9" sorts before "10" and "12 \u2192 14" sorts as 12; equal first
// numbers fall back to the text. Counts may be numbers or strings.
export function compareCounts(a, b) {
    const x = String(a);
    const y = String(b);
    const fx = firstNumber(x);
    const fy = firstNumber(y);
    if (fx !== fy) return fx < fy ? -1 : 1;
    return x > y ? 1 : x < y ? -1 : 0;
}
function firstNumber(text) {
    const first = text.split(' ')[0];
    return /^\d+$/.test(first) ? Number(first) : Infinity;
}

// Sort rows by a column. key is a column index or property name, or a function
// of the row. Ascending or descending; the sort is stable and returns a copy.
// compare is an optional comparator of two column values (default: < and >).
export function sortRows(rows, key, dir, compare) {
    const sign = dir === 'desc' ? -1 : 1;
    const of = typeof key === 'function' ? key : (r) => r[key];
    const order = compare || ((x, y) => (x > y ? 1 : x < y ? -1 : 0));
    return rows.map((r, i) => [r, i]).sort((a, b) => {
        return sign * order(of(a[0]), of(b[0])) || a[1] - b[1];
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
// role has on this engine (same id) is one row. A channel the role has that is
// not in the import reads "not in the import". A name-less channel shows its
// id in the Channel column. A row is [Channel, Id on this engine, Currently, After import,
// Match, Name in import, Id in import].
export function channelRows(row) {
    const kept = row.channels === 'KEPT';
    const nowIds = new Set(row.channelsNow.map((c) => c.id));
    const joined = new Set();
    const rows = row.channelsAfter.map((c) => {
        const fromImport = !kept && c.fileId !== null;
        const missing = fromImport && c.match === 'NOT_FOUND';
        const isNow = !missing && nowIds.has(c.id);
        if (isNow) joined.add(c.id);
        const name = c.name !== null ? c.name : (c.fileName !== null ? c.fileName : c.id);
        return [name, missing ? '' : c.id, isNow ? YES : '', c.used || !fromImport ? YES : '',
            foundText(c), c.fileName === null ? '' : c.fileName, c.fileId === null ? '' : c.fileId];
    });
    for (const c of row.channelsNow) {
        if (!joined.has(c.id)) {
            rows.push([c.name !== null ? c.name : c.id, c.id, YES, '', NOT_IN_IMPORT, '', '']);
        }
    }
    return rows;
}

// The export dialog's detail rows: [Permission], sorted; [Channel, Id], every
// row sorted case-insensitively by its shown text (the name, or the id for a
// channel the map lacks), then by id, as the Swing Administrator does. channelMap
// is a Map of channel id to name, or null when the channel list isn't loaded.
export function exportPermissionRows(role) {
    return [...role.permissions].sort().map((p) => [p]);
}
export function exportChannelRows(role, channelMap) {
    const rows = [...role.channelIds].map((id) => [channelMap && channelMap.has(id) ? channelMap.get(id) : id, id]);
    return rows.sort((a, b) => compareIgnoreCase(a[0], b[0]) || (a[1] > b[1] ? 1 : a[1] < b[1] ? -1 : 0));
}
// Like Java's String.CASE_INSENSITIVE_ORDER: compare upper-cased, then lower-cased.
function compareIgnoreCase(a, b) {
    const upper = [a.toUpperCase(), b.toUpperCase()];
    if (upper[0] !== upper[1]) return upper[0] > upper[1] ? 1 : -1;
    const lower = [a.toLowerCase(), b.toLowerCase()];
    return lower[0] > lower[1] ? 1 : lower[0] < lower[1] ? -1 : 0;
}

// The export table's counts.
export function exportPermissionsCount(role) {
    return role.permissions.size;
}
export function exportChannelsCount(role) {
    if (!role.restricted) return EVERY;
    return role.channelIds.size === 0 ? NONE : role.channelIds.size;
}
