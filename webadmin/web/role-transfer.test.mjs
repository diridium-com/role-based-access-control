// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

/*
 * The strings and pure logic of Export Roles and Import Roles in rbac-core.js.
 * The Swing client has the same texts; a change here is a change there.
 *
 * Run: npm test   (from webadmin/; node --test web/)
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import {
    TASK_EXPORT_ROLES, TASK_EXPORT_ROLES_TOOLTIP, TASK_IMPORT_ROLES, TASK_IMPORT_ROLES_TOOLTIP,
    TITLE_EXPORT_ROLES, EXPORT_PROMPT, EXPORT_CHANNELS_LINE, EXPORT_COLUMNS, MSG_NO_ROLES_TO_EXPORT, EXPORT_FILE_NAME, exportedText,
    TITLE_IMPORT_ROLES, IMPORT_APPLY_CHANNELS, IMPORT_MATCH_BY_NAME, IMPORT_COLUMNS,
    importRefusedText, importSourceText, importedText,
    actionLabel, canTick, defaultTick, mergeTicks, pickedIndexes, notesText, nameMatchHint,
    channelNowLabel, channelAfterLabel, channelsNowLines, channelsAfterLines, permissionsAfterLines,
    exportPermissionsLines, exportChannelsLines
} from './rbac-core.js';

const row = (over = {}) => ({
    index: 0, name: 'R', action: 'CREATE', reason: '',
    droppedPermissions: [], matchedChannelCount: 0, channels: 'FROM_FILE',
    existsHere: false, descriptionNow: '', descriptionAfter: '',
    permissionsNow: [], permissionsAfter: [], channelsNow: [], channelsAfter: [],
    ...over
});

const chan = (over = {}) => ({ id: 'id-1', name: 'One', fileName: 'One', match: 'BY_ID', used: true, ...over });

test('the strings are the agreed wording', () => {
    assert.deepEqual([TASK_EXPORT_ROLES, TASK_EXPORT_ROLES_TOOLTIP, TASK_IMPORT_ROLES, TASK_IMPORT_ROLES_TOOLTIP], [
        'Export Roles', 'Export roles to a file.', 'Import Roles', 'Import roles from a file.']);
    assert.equal(TITLE_EXPORT_ROLES, 'Export Roles');
    assert.equal(EXPORT_PROMPT, 'Pick the roles to export. The admin role is never exported.');
    assert.equal(EXPORT_CHANNELS_LINE,
        'Channel restrictions are included. When importing, you can choose not to apply them.');
    assert.deepEqual(EXPORT_COLUMNS, ['Export', 'Role', 'Description', 'Permissions', 'Channels']);
    assert.equal(MSG_NO_ROLES_TO_EXPORT, 'There are no roles to export. The admin role is never exported.');
    assert.equal(EXPORT_FILE_NAME, 'rbac-roles.xml');
    assert.equal(exportedText(3), 'Exported 3 role(s).');
    assert.equal(TITLE_IMPORT_ROLES, 'Import Roles');
    assert.equal(IMPORT_APPLY_CHANNELS, 'Apply channel restrictions from the file');
    assert.equal(IMPORT_MATCH_BY_NAME, "Also match channels by name when the id isn't found");
    assert.deepEqual(IMPORT_COLUMNS, ['Import', 'Role', 'Action', 'Description now', 'Description after',
        'Permissions now', 'Permissions after', 'Channels now', 'Channels after', 'Notes']);
    assert.equal(importRefusedText('bad'), "This file can't be imported: bad");
    assert.equal(importSourceText('1.2.0', '4.7.0'), 'From rbac 1.2.0 on OIE 4.7.0.');
    assert.equal(importedText(2), 'Imported 2 role(s).');
});

test('no string has an em dash', () => {
    const role = { channelIds: new Set(['a']), permissions: new Set(['p']) };
    const all = [TASK_EXPORT_ROLES_TOOLTIP, TASK_IMPORT_ROLES_TOOLTIP, EXPORT_PROMPT, EXPORT_CHANNELS_LINE,
        MSG_NO_ROLES_TO_EXPORT, IMPORT_APPLY_CHANNELS, IMPORT_MATCH_BY_NAME,
        nameMatchHint(2, true, false), notesText(row({ action: 'UNCHANGED' })),
        channelNowLabel(chan({ name: null })), channelAfterLabel(chan({ match: 'NOT_FOUND' })),
        ...exportChannelsLines(role, null), ...exportChannelsLines(role, new Map()),
        ...permissionsAfterLines(row({ droppedPermissions: ['x'] }))];
    for (const s of all) assert.ok(!s.includes(String.fromCharCode(0x2014)), s);
});

test('action labels', () => {
    assert.deepEqual(['CREATE', 'OVERWRITE', 'UNCHANGED', 'SKIP'].map(actionLabel),
        ['New', 'Overwrite', 'Unchanged', 'Skipped']);
    assert.equal(actionLabel('SOMETHING_NEW'), 'SOMETHING_NEW');
});

test('New starts ticked, Overwrite starts unticked, Unchanged and Skipped cannot be ticked', () => {
    assert.deepEqual(['CREATE', 'OVERWRITE', 'UNCHANGED', 'SKIP'].map((a) => canTick(row({ action: a }))),
        [true, true, false, false]);
    assert.deepEqual(['CREATE', 'OVERWRITE'].map((a) => defaultTick(row({ action: a }))), [true, false]);
    const rows = [row({ index: 0, action: 'CREATE' }), row({ index: 1, action: 'OVERWRITE' }),
        row({ index: 2, action: 'UNCHANGED' }), row({ index: 3, action: 'SKIP' })];
    assert.deepEqual([...mergeTicks([], new Set(), rows)], [0]);
});

test('a new preview keeps the choice for a row shown before with the same action, defaults the rest', () => {
    const before = [row({ index: 0, action: 'CREATE' }), row({ index: 1, action: 'OVERWRITE' }),
        row({ index: 2, action: 'SKIP' }), row({ index: 3, name: 'Z', action: 'CREATE' })];
    const ticks = new Set([1]); // the user unticked the New role 0 and 3, ticked the Overwrite role 1
    const after = [row({ index: 0, action: 'CREATE' }), row({ index: 1, action: 'OVERWRITE' }),
        row({ index: 2, action: 'CREATE' }), // was Skipped, now New: default
        row({ index: 3, name: 'Other', action: 'CREATE' })]; // a different role at that position: default
    assert.deepEqual([...mergeTicks(before, ticks, after)].sort(), [1, 2, 3]);
});

test('pick is the ticked rows that can be ticked, ascending', () => {
    const rows = [row({ index: 4, action: 'CREATE' }), row({ index: 1, action: 'OVERWRITE' }),
        row({ index: 2, action: 'UNCHANGED' })];
    assert.deepEqual(pickedIndexes(rows, new Set([4, 1, 2])), [1, 4]);
    assert.deepEqual(pickedIndexes(rows, new Set()), []);
});

test('Notes: the reason, then "Keeps its channels here", joined with "; "', () => {
    assert.equal(notesText(row()), '');
    assert.equal(notesText(row({ reason: 'Why.', channels: 'KEPT' })), 'Why.; Keeps its channels here');
    assert.equal(notesText(row({ channels: 'KEPT' })), 'Keeps its channels here');
    assert.equal(notesText(row({ channels: 'EVERY_CHANNEL' })), '', 'only KEPT is a part');
});

test('Notes: "Same as the role here" only for an Unchanged row with nothing else to say', () => {
    assert.equal(notesText(row({ action: 'UNCHANGED' })), 'Same as the role here');
    assert.equal(notesText(row({ action: 'UNCHANGED', reason: 'Why.' })), 'Why.');
    assert.equal(notesText(row({ action: 'UNCHANGED', channels: 'KEPT' })), 'Keeps its channels here');
    assert.equal(notesText(row({ action: 'OVERWRITE' })), '');
});

test('the name-match hint shows while channel restrictions apply, there are matches and matching by name is off', () => {
    assert.equal(nameMatchHint(2, true, false),
        '2 channel(s) in the file match a channel here only by name. Tick the box above to use them.');
    assert.equal(nameMatchHint(1, true, false),
        '1 channel(s) in the file match a channel here only by name. Tick the box above to use them.');
    assert.equal(nameMatchHint(2, false, false), null, 'restrictions not applied');
    assert.equal(nameMatchHint(0, true, false), null, 'no matches');
    assert.equal(nameMatchHint(2, true, true), null, 'matching by name is on');
});

test('Channels now: empty with no role here, "Every channel" with an empty list, the name or the deleted channel', () => {
    assert.deepEqual(channelsNowLines(row({ existsHere: false })), []);
    assert.deepEqual(channelsNowLines(row({ existsHere: true })), ['Every channel']);
    assert.deepEqual(channelsNowLines(row({
        existsHere: true,
        channelsNow: [chan({ name: 'Alpha', fileName: null }), chan({ id: 'gone-id', name: null, fileName: null, match: 'NOT_FOUND' })]
    })), ['Alpha', 'gone-id (deleted channel)']);
    assert.equal(channelNowLabel(chan({ id: 'x', name: null })), 'x (deleted channel)');
});

test('Channels after: how each channel was found', () => {
    assert.equal(channelAfterLabel(chan()), 'One (found by id)');
    assert.equal(channelAfterLabel(chan({ name: 'New name', fileName: 'Old name' })),
        'New name (found by id, named "Old name" in the file)', 'a rename');
    assert.equal(channelAfterLabel(chan({ match: 'BY_NAME', used: true })), 'One (found by name)', 'by name, used');
    assert.equal(channelAfterLabel(chan({ match: 'BY_NAME', used: false })),
        'One (found by name, not used)', 'by name, box unticked');
    assert.equal(channelAfterLabel(chan({ match: 'NOT_FOUND', used: false })), 'One (not found here)');
    assert.equal(channelAfterLabel(chan({ id: 'abc', name: null, fileName: null, match: 'NOT_FOUND', used: false })),
        'abc (deleted channel)', 'no file name: the Now wording');
    assert.equal(channelAfterLabel(chan({ id: 'abc', name: null, fileName: '', match: 'NOT_FOUND', used: false })),
        'abc (not found here)', 'not found with a null name shows the id');
    assert.equal(channelAfterLabel(chan({ name: 'Kept', fileName: null })), 'Kept', 'a kept copy of the Now list');
});

test('Channels after: empty means every channel, except on a Skipped row', () => {
    assert.deepEqual(channelsAfterLines(row({ action: 'CREATE' })), ['Every channel']);
    assert.deepEqual(channelsAfterLines(row({ action: 'OVERWRITE' })), ['Every channel']);
    assert.deepEqual(channelsAfterLines(row({ action: 'SKIP' })), []);
    assert.deepEqual(channelsAfterLines(row({
        action: 'CREATE', channelsAfter: [chan(), chan({ id: 'b', name: 'Two', fileName: 'Two', match: 'BY_NAME', used: false })]
    })), ['One (found by id)', 'Two (found by name, not used)']);
});

test('Permissions after: the permissions, then each dropped one', () => {
    assert.deepEqual(permissionsAfterLines(row({ permissionsAfter: ['a', 'b'], droppedPermissions: ['gone'] })),
        ['a', 'b', 'gone (not on this engine, left out)']);
    assert.deepEqual(permissionsAfterLines(row()), []);
});

test('Export cells: permissions sorted; channels by name with unknown ids last; every channel; list not loaded', () => {
    assert.deepEqual(exportPermissionsLines({ permissions: new Set(['viewDashboard', 'viewAlerts']) }),
        ['viewAlerts', 'viewDashboard']);
    const map = new Map([['id-b', 'Beta'], ['id-a', 'Alpha']]);
    assert.deepEqual(exportChannelsLines({ channelIds: new Set() }, map), ['Every channel']);
    assert.deepEqual(exportChannelsLines({ channelIds: new Set() }, null), ['Every channel']);
    assert.deepEqual(exportChannelsLines({ channelIds: new Set(['id-b', 'zzz', 'id-a']) }, map),
        ['Alpha', 'Beta', 'zzz (deleted channel)'], 'a map with a missing id');
    assert.deepEqual(exportChannelsLines({ channelIds: new Set(['id-b', 'id-a']) }, null),
        ['id-a (channel list not loaded)', 'id-b (channel list not loaded)'], 'a null map');
});
