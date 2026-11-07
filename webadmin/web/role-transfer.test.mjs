// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

/*
 * The strings and pure logic of Export Roles and Import Roles in role-transfer-core.js.
 * The Swing client has the same texts; a change here is a change there.
 *
 * Run: npm test   (from webadmin/; node --test web/)
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import {
    TASK_EXPORT_ROLES, TASK_EXPORT_ROLES_TOOLTIP, TASK_IMPORT_ROLES, TASK_IMPORT_ROLES_TOOLTIP,
    TITLE_EXPORT_ROLES, EXPORT_PROMPT, EXPORT_CHANNELS_NOTE, EXPORT_CHANNELS_BOLD, EXPORT_COLUMNS, MSG_NO_ROLES_TO_EXPORT, EXPORT_FILE_NAME, exportedText,
    TITLE_IMPORT_ROLES, IMPORT_APPLY_CHANNELS, IMPORT_MATCH_BY_NAME, IMPORT_COLUMNS,
    importRefusedText, importSourceText, importedText,
    actionLabel, canTick, defaultTick, mergeTicks, pickedIndexes, notesText, nameMatchHint,
    PERMISSION_COLUMNS, CHANNEL_COLUMNS, CHANNEL_ID_COLUMNS, PERMISSIONS_LEGEND, CHANNELS_LEGEND, CHANNELS_NOT_APPLIED,
    EXPORT_PERMISSION_COLUMNS, EXPORT_CHANNEL_COLUMNS,
    EXPORT_EVERY_CHANNEL, EXPORT_NO_CHANNEL, countText, permissionsCountText, channelsCountText, everyChannelText, foundText,
    permissionRows, channelRows, permissionsHeading, channelsHeading, sortRows, compareCounts,
    exportPermissionRows, exportChannelRows, exportPermissionsCount, exportChannelsCount,
    compareIgnoreCase, sortByColumn, EXPORT_COUNT_COLUMNS, IMPORT_COUNT_COLUMNS
} from './role-transfer-core.js';
import { MSG_NO_CHANNELS_TICKED } from './rbac-core.js';

const row = (over = {}) => ({
    index: 0, name: 'R', action: 'CREATE', reason: '',
    droppedPermissions: [], matchedChannelCount: 0, channels: 'FROM_FILE',
    noChannelFound: false, existsHere: false, restrictedNow: false, restrictedAfter: false, descriptionNow: '', descriptionAfter: '',
    permissionsNow: [], permissionsAfter: [], channelsNow: [], channelsAfter: [],
    ...over
});

// A channel from the file, found by id; a channel in a "now" list overrides fileId and fileName with null.
const chan = (over = {}) => ({ id: 'id-1', name: 'One', fileId: 'id-1', fileName: 'One', match: 'BY_ID', used: true, ...over });
const nowChan = (over = {}) => chan({ fileId: null, fileName: null, ...over });

test('the strings are the agreed wording', () => {
    assert.deepEqual([TASK_EXPORT_ROLES, TASK_EXPORT_ROLES_TOOLTIP, TASK_IMPORT_ROLES, TASK_IMPORT_ROLES_TOOLTIP], [
        'Export Roles', 'Export roles to a file.', 'Import Roles', 'Import roles from a file.']);
    assert.equal(TITLE_EXPORT_ROLES, 'Export Roles');
    assert.equal(EXPORT_PROMPT, 'Pick the roles to export. The admin role is never exported.');
    assert.equal(EXPORT_CHANNELS_NOTE, 'Channel restrictions are included. ');
    assert.equal(EXPORT_CHANNELS_BOLD, 'When importing, you can choose not to apply them.');
    assert.deepEqual(EXPORT_COLUMNS, ['Export', 'Role', 'Description', 'Permissions', 'Channels']);
    assert.deepEqual(EXPORT_PERMISSION_COLUMNS, ['Permission']);
    assert.deepEqual(EXPORT_CHANNEL_COLUMNS, ['Channel', 'Id on this engine']);
    assert.equal(EXPORT_EVERY_CHANNEL, 'This role sees every channel.');
    assert.equal(EXPORT_NO_CHANNEL, 'This role sees no channels.');
    assert.equal(MSG_NO_CHANNELS_TICKED, 'This role sees no channels until some are ticked.');
    assert.deepEqual(PERMISSION_COLUMNS, ['Permission', 'Currently', 'After import', 'Note']);
    assert.equal(PERMISSIONS_LEGEND, 'Currently: this role has the permission on this engine.'
        + ' After import: this role will have the permission if imported.');
    assert.deepEqual(CHANNEL_COLUMNS, ['Channel', 'Id on this engine', 'Currently', 'After import', 'Match',
        'Name in import', 'Id in import']);
    assert.equal(CHANNELS_LEGEND, 'Currently: this role is restricted to the channel on this engine. After import:'
        + " this role will be restricted to the channel if imported. Match: how the import's channel was found on this engine.");
    assert.equal(CHANNELS_NOT_APPLIED, 'Channel restrictions from the import are not applied. Roles that already exist'
        + ' on this engine keep their current channels. New roles are restricted to no channels until an administrator'
        + ' sets channels for them.');
    assert.deepEqual(CHANNEL_ID_COLUMNS, [1, 6]);
    assert.equal(permissionsHeading('Lab'), 'Permissions of Lab');
    assert.equal(channelsHeading('Lab'), 'Channels of Lab');
    assert.equal(MSG_NO_ROLES_TO_EXPORT, 'There are no roles to export. The admin role is never exported.');
    assert.equal(EXPORT_FILE_NAME, 'rbac-roles.xml');
    assert.equal(exportedText(3), 'Exported 3 role(s).');
    assert.equal(TITLE_IMPORT_ROLES, 'Import Roles');
    assert.equal(IMPORT_APPLY_CHANNELS, 'Apply channel restrictions from the import');
    assert.equal(IMPORT_MATCH_BY_NAME, "Also match channels by name when the id isn't found");
    assert.deepEqual(IMPORT_COLUMNS, ['Import', 'Role', 'Action', 'Description currently', 'Description after import',
        'Permissions', 'Channels', 'Notes']);
    assert.equal(importRefusedText('bad'), "This file can't be imported: bad");
    assert.equal(importSourceText('1.2.0', '4.7.0'), 'From rbac 1.2.0 on OIE 4.7.0.');
    assert.equal(importedText(2), 'Imported 2 role(s).');
});

test('no string has an em dash', () => {
    const role = { restricted: true, channelIds: new Set(['a']), permissions: new Set(['p']) };
    const all = [TASK_EXPORT_ROLES_TOOLTIP, TASK_IMPORT_ROLES_TOOLTIP, EXPORT_PROMPT,
        EXPORT_CHANNELS_NOTE, EXPORT_CHANNELS_BOLD, MSG_NO_ROLES_TO_EXPORT, IMPORT_APPLY_CHANNELS, IMPORT_MATCH_BY_NAME,
        nameMatchHint(2, true, false), notesText(row({ action: 'UNCHANGED' })),
        everyChannelText(row({ existsHere: true })), EXPORT_EVERY_CHANNEL, EXPORT_NO_CHANNEL, MSG_NO_CHANNELS_TICKED,
        everyChannelText(row({ existsHere: true, restrictedNow: true, restrictedAfter: true })),
        CHANNELS_NOT_APPLIED,
        ...exportChannelRows(role, null).flat(), ...exportChannelRows(role, new Map()).flat(),
        ...permissionRows(row({ droppedPermissions: ['x'] })).flat(),
        ...channelRows(row({ channelsNow: [nowChan({ name: null })], channelsAfter: [chan({ match: 'NOT_FOUND' })] })).flat(),
        countText(row({ existsHere: true }), 1, 2)];
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
    assert.deepEqual(['CREATE', 'OVERWRITE'].map((a) => defaultTick(row({ action: a, noChannelFound: true }))), [true, false],
        'no channel found: the role is imported restricted to no channel, so it is ticked like any new role');
    const rows = [row({ index: 0, action: 'CREATE' }), row({ index: 1, action: 'OVERWRITE' }),
        row({ index: 2, action: 'UNCHANGED' }), row({ index: 3, action: 'SKIP' }),
        row({ index: 4, action: 'CREATE', noChannelFound: true })];
    assert.deepEqual([...mergeTicks([], new Set(), rows)], [0, 4]);
});

test('a new preview keeps the choice for a row shown before with the same action, defaults the rest', () => {
    const before = [row({ index: 0, action: 'CREATE' }), row({ index: 1, action: 'OVERWRITE' }),
        row({ index: 2, action: 'SKIP' }), row({ index: 3, name: 'Z', action: 'CREATE' })];
    const ticks = new Set([1]); // the user unticked the New role 0 and 3, ticked the Overwrite role 1
    const after = [row({ index: 0, action: 'CREATE' }), row({ index: 1, action: 'OVERWRITE' }),
        row({ index: 2, action: 'CREATE' }), // was Skipped, now New: default
        row({ index: 3, name: 'Other', action: 'CREATE' })]; // a different role at that position: default
    assert.deepEqual([...mergeTicks(before, ticks, after)].sort(), [1, 2, 3]);
    const unfound = [row({ index: 0, action: 'CREATE', noChannelFound: true })];
    assert.deepEqual([...mergeTicks(unfound, new Set(), unfound)], [], 'the user unticked it: kept');
    const found = [row({ index: 0, action: 'CREATE' })];
    assert.deepEqual([...mergeTicks(unfound, new Set(), found)], [0],
        'its channels found after matching by name: the default for a new role applies again');
});

test('pick is the ticked rows that can be ticked, ascending', () => {
    const rows = [row({ index: 4, action: 'CREATE' }), row({ index: 1, action: 'OVERWRITE' }),
        row({ index: 2, action: 'UNCHANGED' })];
    assert.deepEqual(pickedIndexes(rows, new Set([4, 1, 2])), [1, 4]);
    assert.deepEqual(pickedIndexes(rows, new Set()), []);
});

test('Notes: the row\'s reason, empty when there is none', () => {
    assert.equal(notesText(row()), '');
    assert.equal(notesText(row({ reason: 'Why.' })), 'Why.');
    assert.equal(notesText(row({ channels: 'KEPT' })), '', 'nothing is composed on the client');
    assert.equal(notesText(row({ action: 'UNCHANGED' })), '');
    assert.equal(notesText(row({ action: 'UNCHANGED', reason: 'Identical to the role on this engine.' })),
        'Identical to the role on this engine.');
});

test('the name-match hint shows while channel restrictions apply, there are matches and matching by name is off', () => {
    assert.equal(nameMatchHint(2, true, false),
        '2 channels in the import match a channel on this engine by name only. Tick the box above to use them.');
    assert.equal(nameMatchHint(1, true, false),
        '1 channel in the import matches a channel on this engine by name only. Tick the box above to use them.');
    assert.equal(nameMatchHint(2, false, false), null, 'restrictions not applied');
    assert.equal(nameMatchHint(0, true, false), null, 'no matches');
    assert.equal(nameMatchHint(2, true, true), null, 'matching by name is on');
});

test('counts: the arrow, "every", and the Skipped, Unchanged and new-role cases', () => {
    const ARROW = String.fromCharCode(0x2192);
    const here = (over) => row({ existsHere: true, action: 'OVERWRITE', ...over });
    const R = { restrictedNow: true, restrictedAfter: true };
    assert.equal(countText(here(), 6, 7), '6 ' + ARROW + ' 7');
    assert.equal(countText(here(), 6, 6), '6');
    assert.equal(countText(here(), 'every', 2), 'every ' + ARROW + ' 2');
    assert.equal(countText(here(), 12, 'every'), '12 ' + ARROW + ' every');
    assert.equal(countText(here({ action: 'UNCHANGED' }), 3, 5), '3');
    assert.equal(countText(here({ action: 'SKIP' }), 3, 5), '3', 'a Skipped row for a role here: the now count');
    assert.equal(countText(row(), 0, 4), '4', 'a role not here: the after count');
    assert.equal(permissionsCountText(here({ permissionsNow: ['a', 'b'], permissionsAfter: ['a', 'b', 'c'] })), '2 ' + ARROW + ' 3');
    assert.equal(permissionsCountText(row({ permissionsAfter: ['a', 'b'] })), '2');
    const used = (n) => Array.from({ length: n }, (_, i) => chan({ id: 'c' + i }));
    const gone = (n) => Array.from({ length: n }, (_, i) => nowChan({ id: 'n' + i }));
    assert.equal(channelsCountText(here({ ...R, channelsNow: gone(40), channelsAfter: used(30) })), '40 ' + ARROW + ' 30');
    assert.equal(channelsCountText(here()), 'every', 'every now and every after');
    assert.equal(channelsCountText(here({ restrictedNow: true, channelsNow: gone(12) })), '12 ' + ARROW + ' every');
    assert.equal(channelsCountText(here({ restrictedAfter: true, channelsAfter: used(2) })), 'every ' + ARROW + ' 2');
    assert.equal(channelsCountText(row({ restrictedAfter: true, channelsAfter: used(3) })), '3');
    assert.equal(channelsCountText(row()), 'every', 'a new role that is not restricted sees every channel');
    assert.equal(channelsCountText(row({ restrictedAfter: true })), 'none', 'a new role restricted to no channel');
    assert.equal(channelsCountText(row({ restrictedAfter: true, channelsAfter: [chan({ match: 'NOT_FOUND', used: false })] })), 'none',
        'restricted, no used entry: none, not every');
    assert.equal(channelsCountText(here({ ...R })), 'none', 'none now and none after');
    assert.equal(channelsCountText(here({ restrictedNow: true })), 'none ' + ARROW + ' every');
    assert.equal(channelsCountText(here({ restrictedAfter: true })), 'every ' + ARROW + ' none');
    assert.equal(channelsCountText(here({ restrictedNow: true, channelsNow: gone(2), restrictedAfter: true })), '2 ' + ARROW + ' none');
    assert.equal(channelsCountText(here({ restrictedNow: true, restrictedAfter: true, channelsAfter: used(2) })), 'none ' + ARROW + ' 2');
    assert.equal(channelsCountText(row({ action: 'SKIP', channelsAfter: [chan({ match: 'NOT_FOUND', used: false })] })), '0',
        'a Skipped row for a role not here, nothing used');
    assert.equal(channelsCountText(here({ action: 'SKIP', restrictedNow: true, channelsNow: gone(2) })), '2');
    assert.equal(channelsCountText(here({ action: 'SKIP' })), 'every');
    assert.equal(channelsCountText(here({ action: 'SKIP', restrictedNow: true })), 'none');
    assert.equal(channelsCountText(here({ ...R, channels: 'KEPT', channelsNow: gone(2), channelsAfter: gone(2) })), '2');
});

test('the every-channel and no-channel lines: now, after, both, neither', () => {
    const NOW = 'This role sees every channel currently.';
    const AFTER = 'This role sees every channel after the import.';
    const NOW_NONE = 'This role sees no channels currently.';
    const AFTER_NONE = 'This role sees no channels after the import.';
    assert.equal(everyChannelText(row({ existsHere: true })), NOW + ' ' + AFTER);
    assert.equal(everyChannelText(row({ existsHere: true, restrictedAfter: true, channelsAfter: [chan()] })), NOW);
    assert.equal(everyChannelText(row({ existsHere: true, restrictedNow: true, channelsNow: [nowChan()] })), AFTER);
    assert.equal(everyChannelText(row()), AFTER, 'a new role: only after');
    assert.equal(everyChannelText(row({ existsHere: true, restrictedNow: true, channelsNow: [nowChan()],
        restrictedAfter: true, channelsAfter: [chan()] })), '');
    assert.equal(everyChannelText(row({ restrictedAfter: true })), AFTER_NONE, 'a new role restricted to no channel');
    assert.equal(everyChannelText(row({ existsHere: true, restrictedNow: true, restrictedAfter: true })), NOW_NONE + ' ' + AFTER_NONE);
    assert.equal(everyChannelText(row({ existsHere: true, restrictedNow: true })), NOW_NONE + ' ' + AFTER);
    assert.equal(everyChannelText(row({ existsHere: true, restrictedAfter: true })), NOW + ' ' + AFTER_NONE);
    assert.equal(everyChannelText(row({ action: 'SKIP', channelsAfter: [chan({ match: 'NOT_FOUND', used: false })] })), '',
        'a Skipped row looked nothing up');
});

test('Match: by id, renamed on this engine, by name used and not used, not on this engine, nothing for a kept copy', () => {
    assert.equal(foundText(chan()), 'by id');
    assert.equal(foundText(chan({ name: 'New name', fileName: 'Old name' })), 'by id, renamed on this engine');
    assert.equal(foundText(chan({ match: 'BY_NAME', used: true })), 'by name');
    assert.equal(foundText(chan({ match: 'BY_NAME', used: false })), 'by name, not used');
    assert.equal(foundText(chan({ match: 'NOT_FOUND', used: false })), 'not on this engine');
    assert.equal(foundText(chan({ match: 'NOT_FOUND', used: false, name: null, fileName: null })), 'not on this engine',
        'a nameless channel in the import is still not on this engine');
    assert.equal(foundText(nowChan()), '', 'a now entry or a kept copy has no id in the import');
});

test('Match: a channel found by id with no name in the import reads "by id", null or empty', () => {
    // The exporter writes name="" for a channel its engine lacks; the engine's JSON sends that as null.
    assert.equal(foundText(chan({ name: 'One', fileName: null })), 'by id');
    assert.equal(foundText(chan({ name: 'One', fileName: '' })), 'by id');
    assert.deepEqual(channelRows(row({ channelsAfter: [chan({ name: 'One', fileName: null })] })),
        [['One', 'id-1', '', 'yes', 'by id', '', 'id-1']]);
});

test('permission rows: the union by name, the left-out ones noted', () => {
    assert.deepEqual(permissionRows(row({
        existsHere: true, permissionsNow: ['viewAlerts', 'viewChannels'],
        permissionsAfter: ['viewChannels', 'viewDashboard'], droppedPermissions: ['oldPermission']
    })), [
        ['oldPermission', '', '', 'not offered by this engine, left out'],
        ['viewAlerts', 'yes', '', ''],
        ['viewChannels', 'yes', 'yes', ''],
        ['viewDashboard', '', 'yes', '']
    ]);
    assert.deepEqual(permissionRows(row()), []);
});

test('channel rows: the import in its order, the joined channel once, a renamed one, by name, not on this engine, then the rest', () => {
    const rows = channelRows(row({
        existsHere: true,
        channelsNow: [nowChan({ id: 'id-1', name: 'One renamed' }), nowChan({ id: 'id-9', name: 'Nine' })],
        channelsAfter: [
            chan({ id: 'id-1', name: 'One renamed', fileName: 'One' }),
            chan({ id: 'id-2', name: 'Two', fileId: 'file-2', fileName: 'Two', match: 'BY_NAME', used: false }),
            chan({ id: 'id-3', name: 'Three', fileId: 'id-3', fileName: 'Three', match: 'NOT_FOUND', used: false }),
            chan({ id: 'id-4', name: null, fileId: 'id-4', fileName: null, match: 'NOT_FOUND', used: false }),
            chan({ id: 'id-5', name: null, fileId: 'id-5', fileName: 'Five', match: 'NOT_FOUND', used: false })
        ]
    }));
    assert.deepEqual(rows, [
        ['One renamed', 'id-1', 'yes', 'yes', 'by id, renamed on this engine', 'One', 'id-1'],
        ['Two', 'id-2', '', '', 'by name, not used', 'Two', 'file-2'],
        ['Three', '', '', '', 'not on this engine', 'Three', 'id-3'],
        ['id-4', '', '', '', 'not on this engine', '', 'id-4'],
        ['Five', '', '', '', 'not on this engine', 'Five', 'id-5'],
        ['Nine', 'id-9', 'yes', '', 'not in the import', '', '']
    ]);
    const byName = channelRows(row({ channelsAfter: [chan({ id: 'id-2', name: 'Two', fileId: 'file-2', fileName: 'Two', match: 'BY_NAME', used: true })] }));
    assert.deepEqual(byName, [['Two', 'id-2', '', 'yes', 'by name', 'Two', 'file-2']], 'by name, used');
});

test('channel rows: a channel the role has whose id no longer exists here, named in the import and not found, is one row', () => {
    const rows = channelRows(row({
        existsHere: true, restrictedNow: true, restrictedAfter: true,
        channelsNow: [nowChan({ id: 'id-1', name: 'One' }), nowChan({ id: 'gone', name: null, match: 'NOT_FOUND' })],
        channelsAfter: [chan({ id: 'id-1', name: 'One' }),
            chan({ id: 'gone', name: 'Gone', fileId: 'gone', fileName: 'Gone', match: 'NOT_FOUND', used: false })]
    }));
    assert.deepEqual(rows, [
        ['One', 'id-1', 'yes', 'yes', 'by id', 'One', 'id-1'],
        ['(no longer exists)', 'gone', 'yes', '', 'deleted on this engine', 'Gone', 'gone']
    ]);
    const nameless = channelRows(row({
        existsHere: true, restrictedNow: true, restrictedAfter: true,
        channelsNow: [nowChan({ id: 'gone', name: null, match: 'NOT_FOUND' })],
        channelsAfter: [chan({ id: 'gone', name: null, fileId: 'gone', fileName: null, match: 'NOT_FOUND', used: false })]
    }));
    assert.deepEqual(nameless, [['(no longer exists)', 'gone', 'yes', '', 'deleted on this engine', '', 'gone']],
        'no name in the import either');
    const notNamed = channelRows(row({
        existsHere: true, restrictedNow: true,
        channelsNow: [nowChan({ id: 'gone', name: null, match: 'NOT_FOUND' })], channelsAfter: []
    }));
    assert.deepEqual(notNamed, [['gone', 'gone', 'yes', '', 'not in the import', '', '']],
        'a deleted channel the import does not name stays a "not in the import" row');
});

test('channel rows: the Channel column is the name here, else the name in the import, else the id', () => {
    const name = (over) => channelRows(row({ channelsAfter: [chan(over)] }))[0][0];
    assert.equal(name({ name: 'Here', fileName: 'There' }), 'Here');
    assert.equal(name({ name: null, fileName: 'There', match: 'NOT_FOUND', used: false }), 'There');
    assert.equal(name({ id: 'the-id', name: null, fileName: null, match: 'NOT_FOUND', used: false }), 'the-id');
});

test('channel rows: a role with no channel found lists the import channels, none used', () => {
    const r = row({ action: 'CREATE', noChannelFound: true, restrictedAfter: true, channelsAfter: [
        chan({ id: 'x1', name: 'X', fileId: 'x1', fileName: 'X', match: 'NOT_FOUND', used: false })] });
    assert.deepEqual(channelRows(r), [['X', '', '', '', 'not on this engine', 'X', 'x1']]);
    assert.equal(everyChannelText(r), 'This role sees no channels after the import.');
});

test('channel rows: a kept channel list is one row each, now and after, with nothing from a file', () => {
    const kept = [nowChan({ id: 'id-1', name: 'One' }), nowChan({ id: 'id-2', name: 'Two' })];
    assert.deepEqual(channelRows(row({ existsHere: true, channels: 'KEPT', channelsNow: kept, channelsAfter: kept })), [
        ['One', 'id-1', 'yes', 'yes', '', '', ''],
        ['Two', 'id-2', 'yes', 'yes', '', '', '']
    ]);
    assert.deepEqual(channelRows(row({ action: 'SKIP' })), [], 'nothing looked up: no rows');
});

test('compareCounts: by first number, every and none after any number, ties by the text', () => {
    const sorted = (counts) => [...counts].sort(compareCounts);
    assert.deepEqual(sorted([10, 9, 2, 'every', 'none', '12 \u2192 14']), [2, 9, 10, '12 \u2192 14', 'every', 'none']);
    assert.deepEqual(sorted(['none', 'every']), ['every', 'none']);
    assert.deepEqual(sorted(['3 \u2192 5', '3 \u2192 4', 3]), [3, '3 \u2192 4', '3 \u2192 5']);
    assert.equal(compareCounts(10, 10), 0);
});

test('sortRows with a comparator: count texts sort by number, descending reverses it, ties keep their order', () => {
    const rows = [['a', '10'], ['b', '2'], ['c', 'every'], ['d', '2'], ['e', 'none']];
    assert.deepEqual(sortRows(rows, 1, 'asc', compareCounts).map((r) => r[0]), ['b', 'd', 'a', 'c', 'e']);
    assert.deepEqual(sortRows(rows, 1, 'desc', compareCounts).map((r) => r[0]), ['e', 'c', 'a', 'b', 'd']);
    assert.deepEqual(sortRows(rows, 1, 'asc').map((r) => r[0]), ['a', 'b', 'd', 'c', 'e'], 'as text, "10" is first');
});

test('sortRows: text sorts with localeCompare and no locale (as Swing\'s Collator), other values with < and >', () => {
    const rows = [['Night'], ['lab'], ['Day'], ['c-unknown'], ['Demo Started']];
    assert.deepEqual(sortRows(rows, 0, 'asc').map((r) => r[0]), ['c-unknown', 'Day', 'Demo Started', 'lab', 'Night'],
        'not by code unit, which puts every capital first');
    assert.deepEqual(sortRows([[1], [0], [1]], 0, 'desc').map((r) => r[0]), [1, 1, 0], 'a tick column');
    const expected = rows.map((r) => r[0]).sort((a, b) => a.localeCompare(b));
    assert.deepEqual(sortRows(rows, 0, 'asc').map((r) => r[0]), expected);
});

test('sortByColumn: no sort keeps the rows; keys or the column index; count columns by number', () => {
    const rows = [{ name: 'b', count: '10' }, { name: 'a', count: '2' }, { name: 'C', count: 'every' }];
    assert.equal(sortByColumn(rows, null, null), rows, 'no header clicked: the same rows');
    const keys = [(r) => r.name, (r) => r.count];
    assert.deepEqual(sortByColumn(rows, keys, { col: 0, dir: 'asc' }).map((r) => r.name), ['a', 'b', 'C']);
    assert.deepEqual(sortByColumn(rows, keys, { col: 1, dir: 'asc' }, [1]).map((r) => r.count), ['2', '10', 'every']);
    assert.deepEqual(sortByColumn(rows, keys, { col: 1, dir: 'asc' }).map((r) => r.count), ['10', '2', 'every'],
        'a column not in countColumns sorts as text');
    const cells = [['x', 'B'], ['y', 'a']];
    assert.deepEqual(sortByColumn(cells, null, { col: 1, dir: 'desc' }), [['x', 'B'], ['y', 'a']], 'keys null: by index');
    assert.deepEqual(EXPORT_COUNT_COLUMNS, [3, 4]);
    assert.deepEqual(IMPORT_COUNT_COLUMNS, [5, 6]);
});

test('compareIgnoreCase is Java\'s String.CASE_INSENSITIVE_ORDER', () => {
    // Each expectation measured with Java 17's String.CASE_INSENSITIVE_ORDER.compare (jshell, 2026-11-07).
    const sign = (a, b) => Math.sign(compareIgnoreCase(a, b));
    assert.equal(sign('Lab_A', 'LabB'), -1, 'an underscore sorts before a letter of either case');
    assert.equal(sign('Lab^', 'LabZ'), -1);
    assert.equal(sign('x`', 'xZ'), -1);
    assert.equal(sign('Lab[1]', 'Labz'), -1);
    assert.equal(sign('a', 'B'), -1);
    assert.equal(sign('Night', 'lab'), 1);
    assert.equal(sign('Ab', 'aB'), 0);
    assert.equal(sign('Stra\u00dfe', 'Strasse'), 1, 'Java does not upper-case the sharp s to SS');
    assert.equal(sign('\u0130stanbul', 'istanbul'), 0, 'Java lower-cases the dotted capital I to i');
    assert.equal(sign('Caf\u00e9 Qu\u00e9bec', 'Cafe Quebec'), 1);
    assert.equal(sign('Lab', 'Lab A'), -1, 'a prefix first');
    assert.deepEqual(exportChannelRows({ restricted: true, channelIds: new Set(['i1', 'i2']) },
        new Map([['i1', 'LabB'], ['i2', 'Lab_A']])), [['Lab_A', 'i2'], ['LabB', 'i1']], 'the export channel table');
});

test('sortRows: ascending, descending, by index, name or function; stable; a copy', () => {
    const rows = [['b', '2'], ['a', '2'], ['c', '1']];
    assert.deepEqual(sortRows(rows, 0, 'asc').map((r) => r[0]), ['a', 'b', 'c']);
    assert.deepEqual(sortRows(rows, 0, 'desc').map((r) => r[0]), ['c', 'b', 'a']);
    assert.deepEqual(sortRows(rows, 1, 'asc').map((r) => r[0]), ['c', 'b', 'a'], 'equal keys keep their order');
    assert.deepEqual(sortRows(rows, 1, 'desc').map((r) => r[0]), ['b', 'a', 'c']);
    assert.deepEqual(sortRows([{ n: 2 }, { n: 1 }], 'n', 'asc'), [{ n: 1 }, { n: 2 }]);
    assert.deepEqual(sortRows([{ n: 2 }, { n: 1 }], (r) => -r.n, 'asc'), [{ n: 2 }, { n: 1 }]);
    assert.deepEqual(rows.map((r) => r[0]), ['b', 'a', 'c'], 'the input is untouched');
});

test('Export rows: permissions sorted; channels by shown text, case-insensitive, ids mixed in; list not loaded; counts', () => {
    assert.deepEqual(exportPermissionRows({ permissions: new Set(['viewDashboard', 'viewAlerts']) }),
        [['viewAlerts'], ['viewDashboard']]);
    const map = new Map([['id-b', 'Beta'], ['id-a', 'Alpha']]);
    assert.deepEqual(exportChannelRows({ restricted: true, channelIds: new Set() }, map), []);
    assert.deepEqual(exportChannelRows({ restricted: true, channelIds: new Set(['id-b', 'zzz', 'id-a']) }, map),
        [['Alpha', 'id-a'], ['Beta', 'id-b'], ['zzz', 'zzz']], 'a map with a missing id');
    const mixed = new Map([['i1', 'beta'], ['i2', 'Alpha'], ['i3', 'Gamma']]);
    assert.deepEqual(exportChannelRows({ channelIds: new Set(['i1', 'i2', 'i3', 'c-id', 'zz-id']) }, mixed),
        [['Alpha', 'i2'], ['beta', 'i1'], ['c-id', 'c-id'], ['Gamma', 'i3'], ['zz-id', 'zz-id']],
        'a missing id sorts among the names by its own text, ignoring case');
    assert.deepEqual(exportChannelRows({ channelIds: new Set(['id-b', 'id-a']) }, null),
        [['id-a', 'id-a'], ['id-b', 'id-b']], 'a null map');
    assert.equal(exportPermissionsCount({ permissions: new Set(['a', 'b']) }), 2);
    assert.equal(exportChannelsCount({ restricted: false, channelIds: new Set() }), 'every');
    assert.equal(exportChannelsCount({ restricted: true, channelIds: new Set() }), 'none');
    assert.equal(exportChannelsCount({ restricted: true, channelIds: new Set(['a']) }), 1);
});
