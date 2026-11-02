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
    TITLE_EXPORT_ROLES, EXPORT_PROMPT, MSG_NO_ROLES_TO_EXPORT, EXPORT_FILE_NAME, exportedText,
    TITLE_IMPORT_ROLES, IMPORT_APPLY_CHANNELS, IMPORT_MATCH_BY_NAME, IMPORT_COLUMNS,
    NAME_MATCH_HEADING, NAME_MATCH_HINT, importRefusedText, importSourceText, importedText,
    actionLabel, canTick, defaultTick, mergeTicks, pickedIndexes, detailsText, nameMatchSection
} from './rbac-core.js';

const row = (over = {}) => ({
    index: 0, name: 'R', action: 'CREATE', reason: '',
    droppedPermissions: [], unmatchedChannels: [], matchedChannelCount: 0, channels: 'FROM_FILE',
    descriptionChanged: false, addedPermissions: [], removedPermissions: [], addedChannels: [], removedChannels: [],
    ...over
});

test('the strings are the agreed wording', () => {
    assert.deepEqual([TASK_EXPORT_ROLES, TASK_EXPORT_ROLES_TOOLTIP, TASK_IMPORT_ROLES, TASK_IMPORT_ROLES_TOOLTIP], [
        'Export Roles', 'Export roles to a file.', 'Import Roles', 'Import roles from a file.']);
    assert.equal(TITLE_EXPORT_ROLES, 'Export Roles');
    assert.equal(EXPORT_PROMPT, 'Pick the roles to export. The admin role is never exported.');
    assert.equal(MSG_NO_ROLES_TO_EXPORT, 'There are no roles to export. The admin role is never exported.');
    assert.equal(EXPORT_FILE_NAME, 'rbac-roles.xml');
    assert.equal(exportedText(3), 'Exported 3 role(s).');
    assert.equal(TITLE_IMPORT_ROLES, 'Import Roles');
    assert.equal(IMPORT_APPLY_CHANNELS, 'Apply channel restrictions from the file');
    assert.equal(IMPORT_MATCH_BY_NAME, "Also match channels by name when the id isn't found");
    assert.deepEqual(IMPORT_COLUMNS, ['', 'Role', 'Action', 'Details']);
    assert.equal(NAME_MATCH_HEADING, 'Channels in the file that match a channel here only by name:');
    assert.equal(NAME_MATCH_HINT, 'Tick "Also match channels by name" to use them.');
    assert.equal(importRefusedText('bad'), "This file can't be imported: bad");
    assert.equal(importSourceText('1.2.0', '4.7.0'), 'From rbac 1.2.0 on OIE 4.7.0.');
    assert.equal(importedText(2), 'Imported 2 role(s).');
});

test('no string has an em dash', () => {
    const all = [TASK_EXPORT_ROLES_TOOLTIP, TASK_IMPORT_ROLES_TOOLTIP, EXPORT_PROMPT, MSG_NO_ROLES_TO_EXPORT,
        IMPORT_APPLY_CHANNELS, IMPORT_MATCH_BY_NAME, NAME_MATCH_HEADING, NAME_MATCH_HINT];
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

test('Details: each part only when it applies, in the agreed order, joined with "; "', () => {
    assert.equal(detailsText(row()), '');
    assert.equal(detailsText(row({
        reason: 'Why.',
        addedPermissions: ['a', 'b'], removedPermissions: ['c'],
        addedChannels: ['d'], removedChannels: ['e', 'f'],
        descriptionChanged: true, channels: 'KEPT',
        droppedPermissions: ['g'], unmatchedChannels: ['h (id)', 'i']
    })), 'Why.; Adds permissions: a, b; Removes permissions: c; Adds channels: d; Removes channels: e, f;'
        + ' Changes the description; Keeps its channels here; Left out, not on this engine: g;'
        + ' Channels not found: h (id), i');
    assert.equal(detailsText(row({ channels: 'EVERY_CHANNEL' })), '', 'only KEPT is a part');
});

test('Details: "Same as the role here" only for an Unchanged row with nothing else to say', () => {
    assert.equal(detailsText(row({ action: 'UNCHANGED' })), 'Same as the role here');
    assert.equal(detailsText(row({ action: 'UNCHANGED', droppedPermissions: ['g'] })),
        'Left out, not on this engine: g');
    assert.equal(detailsText(row({ action: 'OVERWRITE' })), '');
});

test('Details for the captured skipped row', () => {
    const reason = 'None of its 1 channels exist on this engine, and a role with no channels sees every channel.'
        + ' Matching channels by name finds 1 of them.';
    assert.equal(detailsText(row({
        action: 'SKIP', reason, unmatchedChannels: ['probe one (8163af3f-7ed2-4a0c-b326-34830263c504)']
    })), reason + '; Channels not found: probe one (8163af3f-7ed2-4a0c-b326-34830263c504)');
});

test('the name-match list shows while channel restrictions apply and there are matches; the hint while matching is off', () => {
    const matches = [{ name: 'probe one' }, { name: 'probe two' }];
    assert.equal(nameMatchSection(false, false, matches), null, 'restrictions not applied');
    assert.equal(nameMatchSection(true, false, []), null, 'no matches');
    assert.deepEqual(nameMatchSection(true, false, matches), {
        heading: 'Channels in the file that match a channel here only by name:',
        names: ['probe one', 'probe two'],
        hint: 'Tick "Also match channels by name" to use them.'
    });
    assert.equal(nameMatchSection(true, true, matches).hint, null);
});
