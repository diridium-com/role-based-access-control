// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

/*
 * The channels and the restricted flag a role editor save sends, the line under
 * its channel list, and the tick toggle (rbac-core.js). The Swing client has the
 * same rules in RoleChannelSelection and RoleEditorDialog.
 *
 * Run: npm test   (from webadmin/; node --test web/)
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import {
    editorChannelIds, editorRestricted, noChannelsTickedLine, keptChannelsText, toggleIn, MSG_NO_CHANNELS_TICKED
} from './rbac-core.js';

const set = (...ids) => new Set(ids);

test('editorChannelIds: the ticked channels plus the stored ones the editor does not list', () => {
    const saved = editorChannelIds(set('a'), set('a', 'unseen'), set('a', 'b'));
    assert.deepEqual([...saved].sort(), ['a', 'unseen']);
});

test('editorChannelIds: a stored channel the editor lists and the user unticked is dropped', () => {
    const saved = editorChannelIds(set('b'), set('a', 'unseen'), set('a', 'b'));
    assert.deepEqual([...saved].sort(), ['b', 'unseen']);
});

test('editorChannelIds: a new role has no stored ids; nothing listed keeps every stored id', () => {
    assert.deepEqual([...editorChannelIds(set('a'), [], set('a', 'b'))], ['a']);
    assert.deepEqual([...editorChannelIds(set(), set('x', 'y'), set())].sort(), ['x', 'y']);
});

test('editorChannelIds: does not change its inputs', () => {
    const ticked = set('a');
    editorChannelIds(ticked, set('unseen'), set('a'));
    assert.deepEqual([...ticked], ['a']);
});

test('the channel line: no channels only while Specific is selected, nothing is ticked and nothing unseen is kept', () => {
    const live = set('a', 'b');
    assert.equal(noChannelsTickedLine('specific', 0, set('a'), live), MSG_NO_CHANNELS_TICKED, 'a listed channel unticked');
    assert.equal(noChannelsTickedLine('specific', 0, [], live), MSG_NO_CHANNELS_TICKED, 'a new role');
    assert.equal(noChannelsTickedLine('specific', 1, set('unseen'), live), null, 'a channel is ticked');
    assert.equal(noChannelsTickedLine('all', 0, set('unseen'), live), null, 'All Channels');
    assert.equal(noChannelsTickedLine('specific', 0, set('a', 'unseen'), live), 'This role keeps 1 channel this list does not show.');
    assert.equal(noChannelsTickedLine('specific', 0, set('x', 'y'), set()), 'This role keeps 2 channels this list does not show.');
    assert.equal(MSG_NO_CHANNELS_TICKED, 'This role sees no channels until some are ticked.');
    assert.equal(keptChannelsText(1), 'This role keeps 1 channel this list does not show.');
    assert.equal(keptChannelsText(3), 'This role keeps 3 channels this list does not show.');
});

test('toggleIn: adds a missing value, removes a present one, returns a copy', () => {
    const before = set('a');
    assert.deepEqual([...toggleIn(before, 'b')].sort(), ['a', 'b']);
    assert.deepEqual([...toggleIn(before, 'a')], []);
    assert.deepEqual([...toggleIn(new Set([1, 2]), 2)], [1], 'numbers, as the import rows\' index values');
    assert.deepEqual([...before], ['a'], 'the input is untouched');
});

test('editorRestricted: the admin role keeps its flag, any other role follows the mode', () => {
    assert.equal(editorRestricted({ isAdmin: true, restricted: false }, 'specific'), false);
    assert.equal(editorRestricted({ isAdmin: true, restricted: true }, 'all'), true);
    assert.equal(editorRestricted({ isAdmin: false, restricted: false }, 'specific'), true);
    assert.equal(editorRestricted({ isAdmin: false, restricted: true }, 'all'), false);
    assert.equal(editorRestricted(null, 'specific'), true);
    assert.equal(editorRestricted(null, 'all'), false);
});
