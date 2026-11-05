// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

/*
 * The channels and the restricted flag a role editor save sends (rbac-core.js).
 * The Swing client has the same rule in RoleChannelSelection.
 *
 * Run: npm test   (from webadmin/; node --test web/)
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { editorChannelIds, editorRestricted } from './rbac-core.js';

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

test('editorRestricted: the admin role keeps its flag, any other role follows the mode', () => {
    assert.equal(editorRestricted({ isAdmin: true, restricted: false }, 'specific'), false);
    assert.equal(editorRestricted({ isAdmin: true, restricted: true }, 'all'), true);
    assert.equal(editorRestricted({ isAdmin: false, restricted: false }, 'specific'), true);
    assert.equal(editorRestricted({ isAdmin: false, restricted: true }, 'all'), false);
    assert.equal(editorRestricted(null, 'specific'), true);
    assert.equal(editorRestricted(null, 'all'), false);
});
