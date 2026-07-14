// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

/*
 * Golden-string tests for buildAssignmentPreview() — the web port must produce
 * the EXACT text Swing's RbacSettingsPanel.confirmAssignment() renders (label
 * padding to a common column, "All channels" vs "restricted to N channel(s):",
 * "<id> (deleted)" rows with ONE space, sorted-after-labeling channel order,
 * sorted permissions, and the explicit zero-permissions line).
 *
 * Run: npm test   (from webadmin/; node --test web/)
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { buildAssignmentPreview } from './rbac-core.js';

test('restricted role with a deleted channel and no current role (the canonical case)', () => {
    const role = {
        name: 'RO',
        channelIds: ['id1', 'id2'],
        permissions: ['viewDashboard', 'viewChannels'],
    };
    assert.equal(
        buildAssignmentPreview('bob', null, role, { id1: 'Alpha' }),
        'User:         bob\n'
        + 'Current role: (none)\n'
        + 'New role:     RO\n'
        + '\n'
        + 'Channel access: restricted to 2 channel(s):\n'
        + '  Alpha\n'
        + '  id2 (deleted)\n'
        + '\n'
        + 'Permissions (2):\n'
        + '  viewChannels\n'
        + '  viewDashboard\n');
});

test('unrestricted role with a current role', () => {
    const role = { name: 'Ops', channelIds: [], permissions: ['viewDashboard'] };
    assert.equal(
        buildAssignmentPreview('alice', 'Administrator', role, new Map()),
        'User:         alice\n'
        + 'Current role: Administrator\n'
        + 'New role:     Ops\n'
        + '\n'
        + 'Channel access: All channels\n'
        + '\n'
        + 'Permissions (1):\n'
        + '  viewDashboard\n');
});

test('zero-permissions role shows the explicit could-log-in-but-do-nothing line', () => {
    const role = { name: 'Empty', channelIds: [], permissions: [] };
    assert.equal(
        buildAssignmentPreview('carol', 'RO', role, {}),
        'User:         carol\n'
        + 'Current role: RO\n'
        + 'New role:     Empty\n'
        + '\n'
        + 'Channel access: All channels\n'
        + '\n'
        + 'Permissions (0):\n'
        + '  (none — the user could log in but perform no actions)\n');
});

test('channel rows sort AFTER labeling, so deleted ids interleave with live names', () => {
    // Live channel "zeta" labels to "  zeta"; deleted id "abc" labels to
    // "  abc (deleted)" — sorted after labeling, the deleted row comes first.
    const role = { name: 'Mix', channelIds: ['zzz', 'abc'], permissions: ['viewChannels'] };
    assert.equal(
        buildAssignmentPreview('dave', null, role, new Map([['zzz', 'zeta']])),
        'User:         dave\n'
        + 'Current role: (none)\n'
        + 'New role:     Mix\n'
        + '\n'
        + 'Channel access: restricted to 2 channel(s):\n'
        + '  abc (deleted)\n'
        + '  zeta\n'
        + '\n'
        + 'Permissions (1):\n'
        + '  viewChannels\n');
});

test('Set inputs and Map lookups produce the same text as arrays and plain objects', () => {
    const asArrays = buildAssignmentPreview('bob', null,
        { name: 'RO', channelIds: ['id1', 'id2'], permissions: ['viewDashboard', 'viewChannels'] },
        { id1: 'Alpha' });
    const asSets = buildAssignmentPreview('bob', null,
        { name: 'RO', channelIds: new Set(['id1', 'id2']), permissions: new Set(['viewDashboard', 'viewChannels']) },
        new Map([['id1', 'Alpha']]));
    assert.equal(asSets, asArrays);
});
