// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

/*
 * groupPermissions tests: core groups render in PERMISSION_GROUPS order;
 * plugin-published permissions (per the /permissions/extensions map) get one
 * header per publishing plugin, in plugin-name order; unattributed leftovers
 * land in a trailing "Other" group.
 *
 * Run: npm test   (from webadmin/; node --test web/)
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { groupPermissions } from './rbac-core.js';

const names = (groups) => groups.map((g) => g.name);
const group = (groups, name) => groups.find((g) => g.name === name);

test('core permissions bucket into the named Swing groups', () => {
    const groups = groupPermissions(['viewChannels', 'manageChannels', 'viewAlerts']);
    assert.deepEqual(names(groups), ['Channels', 'Alerts']);
    assert.deepEqual(group(groups, 'Channels').permissions, ['viewChannels', 'manageChannels']);
});

test('plugin permissions render under their publishing plugin header', () => {
    const groups = groupPermissions(
        ['viewChannels', 'View Thread Dump', 'View Roles', 'Manage Roles'],
        {
            'View Thread Dump': 'Thread Viewer',
            'View Roles': 'Role-Based Access Control',
            'Manage Roles': 'Role-Based Access Control',
        });
    // Plugin headers trail the core groups, sorted by plugin name; no "Other".
    assert.deepEqual(names(groups), ['Channels', 'Role-Based Access Control', 'Thread Viewer']);
    assert.deepEqual(group(groups, 'Role-Based Access Control').permissions,
        ['Manage Roles', 'View Roles']);
    assert.deepEqual(group(groups, 'Thread Viewer').permissions, ['View Thread Dump']);
});

test('unattributed non-core permissions still land in Other', () => {
    const groups = groupPermissions(
        ['viewChannels', 'View Thread Dump', 'mysteryPermission'],
        { 'View Thread Dump': 'Thread Viewer' });
    assert.deepEqual(names(groups), ['Channels', 'Thread Viewer', 'Other']);
    assert.deepEqual(group(groups, 'Other').permissions, ['mysteryPermission']);
});

test('no extension map (pre-1.1.2 server / fetch failed) degrades to Other', () => {
    for (const ext of [undefined, null, {}]) {
        const groups = groupPermissions(['viewChannels', 'View Thread Dump'], ext);
        assert.deepEqual(names(groups), ['Channels', 'Other']);
        assert.deepEqual(group(groups, 'Other').permissions, ['View Thread Dump']);
    }
});

test('__proto__ as a permission name cannot poison plugin lookup', () => {
    const groups = groupPermissions(['__proto__'], {});
    assert.deepEqual(names(groups), ['Other']);
});
