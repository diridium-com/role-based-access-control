// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

/*
 * The Assigned Role text of the user-assignments table (rbac-core.js
 * lookUpRoleNames): the role's name, "(none)" for no role, "(unknown)" for a
 * failed lookup. The Swing client has the same rule in
 * UserAssignmentsPanel.lookUpRoleNames.
 *
 * Run: npm test   (from webadmin/; node --test web/)
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { lookUpRoleNames, buildAssignmentPreview, NONE_ROLE_LABEL, UNKNOWN_ROLE_LABEL } from './rbac-core.js';

test('lookUpRoleNames: a role, no role, and a failed lookup, one call per user', async () => {
    const calls = [];
    const getUserRole = async (id) => {
        calls.push(id);
        if (id === 1) return { name: 'Administrator' };
        if (id === 2) return null;
        throw new Error('Missing permission: View Roles');
    };
    const names = await lookUpRoleNames([{ id: 1 }, { id: 2 }, { id: 3 }], getUserRole);
    assert.deepEqual(names, { 1: 'Administrator', 2: '(none)', 3: '(unknown)' });
    assert.deepEqual(calls.sort(), [1, 2, 3]);
    assert.deepEqual(await lookUpRoleNames([], getUserRole), {});
});

test('the labels', () => {
    assert.equal(NONE_ROLE_LABEL, '(none)');
    assert.equal(UNKNOWN_ROLE_LABEL, '(unknown)');
});

test('the assignment preview shows "(unknown)" as the current role when the lookup failed', () => {
    const role = { name: 'Lab', restricted: false, channelIds: [], permissions: ['viewChannels'] };
    assert.ok(buildAssignmentPreview('op', UNKNOWN_ROLE_LABEL, role, null).startsWith(
        'User:         op\nCurrent role: (unknown)\nNew role:     Lab\n'));
});
