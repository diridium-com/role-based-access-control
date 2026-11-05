// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

/*
 * What the role editor shows ticked (rbac-core.js editorPermissions): the whole catalog
 * for the admin role, the stored permissions for any other. The Swing client has the same
 * rule in RolePermissionDisplay. Issue #28.
 *
 * Run: npm test   (from webadmin/; node --test web/)
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { editorPermissions, MSG_ADMIN_EVERY_PERMISSION } from './rbac-core.js';

const catalog = new Set(['viewChannels', 'manageUsers', 'Cache Manager#View Caches']);

test('the admin role shows the whole catalog, whatever is stored', () => {
    const admin = { isAdmin: true, permissions: new Set(['viewChannels']) };
    assert.deepEqual(editorPermissions(admin, catalog), catalog);
    assert.deepEqual(editorPermissions({ isAdmin: true, permissions: new Set() }, catalog), catalog);
});

test('any other role shows its stored permissions that the catalog has', () => {
    const role = { isAdmin: false, permissions: new Set(['viewChannels', 'gone#Old']) };
    assert.deepEqual(editorPermissions(role, catalog), new Set(['viewChannels']));
});

test('a new role shows nothing ticked', () => {
    assert.deepEqual(editorPermissions(null, catalog), new Set());
});

test('the line is the agreed wording', () => {
    assert.equal(MSG_ADMIN_EVERY_PERMISSION,
        'The admin role has every permission, including those of plugins installed later.');
});
