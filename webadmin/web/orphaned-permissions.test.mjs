// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

/*
 * The Orphaned Permissions dialog's texts (rbac-core.js) and the list and removal on the wire
 * (rbac-api.js). The Swing twin is OrphanedPermissionsDialog.
 *
 * Run: npm test   (from webadmin/; node --test web/)
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {
    orphanedConfirmation, orphanedDisabledLine, ORPHANED_INTRO, ORPHANED_EMPTY,
    TASK_ORPHANED_PERMISSIONS, TASK_ORPHANED_PERMISSIONS_TOOLTIP
} from './rbac-core.js';
import { normalizeUnregisteredGrants, unregisteredGrantsXml } from './rbac-api.js';

const grant = (roleId, roleName, permission) => ({ roleId, roleName, permission });

// The texts the Swing dialog shows too: OrphanedPermissionsTextsTest reads the same file.
test('the shared texts are the ones the web dialog shows', () => {
    const lines = fs.readFileSync(new URL('./orphaned-permissions-texts.txt', import.meta.url), 'utf8')
        .split('\n').filter((line) => line.trim() && !line.startsWith('#'));
    assert.ok(lines.length >= 8, `read only ${lines.length} texts`);
    const fixed = { title: TASK_ORPHANED_PERMISSIONS, tooltip: TASK_ORPHANED_PERMISSIONS_TOOLTIP,
        intro: ORPHANED_INTRO, empty: ORPHANED_EMPTY };
    for (const line of lines) {
        const key = line.slice(0, line.indexOf(' '));
        const rest = line.slice(key.length + 1);
        if (key in fixed) {
            assert.equal(fixed[key], rest, line);
        } else if (key === 'disabled') {
            const [plugins, text] = rest.split(' => ');
            assert.equal(orphanedDisabledLine(plugins.split(', ')), text, line);
        } else if (key === 'confirmation') {
            const [counts, text] = rest.split(' => ');
            const [permissions, roles] = counts.split(' ').map(Number);
            const grants = Array.from({ length: permissions },
                (_, i) => grant(Math.min(i, roles - 1) + 1, 'Role', `Permission ${i}`));
            assert.equal(orphanedConfirmation(grants), text, line);
        } else {
            assert.fail(`unknown key in ${line}`);
        }
    }
});

test('the confirmation counts a role id sent as text and as a number once', () => {
    assert.equal(orphanedConfirmation([grant(2, 'Billing', 'A'), grant('2', 'Billing', 'B')]),
        'Remove 2 orphaned permissions from 1 role?');
});

test('the disabled line is absent with no disabled plugin', () => {
    assert.equal(orphanedDisabledLine([]), null);
    assert.equal(orphanedDisabledLine(undefined), null);
});

test('the list reads several grants, one grant, and none', () => {
    const several = normalizeUnregisteredGrants({ 'com.diridium.rbac.UnregisteredGrants': {
        grants: { 'com.diridium.rbac.UnregisteredGrant': [
            { roleId: 2, roleName: 'Billing', permission: 'Old Perm' },
            { roleId: '3', roleName: 'Lab', permission: 'Use Perm Test' }] },
        disabledPlugins: { string: ['Data Pruner', 'Server Log'] } } });
    assert.deepEqual(several, {
        grants: [grant(2, 'Billing', 'Old Perm'), grant(3, 'Lab', 'Use Perm Test')],
        disabledPlugins: ['Data Pruner', 'Server Log'] });
    const one = normalizeUnregisteredGrants({ 'com.diridium.rbac.UnregisteredGrants': {
        grants: { 'com.diridium.rbac.UnregisteredGrant': { roleId: 2, roleName: 'Billing', permission: 'Old' } },
        disabledPlugins: { string: 'Data Pruner' } } });
    assert.deepEqual(one, { grants: [grant(2, 'Billing', 'Old')], disabledPlugins: ['Data Pruner'] });
    assert.deepEqual(normalizeUnregisteredGrants({ 'com.diridium.rbac.UnregisteredGrants': { grants: '', disabledPlugins: '' } }),
        { grants: [], disabledPlugins: [] });
});

test('the removal sends each grant\'s role id and permission, escaped', () => {
    assert.equal(unregisteredGrantsXml([grant(2, 'Billing', 'A & <B>'), grant(3, 'Lab', 'Old')]),
        '<com.diridium.rbac.UnregisteredGrants><grants>'
        + '<com.diridium.rbac.UnregisteredGrant><roleId>2</roleId><permission>A &amp; &lt;B&gt;</permission></com.diridium.rbac.UnregisteredGrant>'
        + '<com.diridium.rbac.UnregisteredGrant><roleId>3</roleId><permission>Old</permission></com.diridium.rbac.UnregisteredGrant>'
        + '</grants></com.diridium.rbac.UnregisteredGrants>');
});
