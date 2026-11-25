// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

/*
 * The Orphaned Permissions task and dialog, against the real built bundle and the host with
 * the engine mocked: who sees the task, the list with the disabled plugins named, the empty
 * state, and what Remove Selected and Remove All send.
 */

import { test, expect } from '@playwright/test';
import { mockEngineWithRbac } from './mock.js';
import { rbacFixtures, ADMIN_ROLE, READ_ONLY_ROLE } from './fixtures.js';

const INTRO = 'These permissions are orphaned, usually because a plugin changed or was removed. '
    + 'Engine permissions are never listed here.';
const DISABLED = 'Disabled plugins: Data Pruner, Server Log. Their permissions may appear in this list.';
const EMPTY = 'No role holds an orphaned permission.';
const GRANTS_FQCN = 'com.diridium.rbac.UnregisteredGrants';
const GRANT_FQCN = 'com.diridium.rbac.UnregisteredGrant';
const LIST = { [GRANTS_FQCN]: {
    grants: { [GRANT_FQCN]: [
        { roleId: 2, roleName: 'Read Only', permission: 'Old Perm' },
        { roleId: 2, roleName: 'Read Only', permission: 'Use Perm Test' },
        { roleId: 3, roleName: 'Lab', permission: 'Old Perm' }] },
    disabledPlugins: { string: ['Data Pruner', 'Server Log'] } } };
const NONE = { [GRANTS_FQCN]: { grants: '', disabledPlugins: '' } };
const ROLES_VIEWER = { ...READ_ONLY_ROLE, id: 4, name: 'Roles Viewer', permissions: { string: ['View Roles', 'Manage Roles'] } };

const task = (page, name) => page.getByRole('button', { name, exact: true });

// lists: what each GET of the list answers, in turn (the last one repeats).
async function openPanel(page, { lists = [LIST], userRole = ADMIN_ROLE } = {}) {
    const removals = [];
    let reads = 0;
    await mockEngineWithRbac(page, {
        ...rbacFixtures({ userRole }),
        'GET /extensions/rbac/roles/_unregistered': () => lists[Math.min(reads++, lists.length - 1)],
        'POST /extensions/rbac/roles/_unregistered/_remove': (req) => { removals.push(req.postData()); return { int: 1 }; }
    });
    await page.goto('/settings');
    await page.getByRole('tab', { name: 'Role-Based Access Control', exact: true }).click();
    await expect(task(page, 'Refresh')).toBeVisible();
    return removals;
}

test.describe('the Orphaned Permissions task', () => {
    test('a View Roles and Manage Roles holder who is not the admin role does not see it', async ({ page }) => {
        await openPanel(page, { userRole: ROLES_VIEWER });
        await expect(task(page, 'Orphaned Permissions')).toHaveCount(0);
    });

    test('the admin sees the list, the disabled plugins and the intro', async ({ page }) => {
        await openPanel(page);
        await task(page, 'Orphaned Permissions').click();
        const dialog = page.locator('.rbac-overlay');
        await expect(dialog.getByText(INTRO)).toBeVisible();
        await expect(dialog.getByText(DISABLED)).toBeVisible();
        await expect(dialog.locator('tbody tr')).toHaveCount(3);
        await expect(dialog.getByRole('button', { name: 'Remove Selected' })).toBeDisabled();
        await expect(dialog.getByRole('button', { name: 'Remove All' })).toBeEnabled();
    });

    test('Remove Selected asks, sends only the ticked grant, and shows the list again', async ({ page }) => {
        const removals = await openPanel(page, { lists: [LIST, NONE] });
        await task(page, 'Orphaned Permissions').click();
        const dialog = page.locator('.rbac-overlay');
        await dialog.getByRole('checkbox', { name: 'Lab: Old Perm' }).check();
        await dialog.getByRole('button', { name: 'Remove Selected' }).click();
        await expect(page.getByText('Remove 1 orphaned permission from 1 role?')).toBeVisible();
        await page.getByRole('button', { name: 'Remove', exact: true }).click();
        await expect(dialog.getByText(EMPTY)).toBeVisible();
        expect(removals).toEqual(['<' + GRANTS_FQCN + '><grants><' + GRANT_FQCN + '><roleId>3</roleId>'
            + '<permission>Old Perm</permission></' + GRANT_FQCN + '></grants></' + GRANTS_FQCN + '>']);
    });

    test('Remove All asks with the counts, and Cancel sends nothing', async ({ page }) => {
        const removals = await openPanel(page);
        await task(page, 'Orphaned Permissions').click();
        await page.locator('.rbac-overlay').getByRole('button', { name: 'Remove All' }).click();
        await expect(page.getByText('Remove 3 orphaned permissions from 2 roles?')).toBeVisible();
        await page.getByRole('button', { name: 'Cancel', exact: true }).click();
        await expect(page.locator('.rbac-overlay').locator('tbody tr')).toHaveCount(3);
        expect(removals).toEqual([]);
    });

    test('with nothing orphaned, the dialog says so and offers no removal', async ({ page }) => {
        await openPanel(page, { lists: [NONE] });
        await task(page, 'Orphaned Permissions').click();
        const dialog = page.locator('.rbac-overlay');
        await expect(dialog.getByText(EMPTY)).toBeVisible();
        await expect(dialog.getByText(DISABLED)).toHaveCount(0);
        await expect(dialog.getByRole('button', { name: 'Remove All' })).toBeDisabled();
    });
});
