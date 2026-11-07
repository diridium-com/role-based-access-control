// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

/*
 * The User-Role Assignments table on the Roles settings panel, against the real
 * built bundle and the host with the engine mocked: each user's role ("(none)"
 * when unassigned, "(unknown)" when the lookup failed), Assign Role through the
 * role picker and the impact preview,
 * Remove Role through its confirmation, the selection warnings, and the hint
 * when the user list is denied.
 */

import { test, expect } from '@playwright/test';
import { mockEngineWithRbac } from './mock.js';
import { rbacFixtures, ADMIN_ROLE, READ_ONLY_ROLE } from './fixtures.js';

const LAB_ROLE = {
    ...READ_ONLY_ROLE, id: 3, name: 'Lab', description: 'Lab staff',
    permissions: { string: ['viewDashboard', 'viewChannels'] },
    restricted: true, channelIds: { string: 'c-started' }
};

// Records the assignment writes: [method, path].
function watchWrites(page) {
    const writes = [];
    page.on('request', (req) => {
        const path = new URL(req.url()).pathname;
        if (['POST', 'DELETE'].includes(req.method()) && path.startsWith('/api/extensions/rbac/users/')) {
            writes.push([req.method(), path.replace('/api', '')]);
        }
    });
    return writes;
}

// The admin (user 1) holds the admin role; the operator (user 2) has none.
async function openPanel(page, overrides = {}) {
    await mockEngineWithRbac(page, {
        ...rbacFixtures({ roles: [ADMIN_ROLE, READ_ONLY_ROLE, LAB_ROLE] }),
        'GET /extensions/rbac/users/*/role': (req) => (new URL(req.url()).pathname.includes('/users/2/')
            ? '' : { 'com.diridium.rbac.Role': ADMIN_ROLE }),
        'POST /extensions/rbac/users/*/role/*': '',
        'DELETE /extensions/rbac/users/*/role': '',
        ...overrides
    });
    await page.goto('/settings');
    await page.getByRole('tab', { name: 'Role-Based Access Control', exact: true }).click();
    await expect(page.getByRole('cell', { name: 'operator', exact: true })).toBeVisible();
}

const dialog = (page, name) => page.getByRole('dialog', { name, exact: true });
const userRow = (page, username) => page.locator('tr', { has: page.getByRole('cell', { name: username, exact: true }) });

test('each user shows their role, "(none)" when unassigned', async ({ page }) => {
    await openPanel(page);
    await expect(userRow(page, 'admin').locator('td').nth(2)).toHaveText('Administrator');
    await expect(userRow(page, 'operator').locator('td').nth(2)).toHaveText('(none)');
});

test('a user whose role lookup failed shows "(unknown)", and so does the assignment preview', async ({ page }) => {
    await openPanel(page, {
        'GET /extensions/rbac/users/*/role': (req) => (new URL(req.url()).pathname.includes('/users/2/')
            ? { __status: 500, body: 'An internal error occurred.' } : { 'com.diridium.rbac.Role': ADMIN_ROLE })
    });
    await expect(userRow(page, 'admin').locator('td').nth(2)).toHaveText('Administrator');
    await expect(userRow(page, 'operator').locator('td').nth(2)).toHaveText('(unknown)');
    await userRow(page, 'operator').click();
    await page.getByRole('button', { name: 'Assign Role', exact: true }).click();
    await dialog(page, 'Assign Role').getByRole('button', { name: 'OK', exact: true }).click();
    await expect(dialog(page, 'Confirm Role Assignment').locator('pre')).toContainText('Current role: (unknown)');
});

test('Assign Role: pick a role, read the preview, confirm, and the assignment is sent', async ({ page }) => {
    const writes = watchWrites(page);
    await openPanel(page);
    await userRow(page, 'operator').click();
    await page.getByRole('button', { name: 'Assign Role', exact: true }).click();
    const picker = dialog(page, 'Assign Role');
    await expect(picker.getByText('Select a role for user operator:')).toBeVisible();
    await picker.locator('select').selectOption({ label: 'Lab' });
    await picker.getByRole('button', { name: 'OK', exact: true }).click();

    const preview = dialog(page, 'Confirm Role Assignment');
    await expect(preview.getByText('Review the access this role grants before assigning:')).toBeVisible();
    // The exact text, not whitespace-normalized: the labels are padded to one column.
    expect(await preview.locator('pre').textContent()).toBe('User:         operator\n'
        + 'Current role: (none)\n'
        + 'New role:     Lab\n\n'
        + 'Channel access: restricted to 1 channel(s):\n'
        + '  Demo Started\n\n'
        + 'Permissions (2):\n'
        + '  viewChannels\n'
        + '  viewDashboard\n');
    await preview.getByRole('button', { name: 'OK', exact: true }).click();
    await expect.poll(() => writes).toEqual([['POST', '/extensions/rbac/users/2/role/3']]);
});

test('Assign Role: Cancel in the preview sends nothing', async ({ page }) => {
    const writes = watchWrites(page);
    await openPanel(page);
    await userRow(page, 'operator').click();
    await page.getByRole('button', { name: 'Assign Role', exact: true }).click();
    await dialog(page, 'Assign Role').getByRole('button', { name: 'OK', exact: true }).click();
    await dialog(page, 'Confirm Role Assignment').getByRole('button', { name: 'Cancel', exact: true }).click();
    await expect(dialog(page, 'Confirm Role Assignment')).toHaveCount(0);
    expect(writes).toEqual([]);
});

test('Remove Role: confirm, and the removal is sent', async ({ page }) => {
    const writes = watchWrites(page);
    await openPanel(page);
    await userRow(page, 'operator').click();
    await page.getByRole('button', { name: 'Remove Role', exact: true }).click();
    const confirm = dialog(page, 'Confirm Remove');
    await expect(confirm.getByText('Remove the role from user "operator"?')).toBeVisible();
    await confirm.getByRole('button', { name: 'Remove', exact: true }).click();
    await expect.poll(() => writes).toEqual([['DELETE', '/extensions/rbac/users/2/role']]);
});

test('with no user selected, Assign Role and Remove Role say so', async ({ page }) => {
    await openPanel(page);
    await page.getByRole('button', { name: 'Assign Role', exact: true }).click();
    const warning = dialog(page, 'Warning');
    await expect(warning.getByText('Please select a user to assign a role to.')).toBeVisible();
    await warning.getByRole('button', { name: 'Close' }).last().click();
    await page.getByRole('button', { name: 'Remove Role', exact: true }).click();
    await expect(dialog(page, 'Warning').getByText('Please select a user to remove their role.')).toBeVisible();
});

test('a denied user list leaves the roles table and shows the hint, without Assign or Remove', async ({ page }) => {
    await mockEngineWithRbac(page, {
        ...rbacFixtures({ roles: [ADMIN_ROLE, READ_ONLY_ROLE, LAB_ROLE] }),
        'GET /users': { __status: 403, body: 'Missing permission: manageUsers' }
    });
    await page.goto('/settings');
    await page.getByRole('tab', { name: 'Role-Based Access Control', exact: true }).click();
    await expect(page.getByRole('cell', { name: 'Lab staff', exact: true })).toBeVisible();
    await expect(page.getByText('The user list could not be loaded (viewing assignments requires the manageUsers permission):'))
        .toBeVisible();
    await expect(page.getByRole('button', { name: 'Assign Role', exact: true })).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Remove Role', exact: true })).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Add', exact: true })).toBeVisible();
});
