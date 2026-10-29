// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

/*
 * The channel list fails to load (500): the panel says so, and Add and Edit
 * refuse to open the role editor, which would otherwise list every channel a
 * role is restricted to as deleted. A Refresh that loads the list lifts it.
 */

import { test, expect } from '@playwright/test';
import { mockEngineWithRbac } from './mock.js';
import { rbacFixtures, DEFAULT_FIXTURES } from './fixtures.js';

const BLOCKED = "The channel list didn't load. Click Refresh and try again.";

// The host shows error and warning toasts as dialogs the user has to close.
async function closeDialog(page, title, text) {
    const dialog = page.getByRole('dialog', { name: title });
    await expect(dialog.getByText(text)).toBeVisible();
    await dialog.getByRole('button', { name: 'Close' }).last().click();
    await expect(dialog).toHaveCount(0);
}

test('a failed channel list blocks Add and Edit until a Refresh loads it', async ({ page }) => {
    let fail = true;
    await mockEngineWithRbac(page, {
        ...rbacFixtures(),
        'GET /channels/idsAndNames': () => (fail ? { __status: 500 } : DEFAULT_FIXTURES['GET /channels/idsAndNames'])
    });
    await page.goto('/settings');
    await page.getByRole('tab', { name: 'Role-Based Access Control', exact: true }).click();
    await closeDialog(page, 'Error', /Failed to load channels/);

    await page.getByRole('cell', { name: 'Read Only', exact: true }).click();
    await page.getByRole('button', { name: 'Edit', exact: true }).click();
    await closeDialog(page, 'Warning', BLOCKED);
    await expect(page.locator('.rbac-overlay')).toHaveCount(0);

    await page.getByRole('button', { name: 'Add', exact: true }).click();
    await closeDialog(page, 'Warning', BLOCKED);
    await expect(page.locator('.rbac-overlay')).toHaveCount(0);

    fail = false;
    await page.getByRole('button', { name: 'Refresh', exact: true }).click();
    await page.getByRole('cell', { name: 'Read Only', exact: true }).click();
    await page.getByRole('button', { name: 'Edit', exact: true }).click();
    await expect(page.locator('.rbac-overlay')).toHaveCount(1);
});
