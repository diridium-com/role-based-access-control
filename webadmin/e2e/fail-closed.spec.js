// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

/*
 * P4 — /my-permissions fails (500): the controller installs FAIL-CLOSED
 * (permissions = null denies every checkTask), so EVERY tagged surface hides —
 * including the Settings nav and the tagged "other" items that survive in the
 * empty-set case (P3). Untagged web-only items (the account chip's Edit
 * Account / Change Password, which never reach checkTask) remain — asserted
 * explicitly to document that boundary. And nothing crashes: unmapped views
 * still render their data.
 */

import { test, expect } from '@playwright/test';
import { mockEngineWithRbac } from './mock.js';
import { rbacFixtures } from './fixtures.js';

test.describe('P4 my-permissions 500 (fail closed)', () => {
    test.beforeEach(async ({ page }) => {
        await mockEngineWithRbac(page, {
            ...rbacFixtures(),
            'GET /extensions/rbac/my-permissions': { __status: 500 },
            'GET /extensions/rbac/task-permissions': { __status: 500 }
        });
    });

    test('every tagged item hides — including Settings and Logout; the app still runs', async ({ page }) => {
        await page.goto('/dashboard');

        // No crash: the dashboard view itself renders its (mocked) channels.
        await expect(page.getByText('Demo Started', { exact: true })).toBeVisible();

        // ALL tagged navs are gone — Settings too this time (unlike P3).
        for (const label of ['Dashboard', 'Channels', 'Users', 'Settings', 'Alerts', 'Events', 'Extensions']) {
            await expect(page.getByRole('button', { name: label, exact: true })).toHaveCount(0);
        }

        // The tagged "other" pane items fail closed as well.
        await expect(page.getByRole('button', { name: 'Logout', exact: true })).toHaveCount(0);
        await expect(page.getByRole('button', { name: 'About', exact: true })).toHaveCount(0);

        // Tagged task buttons fail closed too (dashboard Refresh).
        await expect(page.getByRole('button', { name: 'Refresh', exact: true })).toHaveCount(0);
    });

    test('untagged web-only items remain visible (the documented boundary)', async ({ page }) => {
        await page.goto('/dashboard');
        await expect(page.getByText('Demo Started', { exact: true })).toBeVisible();

        // The account chip is untagged; its untagged self-service items remain.
        await page.locator('button.user-chip').click();
        const menu = page.locator('.ctx-menu');
        await expect(menu.getByRole('button', { name: 'Edit Account', exact: true })).toBeVisible();
        await expect(menu.getByRole('button', { name: 'Change Password', exact: true })).toBeVisible();
        // Its tagged items (view/doShowSettings, other/doLogout) are hidden.
        await expect(menu.getByRole('button', { name: 'Settings', exact: true })).toHaveCount(0);
        await expect(menu.getByRole('button', { name: 'Sign out', exact: true })).toHaveCount(0);
    });

    test('the RBAC settings tab is skipped on a failed permission load', async ({ page }) => {
        await page.goto('/settings');
        await expect(page.getByRole('button', { name: 'Server', exact: true })).toBeVisible();
        await expect(page.getByRole('button', { name: 'Role-Based Access Control', exact: true })).toHaveCount(0);
    });
});
