// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

/*
 * P4 — /my-permissions fails (500): the controller installs FAIL-CLOSED
 * (permissions = null denies every checkTask), so EVERY tagged surface hides —
 * including the Settings nav and the tagged "other" items that survive in the
 * empty-set case (P3). Untagged web-only items (the account chip's Edit
 * Account / Change Password, which never reach checkTask) remain — asserted
 * explicitly to document that boundary. And nothing crashes: each page shows
 * Access denied in place of its view.
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

        // No crash: the dashboard shows Access denied in place of its view.
        await expect(page.getByRole('heading', { name: 'Access denied', exact: true })).toBeVisible();

        // ALL tagged navs are gone — Settings too this time (unlike P3).
        for (const label of ['Dashboard', 'Channels', 'Users', 'Settings', 'Alerts', 'Events', 'Extensions']) {
            await expect(page.getByRole('button', { name: label, exact: true })).toHaveCount(0);
        }

        // The tagged "other" pane items fail closed as well.
        await expect(page.getByRole('button', { name: 'Logout', exact: true })).toHaveCount(0);
        await expect(page.getByRole('button', { name: 'About', exact: true })).toHaveCount(0);

        // No task buttons either: the dashboard's Refresh never mounts.
        await expect(page.getByRole('button', { name: 'Refresh', exact: true })).toHaveCount(0);
    });

    test('untagged web-only items remain visible (the documented boundary)', async ({ page }) => {
        await page.goto('/dashboard');
        await expect(page.getByRole('heading', { name: 'Access denied', exact: true })).toBeVisible();

        // The account chip is untagged; its untagged self-service items remain.
        await page.locator('button.user-chip').click();
        const menu = page.getByRole('menu');
        await expect(menu.getByRole('menuitem', { name: 'Edit Account', exact: true })).toBeVisible();
        await expect(menu.getByRole('menuitem', { name: 'Change Password', exact: true })).toBeVisible();
        // Settings fails closed. Account sign-out remains available so a user
        // can leave a failed authorization session safely.
        await expect(menu.getByRole('menuitem', { name: 'Settings', exact: true })).toHaveCount(0);
        await expect(menu.getByRole('menuitem', { name: 'Sign out', exact: true })).toBeVisible();
    });

    test('a Settings URL shows Access denied and no tabs on a failed permission load', async ({ page }) => {
        await page.goto('/settings');
        await expect(page.getByRole('heading', { name: 'Access denied', exact: true })).toBeVisible();
        await expect(page.getByRole('tab')).toHaveCount(0);
        await expect(page.getByRole('tab', { name: 'Role-Based Access Control', exact: true })).toHaveCount(0);
    });
});
