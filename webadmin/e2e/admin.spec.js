// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

/*
 * P1 — Administrator-role holder (full permission catalog). Everything is
 * visible: all 7 Engine navs, the channel Delete/Deploy tasks, the Settings
 * Server Save, and the Role-Based Access Control settings tab listing the
 * mocked roles with all mutating buttons. Also drives the real login form once
 * to prove the plugin loads (and the controller installs) post-login.
 */

import { test, expect } from '@playwright/test';
import { mockEngineWithRbac, login } from './mock.js';
import { rbacFixtures, SAMPLE_USER } from './fixtures.js';

const ENGINE_NAVS = ['Dashboard', 'Channels', 'Users', 'Settings', 'Alerts', 'Events', 'Extensions'];

test.describe('P1 admin (full catalog)', () => {
    test.beforeEach(async ({ page }) => {
        await mockEngineWithRbac(page, rbacFixtures());
    });

    test('all 7 Engine navs are visible', async ({ page }) => {
        await page.goto('/dashboard');
        for (const label of ENGINE_NAVS) {
            await expect(page.getByRole('button', { name: label, exact: true })).toBeVisible();
        }
    });

    test('channel selection shows Delete/Deploy in the task pane and context menu', async ({ page }) => {
        await page.goto('/channels');
        await page.getByText('Demo Started', { exact: true }).click();
        await expect(page.getByRole('button', { name: 'Deploy Channel', exact: true })).toBeVisible();
        await expect(page.getByRole('button', { name: 'Delete Channel', exact: true })).toBeVisible();

        await page.getByText('Demo Started', { exact: true }).click({ button: 'right' });
        const menu = page.locator('.ctx-menu');
        await expect(menu.getByRole('button', { name: 'Deploy Channel', exact: true })).toBeVisible();
        await expect(menu.getByRole('button', { name: 'Delete Channel', exact: true })).toBeVisible();
    });

    test('Settings Server tab keeps its Save; the RBAC tab lists the mocked roles', async ({ page }) => {
        await page.goto('/settings');
        await expect(page.getByRole('button', { name: 'Save', exact: true })).toBeVisible();

        // The plugin registered its settings panel (user holds "View Roles").
        const rbacTab = page.getByRole('button', { name: 'Role-Based Access Control', exact: true });
        await expect(rbacTab).toBeVisible();
        await rbacTab.click();

        // Roles table lists both mocked roles.
        await expect(page.getByRole('cell', { name: 'Full access to all operations and channels', exact: true })).toBeVisible();
        await expect(page.getByRole('cell', { name: 'Read Only', exact: true })).toBeVisible();

        // User-role assignments resolved via the N+1 getUserRole calls.
        await expect(page.getByRole('cell', { name: 'operator', exact: true })).toBeVisible();

        // "Manage Roles" is held → every mutating button renders.
        for (const label of ['Add', 'Edit', 'Delete', 'Assign Role', 'Remove Role']) {
            await expect(page.getByRole('button', { name: label, exact: true })).toBeVisible();
        }
        // And the panel's rail task pane has its Refresh.
        await expect(page.getByRole('button', { name: 'Refresh', exact: true })).toBeVisible();
    });

    test('the plugin loads through the real login flow', async ({ page }) => {
        let authed = false;
        await mockEngineWithRbac(page, {
            ...rbacFixtures(),
            'GET /users/current': () => (authed ? { user: SAMPLE_USER } : { __status: 401 }),
            'POST /users/_login': () => { authed = true; return { status: 'SUCCESS', message: 'ok' }; },
        });
        await page.goto('/');
        await login(page);
        // Post-login boot loaded the engine-served plugin: the RBAC controller
        // allows the admin everything and the settings panel is registered.
        await expect(page.getByRole('button', { name: 'Users', exact: true })).toBeVisible();
        await page.goto('/settings');
        await expect(page.getByRole('button', { name: 'Role-Based Access Control', exact: true })).toBeVisible();
    });
});
