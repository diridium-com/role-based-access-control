// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

/*
 * P3 — a user with NO role: /my-permissions loads fine but is the EMPTY set
 * (wire shape {"linked-hash-set":""}). Every mapped surface hides, but the
 * deliberately-unmapped ones stay: the Settings nav (Swing parity — individual
 * tabs are gated instead) and the "other" pane (Logout). The app must not
 * crash: unmapped views still render.
 */

import { test, expect } from '@playwright/test';
import { mockEngineWithRbac } from './mock.js';
import { rbacFixtures, taskPermissionMap } from './fixtures.js';

test.describe('P3 no-role user (empty permission set)', () => {
    test.beforeEach(async ({ page }) => {
        await mockEngineWithRbac(page, {
            ...rbacFixtures({ myPermissions: [], taskPermissions: taskPermissionMap([]) }),
            // No assigned role → empty body (the servlet answers 204).
            'GET /extensions/rbac/users/*/role': ''
        });
    });

    test('mapped navs hide; Settings nav and Logout stay; no crash', async ({ page }) => {
        await page.goto('/dashboard');

        // doShowSettings is deliberately unmapped → the Settings nav survives.
        await expect(page.getByRole('button', { name: 'Settings', exact: true })).toBeVisible();
        // The "other" pane is never gated in Swing → Logout survives.
        await expect(page.getByRole('button', { name: 'Logout', exact: true })).toBeVisible();

        // Every mapped view nav is gone.
        for (const label of ['Dashboard', 'Channels', 'Users', 'Alerts', 'Events', 'Extensions']) {
            await expect(page.getByRole('button', { name: label, exact: true })).toHaveCount(0);
        }
    });

    test('Settings still opens; the Administrator tab renders; no RBAC tab', async ({ page }) => {
        await page.goto('/settings');
        // The Administrator tab (self-scoped preferences) is deliberately unmapped.
        await page.getByRole('button', { name: 'Administrator', exact: true }).click();
        await expect(page.getByText('System Preferences', { exact: true })).toBeVisible();
        await expect(page.getByRole('button', { name: 'Save', exact: true })).toBeVisible();

        // No "View Roles" → the plugin never registered its settings panel.
        await expect(page.getByRole('button', { name: 'Role-Based Access Control', exact: true })).toHaveCount(0);
    });
});
