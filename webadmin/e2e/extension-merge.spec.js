// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

/*
 * P5 — /task-permissions merge: a mapping declared by another extension
 * ("group/task" composite) merges into the controller and hides its surface
 * when the permission is missing — while the putIfAbsent rule keeps a
 * malicious/buggy remap from overriding a hardcoded core mapping.
 *
 * The mocked extension gates the Administrator settings tab's Save (normally
 * deliberately unmapped → always visible, see P3) behind "Save Settings",
 * which this profile lacks; it also tries to remap the core doStart task to a
 * permission nobody holds — the hardcoded doStart → startStopChannels must win.
 */

import { test, expect } from '@playwright/test';
import { mockEngineWithRbac } from './mock.js';
import { rbacFixtures, taskPermissionMap, FULL_PERMISSIONS } from './fixtures.js';

test.describe('P5 extension task-permissions merge', () => {
    test.beforeEach(async ({ page }) => {
        await mockEngineWithRbac(page, rbacFixtures({
            // Everything except the mocked extension's permission.
            myPermissions: FULL_PERMISSIONS.filter((p) => p !== 'Save Settings'),
            taskPermissions: taskPermissionMap([
                ['settings_Administrator/doSave', 'Save Settings'],
                ['doStart', 'no-such-permission']   // must NOT beat the hardcoded map
            ])
        }));
    });

    test('a merged composite mapping hides the extension-gated surface', async ({ page }) => {
        await page.goto('/settings');
        // Positive control: the Server tab's Save is unaffected (its own
        // composite mapping → editServerSettings, which is held).
        await expect(page.getByRole('button', { name: 'Save', exact: true })).toBeVisible();

        // The Administrator tab's Save is now gated behind the missing
        // "Save Settings"; its sibling tasks stay (unmapped → allowed).
        await page.getByRole('button', { name: 'Administrator', exact: true }).click();
        await expect(page.getByRole('button', { name: 'Restore Defaults', exact: true })).toBeVisible();
        await expect(page.getByRole('button', { name: 'Refresh', exact: true })).toBeVisible();
        await expect(page.getByRole('button', { name: 'Save', exact: true })).toHaveCount(0);
    });

    test('hardcoded mappings win over a conflicting extension entry (putIfAbsent)', async ({ page }) => {
        await page.goto('/dashboard');
        // startStopChannels is held; if the extension's doStart remap had won,
        // Start would be hidden ("no-such-permission" is never granted).
        await page.getByText('Demo Stopped', { exact: true }).click();
        await expect(page.getByRole('button', { name: 'Start', exact: true })).toBeVisible();
    });
});
