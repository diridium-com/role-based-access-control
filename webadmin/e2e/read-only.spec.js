// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

/*
 * P2 — a "Read Only" role (the plugin's 13 view-only permissions): every
 * mutating surface hides while its view-only twin stays, and the RBAC settings
 * tab is ABSENT (no "View Roles"). P2b adds "View Roles" (still no "Manage
 * Roles"): the tab appears but its mutating buttons stay hidden.
 *
 * Negative assertions are anchored by a positive one on the same surface (the
 * views render only after loadPlugins() resolves, so once an allowed control
 * is visible the RBAC controller is already installed).
 */

import { test, expect } from '@playwright/test';
import { mockEngineWithRbac } from './mock.js';
import {
    rbacFixtures, taskPermissionMap, permissionSet,
    READ_ONLY_PERMISSIONS, ADMIN_ROLE, READ_ONLY_ROLE,
    SAMPLE_STATUSES, SAMPLE_CHANNELS
} from './fixtures.js';

// Extension task-permissions kept empty here: the live capture's bare
// doSave/doRefresh entries would (correctly, but distractingly) also gate the
// ungrouped settings tasks — P5 covers the merge on its own.
const readOnly = (extra = []) => rbacFixtures({
    myPermissions: [...READ_ONLY_PERMISSIONS, ...extra],
    taskPermissions: taskPermissionMap([]),
    userRole: READ_ONLY_ROLE
});

test.describe('P2 read-only role', () => {
    test.beforeEach(async ({ page }) => {
        await mockEngineWithRbac(page, readOnly());
    });

    test('Users and Extensions navs are hidden; view navs stay', async ({ page }) => {
        await page.goto('/dashboard');
        for (const label of ['Dashboard', 'Channels', 'Settings', 'Alerts', 'Events']) {
            await expect(page.getByRole('button', { name: label, exact: true })).toBeVisible();
        }
        await expect(page.getByRole('button', { name: 'Users', exact: true })).toHaveCount(0);
        await expect(page.getByRole('button', { name: 'Extensions', exact: true })).toHaveCount(0);
    });

    test('channel task pane and context menu lose Delete/Deploy but keep Refresh/Export', async ({ page }) => {
        await page.goto('/channels');
        await page.getByText('Demo Started', { exact: true }).click();

        await expect(page.getByRole('button', { name: 'Refresh', exact: true })).toBeVisible();
        await expect(page.getByRole('button', { name: 'Export Channel', exact: true })).toBeVisible();
        await expect(page.getByRole('button', { name: 'Deploy Channel', exact: true })).toHaveCount(0);
        await expect(page.getByRole('button', { name: 'Delete Channel', exact: true })).toHaveCount(0);
        // Other mutations gated on manageChannels are gone too.
        await expect(page.getByRole('button', { name: 'New Channel', exact: true })).toHaveCount(0);
        await expect(page.getByRole('button', { name: 'Edit Channel', exact: true })).toHaveCount(0);

        await page.getByText('Demo Started', { exact: true }).click({ button: 'right' });
        const menu = page.locator('.ctx-menu');
        await expect(menu.getByRole('button', { name: 'Export Channel', exact: true })).toBeVisible();
        await expect(menu.getByRole('button', { name: 'Refresh', exact: true })).toBeVisible();
        await expect(menu.getByRole('button', { name: 'Deploy Channel', exact: true })).toHaveCount(0);
        await expect(menu.getByRole('button', { name: 'Delete Channel', exact: true })).toHaveCount(0);
    });

    test('Settings Server tab keeps Refresh but loses Save; Config Map loses Add Row', async ({ page }) => {
        await page.goto('/settings');
        // Server tab (viewServerSettings held, editServerSettings not).
        await expect(page.getByRole('button', { name: 'Refresh', exact: true })).toBeVisible();
        await expect(page.getByRole('button', { name: 'Save', exact: true })).toHaveCount(0);
        await expect(page.getByRole('button', { name: 'Backup Config', exact: true })).toHaveCount(0);
        await expect(page.getByRole('button', { name: 'Restore Config', exact: true })).toHaveCount(0);

        // Configuration Map tab: Add Row rides doSave → editConfigurationMap.
        await page.getByRole('button', { name: 'Configuration Map', exact: true }).click();
        await expect(page.getByRole('button', { name: 'Export Map', exact: true })).toBeVisible();
        await expect(page.getByRole('button', { name: 'Add Row', exact: true })).toHaveCount(0);
        await expect(page.getByRole('button', { name: 'Save', exact: true })).toHaveCount(0);
        await expect(page.getByRole('button', { name: 'Import Map', exact: true })).toHaveCount(0);
    });

    test('dashboard Start/Stop/Send Message/Remove All Messages are hidden', async ({ page }) => {
        await page.goto('/dashboard');

        // A STOPPED channel would offer Start; read-only hides it (and the rest).
        await page.getByText('Demo Stopped', { exact: true }).click();
        await expect(page.getByRole('button', { name: 'View Messages', exact: true })).toBeVisible();
        await expect(page.getByRole('button', { name: 'Start', exact: true })).toHaveCount(0);
        await expect(page.getByRole('button', { name: 'Send Message', exact: true })).toHaveCount(0);
        await expect(page.getByRole('button', { name: 'Remove All Messages', exact: true })).toHaveCount(0);

        // A STARTED channel would offer Stop.
        await page.getByText('Demo Started', { exact: true }).click();
        await expect(page.getByRole('button', { name: 'View Messages', exact: true })).toBeVisible();
        await expect(page.getByRole('button', { name: 'Stop', exact: true })).toHaveCount(0);
    });

    test('message browser Remove buttons are hidden', async ({ page }) => {
        await page.goto('/messages/c-started');
        await expect(page.getByRole('button', { name: 'Refresh', exact: true })).toBeVisible();
        await expect(page.getByRole('button', { name: 'Remove All Messages', exact: true })).toHaveCount(0);
        await expect(page.getByRole('button', { name: 'Remove Results', exact: true })).toHaveCount(0);

        // Selecting a message still yields no Remove/Reprocess Message.
        await page.getByText('12345', { exact: true }).click();
        await expect(page.getByRole('button', { name: 'Remove Message', exact: true })).toHaveCount(0);
        await expect(page.getByRole('button', { name: 'Reprocess Message', exact: true })).toHaveCount(0);
    });

    test('the Role-Based Access Control settings tab is absent without "View Roles"', async ({ page }) => {
        await page.goto('/settings');
        await expect(page.getByRole('button', { name: 'Server', exact: true })).toBeVisible();
        await expect(page.getByRole('button', { name: 'Role-Based Access Control', exact: true })).toHaveCount(0);
    });
});

test.describe('P2 + channel restriction — server-side redaction (fixture subset)', () => {
    // Real redaction is the engine's ChannelAuthorizer and can only be proven
    // live (plan §C); the web client has no channel filter of its own and
    // renders whatever the server returns. This pins that contract: a redacted
    // /channels + /channels/statuses subset (XStream singleton collapse — how
    // one remaining channel arrives on the wire) flows through to Dashboard
    // and Channels untouched, with no client-side cache resurrecting the rest.
    test.beforeEach(async ({ page }) => {
        await mockEngineWithRbac(page, {
            ...readOnly(),
            'GET /extensions/rbac/users/*/role': {
                'com.diridium.rbac.Role': { ...READ_ONLY_ROLE, channelIds: { string: 'c-started' } }
            },
            'GET /channels/statuses': { list: { dashboardStatus: SAMPLE_STATUSES[0] } },
            'GET /channels': { list: { channel: SAMPLE_CHANNELS[0] } },
            'GET /channels/idsAndNames': { map: { entry: { string: ['c-started', 'Demo Started'] } } }
        });
    });

    test('dashboard and channels render only the allowed channel', async ({ page }) => {
        await page.goto('/dashboard');
        await expect(page.getByText('Demo Started', { exact: true })).toBeVisible();
        await expect(page.getByText('Demo Stopped', { exact: true })).toHaveCount(0);

        await page.goto('/channels');
        await expect(page.getByText('Demo Started', { exact: true })).toBeVisible();
        await expect(page.getByText('Demo Stopped', { exact: true })).toHaveCount(0);
    });
});

test.describe('P2b read-only + View Roles (no Manage Roles)', () => {
    test.beforeEach(async ({ page }) => {
        await mockEngineWithRbac(page, readOnly(['View Roles']));
    });

    test('the RBAC tab appears, listing roles, with every mutating button hidden', async ({ page }) => {
        await page.goto('/settings');
        const rbacTab = page.getByRole('button', { name: 'Role-Based Access Control', exact: true });
        await expect(rbacTab).toBeVisible();
        await rbacTab.click();

        // Roles load ("View Roles" gates the tab; the roles table works) —
        // asserted via the unique description cells (the role NAME also appears
        // in the assignments table's Assigned Role column).
        await expect(page.getByRole('cell', { name: 'Full access to all operations and channels', exact: true })).toBeVisible();
        await expect(page.getByRole('cell', { name: 'View-only access', exact: true })).toBeVisible();
        await expect(page.getByRole('button', { name: 'Refresh', exact: true })).toBeVisible();

        // No "Manage Roles" → Add/Edit/Delete and Assign/Remove are hidden.
        for (const label of ['Add', 'Edit', 'Delete', 'Assign Role', 'Remove Role']) {
            await expect(page.getByRole('button', { name: label, exact: true })).toHaveCount(0);
        }
    });
});
