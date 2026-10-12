// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

// Real built RBAC bundle + real host surfaces; only engine HTTP is mocked.
import { test, expect } from '@playwright/test';
import { mockEngineWithRbac, login } from './mock.js';
import { rbacFixtures, permissionSet, taskPermissionMap } from './fixtures.js';

const properties = { enabled: 'true', pruningBlockSize: '1000', pruneEvents: 'false', archiveEnabled: 'false' };
const prunerProperties = { properties: { property: Object.entries(properties).map(([name, value]) => ({ '@name': name, $: value })) } };
const status = running => ({ map: { entry: { string: ['isRunning', String(running)] } } });

async function setup(page, permissions, overrides = {}) {
    const writes = [];
    page.on('request', request => {
        if (request.method() !== 'GET' && /\/api\/extensions\/(Data%20Pruner|datapruner)/.test(request.url())) {
            writes.push(`${request.method()} ${new URL(request.url()).pathname}`);
        }
    });
    await mockEngineWithRbac(page, {
        ...rbacFixtures({ myPermissions: permissions }),
        'GET /extensions/Data%20Pruner/properties': prunerProperties,
        'GET /extensions/datapruner/status': status(false),
        ...overrides
    });
    return writes;
}

async function openPruner(page) {
    await page.goto('/settings');
    await page.getByRole('tab', { name: 'Data Pruner', exact: true }).click();
    await expect(page.getByRole('button', { name: 'Refresh', exact: true })).toBeEnabled();
    await expect(page.getByText('Block Size', { exact: true })).toBeVisible();
}

async function openPalette(page) {
    await page.keyboard.press('Control+k');
    await expect(page.locator('.cmdk')).toBeVisible();
}

test('Data Pruner viewer sees Refresh but no Save, Prune, Stop or Events actions', async ({ page }) => {
    const writes = await setup(page, ['View Settings']);
    await openPruner(page);
    for (const name of ['Save', 'Prune Now', 'Stop Pruner', 'View Events']) {
        await expect(page.getByRole('button', { name, exact: true })).toHaveCount(0);
    }
    await page.getByRole('button', { name: 'Refresh', exact: true }).click();
    await expect(page.getByRole('button', { name: 'Refresh', exact: true })).toBeEnabled();
    expect(writes).toEqual([]);
});

test('channel-control grant does not grant Data Pruner control', async ({ page }) => {
    const writes = await setup(page, ['View Settings', 'viewDashboard', 'startStopChannels']);
    await openPruner(page);
    for (const name of ['Prune Now', 'Stop Pruner']) {
        await expect(page.getByRole('button', { name, exact: true })).toHaveCount(0);
    }
    await page.getByRole('button', { name: 'Dashboard', exact: true }).click();
    await page.getByText('Demo Stopped', { exact: true }).click();
    await expect(page.getByRole('button', { name: 'Start', exact: true })).toBeVisible();
    expect(writes).toEqual([]);
});

test('pruner-control grant starts and stops pruning without channel-control permission', async ({ page }) => {
    let running = false;
    const writes = await setup(page, ['View Settings', 'Start / Stop', 'viewDashboard'], {
        'GET /extensions/datapruner/status': () => status(running),
        'POST /extensions/datapruner/_start': () => { running = true; return ''; },
        'POST /extensions/datapruner/_stop': () => { running = false; return ''; }
    });
    await openPruner(page);
    await expect(page.getByRole('button', { name: 'Prune Now', exact: true })).toBeEnabled();
    await expect(page.getByRole('button', { name: 'Stop Pruner', exact: true })).toBeDisabled();
    await page.getByRole('button', { name: 'Prune Now', exact: true }).click();
    await page.getByRole('dialog', { name: 'Prune Now', exact: true }).getByRole('button', { name: 'Start', exact: true }).click();
    await expect(page.getByRole('button', { name: 'Stop Pruner', exact: true })).toBeEnabled();
    await expect(page.getByRole('button', { name: 'Prune Now', exact: true })).toBeDisabled();
    await page.getByRole('button', { name: 'Stop Pruner', exact: true }).click();
    await expect(page.getByRole('button', { name: 'Prune Now', exact: true })).toBeEnabled();
    expect(writes).toEqual(['POST /api/extensions/datapruner/_start', 'POST /api/extensions/datapruner/_stop']);
    await page.getByRole('button', { name: 'Dashboard', exact: true }).click();
    await page.getByText('Demo Stopped', { exact: true }).click();
    await expect(page.getByRole('button', { name: 'Start', exact: true })).toHaveCount(0);
});

for (const failed of [false, true]) {
    test(`script/template navigation and palette entries hide with ${failed ? 'failed' : 'empty'} permissions`, async ({ page }) => {
        await setup(page, [], failed ? { 'GET /extensions/rbac/my-permissions': { __status: 503 } } : {});
        await page.goto('/dashboard');
        await expect(page.getByText('Demo Started', { exact: true })).toBeVisible();
        for (const name of ['Global Scripts', 'Code Templates']) {
            await expect(page.getByRole('button', { name, exact: true })).toHaveCount(0);
        }
        await openPalette(page);
        for (const name of ['Global Scripts', 'Code Templates']) {
            await page.locator('.cmdk-field input').fill(name);
            await expect(page.locator('.cmdk-opt').filter({ hasText: name })).toHaveCount(0);
        }
    });
}

test('Settings commands match hidden tabs, including Data Pruner without extension-supplied mappings', async ({ page }) => {
    await setup(page, [], { 'GET /extensions/rbac/task-permissions': taskPermissionMap([]) });
    await page.goto('/settings');
    await expect(page.getByRole('tab', { name: 'Administrator', exact: true })).toBeVisible();
    const tabs = ['Data Pruner', 'Server', 'Configuration Map', 'Database Tasks', 'Resources', 'Role-Based Access Control'];
    for (const name of tabs) await expect(page.getByRole('tab', { name, exact: true })).toHaveCount(0);
    await openPalette(page);
    for (const name of tabs) {
        await page.locator('.cmdk-field input').fill('Settings: ' + name);
        await expect(page.locator('.cmdk-opt').filter({ hasText: 'Settings: ' + name })).toHaveCount(0);
    }
    await page.locator('.cmdk-field input').fill('Settings: Administrator');
    await expect(page.locator('.cmdk-opt').filter({ hasText: 'Settings: Administrator' })).toBeVisible();
});

for (const failedPath of ['my-permissions', 'task-permissions']) {
    test(`Roles and mounted Settings recover after ${failedPath} fails`, async ({ page }) => {
        await page.clock.install();
        let failing = true;
        let calls = 0;
        const fixtures = rbacFixtures({ myPermissions: ['View Roles'], taskPermissions: taskPermissionMap([]) });
        const key = 'GET /extensions/rbac/' + failedPath;
        await setup(page, ['View Roles'], {
            ...fixtures,
            [key]: () => { calls++; return failing ? { __status: 503 } : fixtures[key]; }
        });
        await page.goto('/settings');
        await expect(page.getByText('No settings are available with your current permissions.', { exact: true })).toBeVisible();
        await expect(page.getByRole('tab', { name: 'Role-Based Access Control', exact: true })).toHaveCount(0);
        failing = false;
        await page.clock.fastForward(16000);
        // No further click/render is necessary to recover a completely empty view.
        await expect(page.getByRole('tab', { name: 'Role-Based Access Control', exact: true })).toHaveCount(1);
        await page.getByRole('tab', { name: 'Role-Based Access Control', exact: true }).click();
        await expect(page.getByText('Roles', { exact: true })).toBeVisible();
        const recoveredCalls = calls;
        await page.clock.fastForward(16000);
        await openPalette(page);
        await page.locator('.cmdk-field input').fill('Settings: Role-Based Access Control');
        await expect(page.locator('.cmdk-opt').filter({ hasText: 'Settings: Role-Based Access Control' })).toHaveCount(1);
        await page.keyboard.press('Escape');
        expect(calls).toBe(recoveredCalls, 'successful recovery does not keep fetching');
        await expect(page.getByRole('tab', { name: 'Role-Based Access Control', exact: true })).toHaveCount(1);
    });
}

test('same-tab account change reloads RBAC permissions before showing the new session', async ({ page }) => {
    let loggedIn = true, restricted = false;
    await setup(page, ['View Roles', 'viewGlobalScripts'], {
        'GET /users/current': () => loggedIn ? { user: { id: restricted ? 2 : 1, username: restricted ? 'limited' : 'admin' } } : { __status: 401 },
        'POST /users/_logout': () => { loggedIn = false; return ''; },
        'POST /users/_login': () => { loggedIn = true; restricted = true; return { status: 'SUCCESS', message: 'ok' }; },
        'GET /extensions/rbac/task-permissions': taskPermissionMap([]),
        'GET /extensions/rbac/my-permissions': () => permissionSet(restricted ? [] : ['View Roles', 'viewGlobalScripts'])
    });
    await page.goto('/settings');
    await expect(page.getByRole('tab', { name: 'Role-Based Access Control', exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Global Scripts', exact: true })).toBeVisible();
    await page.getByRole('button', { name: 'Logout', exact: true }).click();
    await expect(page.getByRole('button', { name: 'Sign in', exact: true })).toBeVisible();
    await login(page, 'limited');
    await expect(page.getByRole('button', { name: 'Settings', exact: true })).toBeVisible();
    await page.getByRole('button', { name: 'Settings', exact: true }).click();
    await expect(page.getByRole('tab', { name: 'Administrator', exact: true })).toBeVisible();
    await expect(page.getByRole('tab', { name: 'Role-Based Access Control', exact: true })).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Global Scripts', exact: true })).toHaveCount(0);
});
