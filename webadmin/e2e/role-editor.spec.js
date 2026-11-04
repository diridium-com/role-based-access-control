// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

/*
 * The role editor's channel tab and the restricted flag, against the real built
 * bundle and the host with the engine mocked: the radio comes from the role's
 * flag (not from whether its channel list is empty), "Specific Channels" with
 * nothing ticked is legal and says so, no confirmation appears, and the role
 * sent to the server carries the flag.
 */

import { test, expect } from '@playwright/test';
import { mockEngineWithRbac } from './mock.js';
import { rbacFixtures, ADMIN_ROLE, READ_ONLY_ROLE } from './fixtures.js';

const NO_CHANNELS = 'This role sees no channels until some are ticked.';
const NONE_ROLE = { ...READ_ONLY_ROLE, id: 5, name: 'Sees None', restricted: true, channelIds: null };
const SOME_ROLE = { ...READ_ONLY_ROLE, id: 6, name: 'Sees Some', restricted: true, channelIds: { string: 'c-started' } };

// Records the role writes: [method, body].
function watchWrites(page) {
    const writes = [];
    page.on('request', (req) => {
        const path = new URL(req.url()).pathname;
        if (['POST', 'PUT'].includes(req.method()) && path.startsWith('/api/extensions/rbac/roles')) {
            writes.push([req.method(), req.postData()]);
        }
    });
    return writes;
}

async function openPanel(page) {
    await mockEngineWithRbac(page, {
        ...rbacFixtures({ roles: [ADMIN_ROLE, READ_ONLY_ROLE, NONE_ROLE, SOME_ROLE] }),
        'POST /extensions/rbac/roles': { 'com.diridium.rbac.Role': NONE_ROLE },
        'PUT /extensions/rbac/roles/*': { 'com.diridium.rbac.Role': NONE_ROLE }
    });
    await page.goto('/settings');
    await page.getByRole('tab', { name: 'Role-Based Access Control', exact: true }).click();
    await expect(page.getByRole('cell', { name: 'Sees None', exact: true })).toBeVisible();
}

async function editRole(page, name) {
    await page.getByRole('cell', { name, exact: true }).click();
    await page.getByRole('button', { name: 'Edit', exact: true }).click();
    const editor = page.locator('.rbac-overlay');
    await editor.getByRole('button', { name: 'Channel Restrictions' }).click();
    return editor;
}

async function addRole(page, name) {
    await page.getByRole('button', { name: 'Add', exact: true }).click();
    const editor = page.locator('.rbac-overlay');
    await editor.locator('input[type=text]').first().fill(name);
    await editor.getByRole('button', { name: 'Select All', exact: true }).click();
    await editor.getByRole('button', { name: 'Channel Restrictions' }).click();
    return editor;
}

const all = (editor) => editor.getByLabel('All Channels');
const specific = (editor) => editor.getByLabel('Specific Channels');

test.describe('role editor: the restricted flag', () => {
    test('the radio comes from the flag: unrestricted is All, restricted with no channels or some is Specific', async ({ page }) => {
        await openPanel(page);
        let editor = await editRole(page, 'Read Only');
        await expect(all(editor)).toBeChecked();
        await expect(editor.getByText(NO_CHANNELS)).toHaveCount(0);
        await editor.getByRole('button', { name: 'Cancel' }).click();

        editor = await editRole(page, 'Sees None');
        await expect(specific(editor)).toBeChecked();
        await expect(editor.locator('.rbac-channel-list input[type=checkbox]:checked')).toHaveCount(0);
        await expect(editor.getByText(NO_CHANNELS)).toBeVisible();
        await editor.getByRole('button', { name: 'Cancel' }).click();

        editor = await editRole(page, 'Sees Some');
        await expect(specific(editor)).toBeChecked();
        await expect(editor.locator('.rbac-channel-list input[type=checkbox]:checked')).toHaveCount(1);
        await expect(editor.getByText(NO_CHANNELS)).toHaveCount(0);
    });

    test('Specific with nothing ticked saves a restricted role with no channels, with no confirmation', async ({ page }) => {
        const writes = watchWrites(page);
        await openPanel(page);
        const editor = await addRole(page, 'Nobody');
        await specific(editor).check();
        await expect(editor.getByText(NO_CHANNELS)).toBeVisible();
        await editor.getByRole('button', { name: 'Apply' }).click();
        await expect(page.locator('.rbac-overlay')).toHaveCount(0);
        await expect(page.getByRole('dialog', { name: 'No Channel Restrictions' })).toHaveCount(0);
        await expect.poll(() => writes.length).toBe(1);
        expect(writes[0][0]).toBe('POST');
        expect(writes[0][1]).toContain('<name>Nobody</name>');
        expect(writes[0][1]).toContain('<channelIds></channelIds><restricted>true</restricted>');
    });

    test('the line shows only while Specific is selected and nothing is ticked', async ({ page }) => {
        await openPanel(page);
        const editor = await addRole(page, 'Line');
        await expect(editor.getByText(NO_CHANNELS)).toHaveCount(0);
        await specific(editor).check();
        await expect(editor.getByText(NO_CHANNELS)).toBeVisible();
        await editor.getByLabel('Demo Started').check();
        await expect(editor.getByText(NO_CHANNELS)).toHaveCount(0);
        await editor.getByLabel('Demo Started').uncheck();
        await expect(editor.getByText(NO_CHANNELS)).toBeVisible();
        await all(editor).check();
        await expect(editor.getByText(NO_CHANNELS)).toHaveCount(0);
    });

    test('All Channels saves restricted false with no channels, even after ticking some', async ({ page }) => {
        const writes = watchWrites(page);
        await openPanel(page);
        const editor = await addRole(page, 'Everything');
        await specific(editor).check();
        await editor.getByLabel('Demo Started').check();
        await all(editor).check();
        await editor.getByRole('button', { name: 'Apply' }).click();
        await expect.poll(() => writes.length).toBe(1);
        expect(writes[0][1]).toContain('<channelIds></channelIds><restricted>false</restricted>');
    });

    test('Specific with a channel ticked saves it with restricted true', async ({ page }) => {
        const writes = watchWrites(page);
        await openPanel(page);
        const editor = await addRole(page, 'Some');
        await specific(editor).check();
        await editor.getByLabel('Demo Started').check();
        await editor.getByRole('button', { name: 'Apply' }).click();
        await expect.poll(() => writes.length).toBe(1);
        expect(writes[0][1]).toContain('<channelIds><string>c-started</string></channelIds><restricted>true</restricted>');
    });

    test('editing a restricted role with no channels and applying keeps it restricted', async ({ page }) => {
        const writes = watchWrites(page);
        await openPanel(page);
        const editor = await editRole(page, 'Sees None');
        await editor.getByRole('button', { name: 'Apply' }).click();
        await expect.poll(() => writes.length).toBe(1);
        expect(writes[0][0]).toBe('PUT');
        expect(writes[0][1]).toContain('<channelIds></channelIds><restricted>true</restricted>');
    });
});
