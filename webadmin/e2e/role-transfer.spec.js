// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

/*
 * Export Roles and Import Roles on the Roles settings panel, against the real
 * built bundle and the host with the engine mocked: who sees the two tasks
 * (the admin role only), the export download, and the import preview, tick
 * boxes, apply and failed apply.
 */

import fs from 'node:fs';
import { test, expect } from '@playwright/test';
import { mockEngineWithRbac } from './mock.js';
import {
    rbacFixtures, rolesList, ADMIN_ROLE, READ_ONLY_ROLE, EXPORT_FILE,
    IMPORT_PREVIEW_TWO_ROWS, IMPORT_NAME_MATCH_OFF, IMPORT_NAME_MATCH_ON, IMPORT_OVERWRITE_DETAILS,
    IMPORT_APPLIED, IMPORT_REFUSED
} from './fixtures.js';

const LAB_ROLE = {
    ...READ_ONLY_ROLE, id: 3, name: 'Lab', description: 'Lab staff',
    permissions: { string: ['viewDashboard', 'viewAlerts'] },
    channelIds: { string: ['c-stopped', 'c-deleted', 'c-started'] }
};
const VIEW_ROLES_ONLY = { ...READ_ONLY_ROLE, id: 4, name: 'Roles Viewer', permissions: { string: 'View Roles' } };
const FILE = { name: 'roles.xml', mimeType: 'application/xml', buffer: Buffer.from(EXPORT_FILE) };
const STALE = 'The roles changed since the preview. Preview the import again.';

// Records the requests the dialogs make to the two new endpoints.
function watch(page) {
    const seen = { exports: [], previews: [], applies: [], bodies: [], roleListLoads: 0 };
    page.on('request', (req) => {
        const url = new URL(req.url());
        if (url.pathname === '/api/extensions/rbac/roles/_export') seen.exports.push(url.searchParams.getAll('roleId'));
        if (url.pathname === '/api/extensions/rbac/roles/_import') {
            const q = Object.fromEntries(url.searchParams);
            q.pick = url.searchParams.getAll('pick');
            (q.dryRun === 'true' ? seen.previews : seen.applies).push(q);
            seen.bodies.push(req.postData());
        }
        if (req.method() === 'GET' && url.pathname === '/api/extensions/rbac/roles') seen.roleListLoads++;
    });
    return seen;
}

async function openPanel(page, overrides = {}, { admin = true, roles = [ADMIN_ROLE, READ_ONLY_ROLE, LAB_ROLE] } = {}) {
    await mockEngineWithRbac(page, {
        ...rbacFixtures({
            roles,
            userRole: admin ? ADMIN_ROLE : VIEW_ROLES_ONLY,
            myPermissions: admin ? undefined : ['View Roles', 'Manage Roles']
        }),
        ...overrides
    });
    await page.goto('/settings');
    await page.getByRole('tab', { name: 'Role-Based Access Control', exact: true }).click();
    await expect(page.getByRole('button', { name: 'Refresh', exact: true })).toBeVisible();
    await expect(page.getByRole('cell', { name: 'Lab', exact: true })).toBeVisible();
}

const task = (page, name) => page.getByRole('button', { name, exact: true });

async function chooseFile(page, file = FILE) {
    const chooser = page.waitForEvent('filechooser');
    await task(page, 'Import Roles').click();
    await (await chooser).setFiles(file);
}

function importFixtures(preview, extra = {}) {
    return {
        'POST /extensions/rbac/roles/_import': (req) => {
            const q = new URL(req.url()).searchParams;
            if (q.get('dryRun') === 'false') return IMPORT_APPLIED;
            return typeof preview === 'function' ? preview(q) : preview;
        },
        ...extra
    };
}

const IMPORT_HEADERS = ['Import', 'Role', 'Action', 'Description now', 'Description after',
    'Permissions now', 'Permissions after', 'Channels now', 'Channels after', 'Notes'];
// The lines of a list cell, one div per line.
const lines = (cell) => cell.locator('div');
const COL = { name: 1, action: 2, descNow: 3, descAfter: 4, permsNow: 5, permsAfter: 6, chanNow: 7, chanAfter: 8, notes: 9 };
const cell = (row, name) => row.locator('td').nth(COL[name]);
const NAME_MATCH_HINT = '1 channel(s) in the file match a channel here only by name. Tick the box above to use them.';

const dialog = (page, name) => page.getByRole('dialog', { name, exact: true });
// The message toast (the page also has a screen reader copy of it).
const toast = (page, text) => page.locator('.toast-msg', { hasText: text });

test.describe('who sees Export Roles and Import Roles', () => {
    test('a View Roles and Manage Roles holder who is not the admin role sees neither', async ({ page }) => {
        await openPanel(page, {}, { admin: false });
        await expect(task(page, 'Refresh')).toBeVisible();
        await expect(task(page, 'Export Roles')).toHaveCount(0);
        await expect(task(page, 'Import Roles')).toHaveCount(0);
        await expect(page.getByRole('button', { name: 'Add', exact: true })).toBeVisible();
    });

    test('a failed role lookup means not an admin, and the panel still loads', async ({ page }) => {
        await openPanel(page, { 'GET /extensions/rbac/users/*/role': { __status: 403, body: 'Missing permission: View Roles' } });
        await expect(task(page, 'Refresh')).toBeVisible();
        await expect(task(page, 'Export Roles')).toHaveCount(0);
        await expect(task(page, 'Import Roles')).toHaveCount(0);
    });

    test('the admin role sees both, with their tooltips', async ({ page }) => {
        await openPanel(page);
        await expect(task(page, 'Export Roles')).toHaveAttribute('title', 'Export roles to a file.');
        await expect(task(page, 'Import Roles')).toHaveAttribute('title', 'Import roles from a file.');
    });
});

test.describe('Export Roles', () => {
    test.beforeEach(async ({ page }) => {
        // No save-file picker: saveFile falls back to a normal download.
        await page.addInitScript(() => { window.showSaveFilePicker = undefined; });
    });

    test('lists every role but the admin role, all ticked, and downloads the server text', async ({ page }) => {
        const seen = watch(page);
        await openPanel(page, { 'GET /extensions/rbac/roles/_export': EXPORT_FILE });
        await task(page, 'Export Roles').click();
        const box = dialog(page, 'Export Roles');
        await expect(box.getByText('Pick the roles to export. The admin role is never exported.')).toBeVisible();
        await expect(box.getByText('Channel restrictions are included. When importing, you can choose not to apply them.')).toBeVisible();
        await expect(box.getByRole('checkbox')).toHaveCount(2);
        await expect(box.getByLabel('Read Only')).toBeChecked();
        await expect(box.getByLabel('Lab')).toBeChecked();
        await expect(box.getByText('Administrator')).toHaveCount(0);

        await box.getByLabel('Read Only').uncheck();
        const download = page.waitForEvent('download');
        await box.getByRole('button', { name: 'Export', exact: true }).click();
        const file = await download;
        expect(file.suggestedFilename()).toBe('rbac-roles.xml');
        expect(fs.readFileSync(await file.path(), 'utf8')).toBe(EXPORT_FILE);
        expect(seen.exports).toEqual([['3']]);
        await expect(toast(page, 'Exported 1 role(s).')).toBeVisible();
        await expect(dialog(page, 'Export Roles')).toHaveCount(0);
    });

    test('the table shows each role with its description, permissions and channels', async ({ page }) => {
        await openPanel(page);
        await task(page, 'Export Roles').click();
        const box = dialog(page, 'Export Roles');
        await expect(box.getByRole('columnheader')).toHaveText(['Export', 'Role', 'Description', 'Permissions', 'Channels']);
        const rows = box.locator('tbody tr');
        await expect(rows).toHaveCount(2);
        const readOnly = rows.nth(0).locator('td');
        await expect(readOnly.nth(1)).toHaveText('Read Only');
        await expect(readOnly.nth(2)).toHaveText('View-only access');
        await expect(lines(readOnly.nth(3)).first()).toHaveText('viewAlerts');
        await expect(lines(readOnly.nth(3))).toHaveCount(13);
        await expect(lines(readOnly.nth(4))).toHaveText(['Every channel']);
        const lab = rows.nth(1).locator('td');
        await expect(lab.nth(1)).toHaveText('Lab');
        await expect(lab.nth(2)).toHaveText('Lab staff');
        await expect(lines(lab.nth(3))).toHaveText(['viewAlerts', 'viewDashboard']);
        await expect(lines(lab.nth(4))).toHaveText(['Demo Started', 'Demo Stopped', 'c-deleted (deleted channel)']);
    });

    test('Export is disabled while nothing is ticked; Cancel closes without a request', async ({ page }) => {
        const seen = watch(page);
        await openPanel(page);
        await task(page, 'Export Roles').click();
        const box = dialog(page, 'Export Roles');
        await box.getByLabel('Read Only').uncheck();
        await box.getByLabel('Lab').uncheck();
        await expect(box.getByRole('button', { name: 'Export', exact: true })).toBeDisabled();
        await box.getByLabel('Lab').check();
        await expect(box.getByRole('button', { name: 'Export', exact: true })).toBeEnabled();
        await box.getByRole('button', { name: 'Cancel', exact: true }).click();
        await expect(dialog(page, 'Export Roles')).toHaveCount(0);
        expect(seen.exports).toEqual([]);
    });

    test('with only the admin role there is a message and no dialog', async ({ page }) => {
        await mockEngineWithRbac(page, rbacFixtures({ roles: [ADMIN_ROLE] }));
        await page.goto('/settings');
        await page.getByRole('tab', { name: 'Role-Based Access Control', exact: true }).click();
        // The roles table comes first; once users load, their Role column says Administrator too.
        await expect(page.getByRole('cell', { name: 'Administrator', exact: true }).first()).toBeVisible();
        await task(page, 'Export Roles').click();
        await expect(toast(page, 'There are no roles to export. The admin role is never exported.')).toBeVisible();
        await expect(dialog(page, 'Export Roles')).toHaveCount(0);
    });
});

test.describe('Import Roles', () => {
    test('the preview table, default ticks, source line, and a successful apply', async ({ page }) => {
        const seen = watch(page);
        await openPanel(page, importFixtures(IMPORT_PREVIEW_TWO_ROWS));
        const loadsBefore = seen.roleListLoads;
        await chooseFile(page);
        const box = dialog(page, 'Import Roles');
        await expect(box.getByText('From rbac 1.2.0 on OIE 4.7.0.')).toBeVisible();
        await expect(box.getByRole('columnheader')).toHaveText(IMPORT_HEADERS);
        const rows = box.locator('tbody tr');
        await expect(rows).toHaveCount(2);
        await expect(cell(rows.nth(0), 'name')).toHaveText('probe lab');
        await expect(cell(rows.nth(0), 'action')).toHaveText('New');
        await expect(rows.nth(0).getByRole('checkbox')).toBeChecked();
        await expect(cell(rows.nth(1), 'name')).toHaveText('probe everyone');
        await expect(cell(rows.nth(1), 'action')).toHaveText('Unchanged');
        await expect(cell(rows.nth(1), 'notes')).toHaveText('Same as the role here');
        await expect(rows.nth(1).getByRole('checkbox')).toBeDisabled();
        await expect(rows.nth(1).getByRole('checkbox')).not.toBeChecked();

        expect(seen.previews).toHaveLength(1);
        expect(seen.previews[0]).toMatchObject({ dryRun: 'true', applyChannels: 'true', matchChannelsByName: 'false' });
        expect(seen.bodies[0]).toBe(EXPORT_FILE);

        await box.getByRole('button', { name: 'Import', exact: true }).click();
        await expect(toast(page, 'Imported 1 role(s).')).toBeVisible();
        await expect(dialog(page, 'Import Roles')).toHaveCount(0);
        expect(seen.applies).toHaveLength(1);
        expect(seen.applies[0]).toMatchObject({
            dryRun: 'false', applyChannels: 'true', matchChannelsByName: 'false',
            planToken: IMPORT_PREVIEW_TWO_ROWS['com.diridium.rbac.RoleImportResult'].planToken
        });
        expect(seen.applies[0].pick).toEqual(['0']);
        await expect.poll(() => seen.roleListLoads).toBeGreaterThan(loadsBefore);
    });

    test('a New row fills Description after, Permissions after and Channels after, and nothing "now"', async ({ page }) => {
        await openPanel(page, importFixtures(IMPORT_PREVIEW_TWO_ROWS));
        await chooseFile(page);
        const row = dialog(page, 'Import Roles').locator('tbody tr').nth(0);
        await expect(cell(row, 'descNow')).toHaveText('');
        await expect(cell(row, 'descAfter')).toHaveText('rbac e2e');
        await expect(lines(cell(row, 'permsNow'))).toHaveCount(0);
        await expect(lines(cell(row, 'permsAfter'))).toHaveText(['viewChannels', 'viewDashboard']);
        await expect(lines(cell(row, 'chanNow'))).toHaveCount(0);
        await expect(lines(cell(row, 'chanAfter'))).toHaveText(['probe one (found by id)', 'probe two (found by id)']);
        await expect(cell(row, 'notes')).toHaveText('');
        // The Unchanged row: the role here sees every channel, and so does the file's.
        const same = dialog(page, 'Import Roles').locator('tbody tr').nth(1);
        await expect(lines(cell(same, 'chanNow'))).toHaveText(['Every channel']);
        await expect(lines(cell(same, 'chanAfter'))).toHaveText(['Every channel']);
        await expect(lines(cell(same, 'permsNow'))).toHaveText(['viewChannels']);
    });

    test('an Overwrite row shows the role now and after side by side, a renamed channel and a dropped permission', async ({ page }) => {
        await openPanel(page, importFixtures(IMPORT_OVERWRITE_DETAILS));
        await chooseFile(page);
        const row = dialog(page, 'Import Roles').locator('tbody tr').nth(0);
        await expect(cell(row, 'action')).toHaveText('Overwrite');
        await expect(row.getByRole('checkbox')).not.toBeChecked();
        await expect(cell(row, 'descNow')).toHaveText('Lab staff');
        await expect(cell(row, 'descAfter')).toHaveText('Lab team');
        await expect(lines(cell(row, 'permsNow'))).toHaveText(['viewAlerts', 'viewChannels']);
        await expect(lines(cell(row, 'permsAfter'))).toHaveText([
            'viewChannels', 'viewDashboard', 'oldPermission (not on this engine, left out)']);
        await expect(lines(cell(row, 'chanNow'))).toHaveText(['probe one', 'gone-id (deleted channel)']);
        await expect(lines(cell(row, 'chanAfter'))).toHaveText([
            'probe one renamed (found by id, named "probe one" in the file)', 'probe two (found by id)']);
        await expect(cell(row, 'notes')).toHaveText('');
    });

    test('Import is disabled when nothing is ticked', async ({ page }) => {
        await openPanel(page, importFixtures(IMPORT_PREVIEW_TWO_ROWS));
        await chooseFile(page);
        const box = dialog(page, 'Import Roles');
        await box.locator('tbody tr').nth(0).getByRole('checkbox').uncheck();
        await expect(box.getByRole('button', { name: 'Import', exact: true })).toBeDisabled();
    });

    test('the two tick boxes: the second needs the first, and each change previews again', async ({ page }) => {
        const seen = watch(page);
        await openPanel(page, importFixtures((q) =>
            q.get('matchChannelsByName') === 'true' ? IMPORT_NAME_MATCH_ON : IMPORT_NAME_MATCH_OFF));
        await chooseFile(page);
        const box = dialog(page, 'Import Roles');
        const apply = box.getByLabel('Apply channel restrictions from the file');
        const byName = box.getByLabel("Also match channels by name when the id isn't found");
        await expect(apply).toBeChecked();
        await expect(byName).not.toBeChecked();
        await expect(byName).toBeEnabled();

        // Matching is off: the skipped row (an empty Channels after would be nothing looked up; here the
        // channel is listed as not found) and the hint.
        const row = box.locator('tbody tr').nth(0);
        await expect(cell(row, 'action')).toHaveText('Skipped');
        await expect(lines(cell(row, 'chanAfter'))).toHaveText(['probe one (not found here)']);
        await expect(row.getByRole('checkbox')).toBeDisabled();
        await expect(box.getByRole('button', { name: 'Import', exact: true })).toBeDisabled();
        await expect(box.getByText(NAME_MATCH_HINT)).toBeVisible();

        // Ticking the second previews again: now a New role, ticked, the channel found by name, and no hint.
        await byName.check();
        await expect(cell(row, 'action')).toHaveText('New');
        await expect(row.getByRole('checkbox')).toBeChecked();
        await expect(lines(cell(row, 'chanAfter'))).toHaveText(['probe one (found by name)']);
        await expect(box.getByText(NAME_MATCH_HINT)).toHaveCount(0);
        await expect(box.getByRole('button', { name: 'Import', exact: true })).toBeEnabled();
        expect(seen.previews.map((p) => [p.applyChannels, p.matchChannelsByName]))
            .toEqual([['true', 'false'], ['true', 'true']]);

        // Unticking the first unticks and disables the second and previews again.
        await apply.uncheck();
        await expect(byName).not.toBeChecked();
        await expect(byName).toBeDisabled();
        await expect(box.getByText(NAME_MATCH_HINT)).toHaveCount(0);
        expect(seen.previews.map((p) => [p.applyChannels, p.matchChannelsByName]))
            .toEqual([['true', 'false'], ['true', 'true'], ['false', 'false']]);

        // Ticking the first again enables the second.
        await apply.check();
        await expect(byName).toBeEnabled();
        expect(seen.previews).toHaveLength(4);
    });

    test('a failed apply shows the server message and previews again with the same settings', async ({ page }) => {
        const seen = watch(page);
        await openPanel(page, importFixtures(IMPORT_PREVIEW_TWO_ROWS, {
            'POST /extensions/rbac/roles/_import': (req) => {
                const q = new URL(req.url()).searchParams;
                return q.get('dryRun') === 'false' ? { __status: 409, body: STALE } : IMPORT_PREVIEW_TWO_ROWS;
            }
        }));
        await chooseFile(page);
        const box = dialog(page, 'Import Roles');
        await box.getByLabel('Apply channel restrictions from the file').uncheck();
        await expect(box.locator('tbody tr')).toHaveCount(2);
        await box.getByRole('button', { name: 'Import', exact: true }).click();
        const error = dialog(page, 'Error');
        await expect(error.getByText(STALE)).toBeVisible();
        // The dialog was previewed again, with the same settings, behind the error.
        await expect.poll(() => seen.previews.length).toBe(3);
        expect(seen.previews[2]).toMatchObject({ dryRun: 'true', applyChannels: 'false', matchChannelsByName: 'false' });
        expect(seen.applies).toHaveLength(1);
        await error.locator('button.btn-primary', { hasText: 'Close' }).click();
        await expect(dialog(page, 'Import Roles')).toBeVisible();
        await expect(toast(page, 'Imported 1 role(s).')).toHaveCount(0);
    });

    test('a refused file shows why and opens no dialog', async ({ page }) => {
        await openPanel(page, importFixtures(IMPORT_REFUSED));
        await chooseFile(page);
        await expect(dialog(page, 'Error').getByText(
            "This file can't be imported: This file is format 2, written by rbac 9. This rbac reads format 1.")).toBeVisible();
        await expect(dialog(page, 'Import Roles')).toHaveCount(0);
    });

    test('Cancel closes the dialog without applying', async ({ page }) => {
        const seen = watch(page);
        await openPanel(page, importFixtures(IMPORT_PREVIEW_TWO_ROWS));
        await chooseFile(page);
        const box = dialog(page, 'Import Roles');
        await box.getByRole('button', { name: 'Cancel', exact: true }).click();
        await expect(dialog(page, 'Import Roles')).toHaveCount(0);
        expect(seen.applies).toEqual([]);
    });
});
