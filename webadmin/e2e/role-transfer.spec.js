// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

/*
 * Export Roles and Import Roles on the Roles settings panel, against the real
 * built bundle and the host with the engine mocked: who sees the two tasks
 * (the admin role only), the export download and its tables, and the import
 * preview (the roles table and the selected role's permission and channel
 * tables), tick boxes, sorting, apply and failed apply.
 */

import fs from 'node:fs';
import { test, expect } from '@playwright/test';
import { mockEngineWithRbac } from './mock.js';
import {
    rbacFixtures, rolesList, ADMIN_ROLE, READ_ONLY_ROLE, EXPORT_FILE,
    IMPORT_PREVIEW_TWO_ROWS, IMPORT_NAME_MATCH_OFF, IMPORT_NAME_MATCH_ON, IMPORT_OVERWRITE_DETAILS,
    IMPORT_SEVERAL_ROWS, IMPORT_MATCH_VALUES, IMPORT_NONE_ROWS, IMPORT_NO_CHANNEL_FOUND, IMPORT_APPLIED, IMPORT_REFUSED
} from './fixtures.js';

const LAB_ROLE = {
    ...READ_ONLY_ROLE, id: 3, name: 'Lab', description: 'Lab staff',
    permissions: { string: ['viewDashboard', 'viewAlerts'] },
    restricted: true, channelIds: { string: ['c-stopped', 'c-deleted', 'c-started'] }
};
const NONE_ROLE = { ...READ_ONLY_ROLE, id: 5, name: 'Sees None', description: 'Sees nothing', restricted: true, channelIds: null };
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

const IMPORT_HEADERS = ['Import', 'Role', 'Action', 'Description currently', 'Description after import',
    'Permissions', 'Channels', 'Notes'];
const PERMISSION_HEADERS = ['Permission', 'Currently', 'After import', 'Note'];
const CHANNEL_HEADERS = ['Channel', 'Id on this engine', 'Currently', 'After import', 'Match', 'Name in import',
    'Id in import'];
const PERMISSIONS_LEGEND = 'Currently: this role has the permission on this engine.'
    + ' After import: this role will have the permission if imported.';
const CHANNELS_LEGEND = 'Currently: this role is restricted to the channel on this engine. After import: this role will'
    + " be restricted to the channel if imported. Match: how the import's channel was found on this engine.";
const NOT_APPLIED = 'Channel restrictions from the import are not applied. Roles that already exist on this engine'
    + ' keep their current channels. New roles are restricted to no channels until an administrator sets channels'
    + ' for them.';
const APPLY_LABEL = 'Apply channel restrictions from the import';
const COL = { name: 1, action: 2, descNow: 3, descAfter: 4, perms: 5, chans: 6, notes: 7 };
const cell = (row, name) => row.locator('td').nth(COL[name]);
// The text of every cell of a table's body rows, one array per row.
const cellsOf = (table) => table.locator('tbody tr').evaluateAll(
    (trs) => trs.map((tr) => [...tr.querySelectorAll('td')].map((td) => td.textContent)));
// The detail table under a heading such as "Channels of Lab".
const detail = (box, heading) => box.locator('div').filter({ has: box.page().locator('h4', { hasText: heading }) })
    .last().locator('.rbac-xfer-scroll');
const ARROW = String.fromCharCode(0x2192);
const ONE = '4c468ff3-0cf7-4e8b-88e7-a7d8a3b538bf';
const TWO = 'ee366a8b-755b-4f73-9f1b-abe1801cc121';
const MOVED = '8163af3f-7ed2-4a0c-b326-34830263c504';
const NOWHERE = 'bbb4ce36-25d9-4830-9644-7fcd5682f5fd';
const NAME_MATCH_HINT = '1 channel in the import matches a channel on this engine by name only. Tick the box above to use them.';

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

    test('the roles table shows each role with its description and the counts; the first row is selected', async ({ page }) => {
        await openPanel(page);
        await task(page, 'Export Roles').click();
        const box = dialog(page, 'Export Roles');
        await expect(box.locator('.rbac-xfer-roles').getByRole('columnheader')).toHaveText(
            ['Export', 'Role', 'Description', 'Permissions', 'Channels']);
        const rows = box.locator('.rbac-xfer-roles tbody tr');
        await expect(rows).toHaveCount(2);
        const readOnly = rows.nth(0).locator('td');
        await expect(readOnly.nth(1)).toHaveText('Read Only');
        await expect(readOnly.nth(2)).toHaveText('View-only access');
        await expect(readOnly.nth(3)).toHaveText('13');
        await expect(readOnly.nth(4)).toHaveText('every');
        const lab = rows.nth(1).locator('td');
        await expect(lab.nth(1)).toHaveText('Lab');
        await expect(lab.nth(2)).toHaveText('Lab staff');
        await expect(lab.nth(3)).toHaveText('2');
        await expect(lab.nth(4)).toHaveText('3');
        await expect(rows.nth(0)).toHaveClass(/rbac-xfer-selected/);
        await expect(rows.nth(1)).not.toHaveClass(/rbac-xfer-selected/);
    });

    test('the callout under the prompt is highlighted, with the second sentence in bold', async ({ page }) => {
        await openPanel(page);
        await task(page, 'Export Roles').click();
        const callout = dialog(page, 'Export Roles').locator('.rbac-xfer-callout');
        await expect(callout).toHaveText('Channel restrictions are included. When importing, you can choose not to apply them.');
        await expect(callout.locator('strong')).toHaveText('When importing, you can choose not to apply them.');
        await expect(callout).toHaveCSS('background-color', 'rgb(255, 247, 223)');
        await expect(callout).toHaveCSS('border-top-color', 'rgb(232, 207, 122)');
    });

    test('selecting a role fills the permission and channel tables; a role with no channels says so', async ({ page }) => {
        await openPanel(page);
        await task(page, 'Export Roles').click();
        const box = dialog(page, 'Export Roles');
        // Read Only is selected first: every channel, so no channel rows.
        await expect(box.getByRole('heading', { name: 'Permissions of Read Only' })).toBeVisible();
        await expect(box.getByRole('heading', { name: 'Channels of Read Only' })).toBeVisible();
        await expect(detail(box, 'Channels of Read Only')).toHaveText('This role sees every channel.');
        await expect(detail(box, 'Channels of Read Only').locator('tbody tr')).toHaveCount(0);
        await expect(detail(box, 'Permissions of Read Only').locator('tbody tr')).toHaveCount(13);

        await box.locator('.rbac-xfer-roles tbody tr').nth(1).locator('td').nth(2).click();
        await expect(box.locator('.rbac-xfer-roles tbody tr').nth(1)).toHaveClass(/rbac-xfer-selected/);
        await expect(box.getByRole('heading', { name: 'Permissions of Lab' })).toBeVisible();
        expect(await cellsOf(detail(box, 'Permissions of Lab'))).toEqual([['viewAlerts'], ['viewDashboard']]);
        await expect(detail(box, 'Channels of Lab').getByRole('columnheader')).toHaveText(['Channel', 'Id on this engine']);
        expect(await cellsOf(detail(box, 'Channels of Lab'))).toEqual([
            ['Demo Started', 'c-started'], ['Demo Stopped', 'c-stopped'], ['(no longer exists)', 'c-deleted']]);
        // Ids are in a monospace font; names are not.
        const channelCells = detail(box, 'Channels of Lab').locator('tbody tr').first().locator('td');
        await expect(channelCells.nth(1)).toHaveClass(/rbac-xfer-id/);
        await expect(channelCells.nth(0)).not.toHaveClass(/rbac-xfer-id/);
    });

    test('a role restricted to no channel counts "none" and says it sees no channels', async ({ page }) => {
        await openPanel(page, {}, { roles: [ADMIN_ROLE, READ_ONLY_ROLE, LAB_ROLE, NONE_ROLE] });
        await task(page, 'Export Roles').click();
        const box = dialog(page, 'Export Roles');
        const rows = box.locator('.rbac-xfer-roles tbody tr');
        await expect(rows.nth(0).locator('td').nth(4)).toHaveText('every');
        await expect(rows.nth(2).locator('td').nth(4)).toHaveText('none');
        await rows.nth(2).locator('td').nth(2).click();
        await expect(detail(box, 'Channels of Sees None')).toHaveText('This role sees no channels.');
        await expect(detail(box, 'Channels of Sees None').locator('tbody tr')).toHaveCount(0);
    });

    test('a tick box does not select its row; sorting a header keeps the selection and the ticks', async ({ page }) => {
        await openPanel(page);
        await task(page, 'Export Roles').click();
        const box = dialog(page, 'Export Roles');
        const rows = box.locator('.rbac-xfer-roles tbody tr');
        await box.getByLabel('Lab').uncheck();
        await expect(rows.nth(0)).toHaveClass(/rbac-xfer-selected/);
        await rows.nth(1).locator('td').nth(1).click();
        await expect(box.getByRole('heading', { name: 'Channels of Lab' })).toBeVisible();

        await box.locator('.rbac-xfer-roles').getByRole('columnheader', { name: 'Role' }).click();
        await expect(rows.locator('td:nth-child(2)')).toHaveText(['Lab', 'Read Only']);
        await box.locator('.rbac-xfer-roles').getByRole('columnheader', { name: 'Role' }).click();
        await expect(rows.locator('td:nth-child(2)')).toHaveText(['Read Only', 'Lab']);
        await expect(rows.nth(1)).toHaveClass(/rbac-xfer-selected/);
        await expect(box.getByLabel('Lab')).not.toBeChecked();
        await expect(box.getByLabel('Read Only')).toBeChecked();

        const channelTable = detail(box, 'Channels of Lab');
        await channelTable.getByRole('columnheader', { name: 'Channel' }).click();
        expect((await cellsOf(channelTable)).map((r) => r[0])).toEqual(['(no longer exists)', 'Demo Started', 'Demo Stopped']);
        await channelTable.getByRole('columnheader', { name: 'Channel' }).click();
        expect((await cellsOf(channelTable)).map((r) => r[0])).toEqual(['Demo Stopped', 'Demo Started', '(no longer exists)']);
        await channelTable.getByRole('columnheader', { name: 'Id on this engine' }).click();
        expect((await cellsOf(channelTable)).map((r) => r[1])).toEqual(['c-deleted', 'c-started', 'c-stopped']);
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
        await expect(box.locator('.rbac-xfer-roles').getByRole('columnheader')).toHaveText(IMPORT_HEADERS);
        const rows = box.locator('.rbac-xfer-roles tbody tr');
        await expect(rows).toHaveCount(2);
        await expect(cell(rows.nth(0), 'name')).toHaveText('probe lab');
        await expect(cell(rows.nth(0), 'action')).toHaveText('New');
        await expect(rows.nth(0).getByRole('checkbox')).toBeChecked();
        await expect(cell(rows.nth(1), 'name')).toHaveText('probe everyone');
        await expect(cell(rows.nth(1), 'action')).toHaveText('Unchanged');
        await expect(cell(rows.nth(1), 'notes')).toHaveText('Identical to the role on this engine.');
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

    test('a New row: Description after and the counts, nothing "now", and its permission and channel tables', async ({ page }) => {
        await openPanel(page, importFixtures(IMPORT_PREVIEW_TWO_ROWS));
        await chooseFile(page);
        const box = dialog(page, 'Import Roles');
        const rows = box.locator('.rbac-xfer-roles tbody tr');
        const row = rows.nth(0);
        await expect(row).toHaveClass(/rbac-xfer-selected/);
        await expect(cell(row, 'descNow')).toHaveText('');
        await expect(cell(row, 'descAfter')).toHaveText('rbac e2e');
        await expect(cell(row, 'perms')).toHaveText('2');
        await expect(cell(row, 'chans')).toHaveText('2');
        await expect(cell(row, 'notes')).toHaveText('');
        await expect(box.getByRole('heading', { name: 'Permissions of probe lab' })).toBeVisible();
        await expect(detail(box, 'Permissions of probe lab').getByRole('columnheader')).toHaveText(PERMISSION_HEADERS);
        expect(await cellsOf(detail(box, 'Permissions of probe lab'))).toEqual([
            ['viewChannels', '', 'yes', ''], ['viewDashboard', '', 'yes', '']]);
        await expect(detail(box, 'Channels of probe lab').getByRole('columnheader')).toHaveText(CHANNEL_HEADERS);
        expect(await cellsOf(detail(box, 'Channels of probe lab'))).toEqual([
            ['probe one', ONE, '', 'yes', 'by id', 'probe one', ONE],
            ['probe two', TWO, '', 'yes', 'by id', 'probe two', TWO]]);

        // The Unchanged row: the role here sees every channel, and so does the file's.
        const same = rows.nth(1);
        await expect(cell(same, 'perms')).toHaveText('1');
        await expect(cell(same, 'chans')).toHaveText('every');
        await same.locator('td').nth(1).click();
        await expect(same).toHaveClass(/rbac-xfer-selected/);
        await expect(row).not.toHaveClass(/rbac-xfer-selected/);
        await expect(detail(box, 'Channels of probe everyone')).toHaveText(
            'This role sees every channel currently. This role sees every channel after the import.');
        expect(await cellsOf(detail(box, 'Permissions of probe everyone'))).toEqual([['viewChannels', 'yes', 'yes', '']]);
    });

    test('an Overwrite row: the channel table has a renamed channel, a channel not found, a deleted one, ids and a dropped permission', async ({ page }) => {
        await openPanel(page, importFixtures(IMPORT_OVERWRITE_DETAILS));
        await chooseFile(page);
        const box = dialog(page, 'Import Roles');
        const row = box.locator('.rbac-xfer-roles tbody tr').nth(0);
        await expect(cell(row, 'action')).toHaveText('Overwrite');
        await expect(row.getByRole('checkbox')).not.toBeChecked();
        await expect(cell(row, 'descNow')).toHaveText('Lab staff');
        await expect(cell(row, 'descAfter')).toHaveText('Lab team');
        await expect(cell(row, 'perms')).toHaveText('2');
        await expect(cell(row, 'chans')).toHaveText('2');
        await expect(cell(row, 'notes')).toHaveText('Of the 3 channels in the import, 1 is not on this engine.'
            + ' 1 permission in the import is not offered by this engine and is left out.');
        expect(await cellsOf(detail(box, 'Permissions of Lab'))).toEqual([
            ['oldPermission', '', '', 'not offered by this engine, left out'],
            ['viewAlerts', 'yes', '', ''],
            ['viewChannels', 'yes', 'yes', ''],
            ['viewDashboard', '', 'yes', '']]);
        expect(await cellsOf(detail(box, 'Channels of Lab'))).toEqual([
            ['probe one renamed', ONE, 'yes', 'yes', 'by id, renamed on this engine', 'probe one', ONE],
            ['probe two', TWO, '', 'yes', 'by id', 'probe two', TWO],
            ['probe nowhere', '', '', '', 'not on this engine', 'probe nowhere', NOWHERE],
            ['(no longer exists)', 'gone-id', 'yes', '', 'deleted on this engine', '', '']]);
        // Ids are in a monospace font, the other cells are not.
        const first = detail(box, 'Channels of Lab').locator('tbody tr').first().locator('td');
        const family = (td) => td.evaluate((el) => getComputedStyle(el).fontFamily);
        expect(await family(first.nth(1))).toMatch(/mono|Menlo|Consolas/i);
        expect(await family(first.nth(6))).toMatch(/mono|Menlo|Consolas/i);
        expect(await family(first.nth(0))).not.toMatch(/mono/i);
    });

    test('several roles: counts with the arrow and "every", the long Notes cell wraps, and a click on a row selects it', async ({ page }) => {
        await openPanel(page, importFixtures(IMPORT_SEVERAL_ROWS));
        await chooseFile(page);
        const box = dialog(page, 'Import Roles');
        const rows = box.locator('.rbac-xfer-roles tbody tr');
        await expect(rows).toHaveCount(4);
        const counts = async () => rows.evaluateAll((trs) => trs.map((tr) => [...tr.querySelectorAll('td')].slice(5, 7).map((td) => td.textContent)));
        expect(await counts()).toEqual([['2', '2'], ['1 ' + ARROW + ' 3', '1 ' + ARROW + ' every'], ['1', 'every ' + ARROW + ' 2'], ['2', '2']]);

        const day = rows.filter({ hasText: 'Day' });
        await day.locator('td').nth(1).click();
        await expect(day).toHaveClass(/rbac-xfer-selected/);
        expect(await cellsOf(detail(box, 'Channels of Day'))).toEqual([['probe one', ONE, 'yes', '', 'not in the import', '', '']]);
        await expect(detail(box, 'Channels of Day').locator('.rbac-xfer-notice')).toHaveText('This role sees every channel after the import.');
        await rows.filter({ hasText: 'Night' }).locator('td').nth(1).click();
        expect(await cellsOf(detail(box, 'Channels of Night'))).toEqual([
            ['probe one', ONE, '', 'yes', 'by id', 'probe one', ONE], ['probe two', TWO, '', 'yes', 'by id', 'probe two', TWO]]);
        await expect(detail(box, 'Channels of Night').locator('.rbac-xfer-notice')).toHaveText('This role sees every channel currently.');

        // The Notes cell wraps; the other cells do not.
        const white = (td) => td.evaluate((el) => getComputedStyle(el).whiteSpace);
        expect(await white(cell(rows.nth(0), 'notes'))).toBe('normal');
        expect(await white(cell(rows.nth(0), 'name'))).toBe('nowrap');
    });

    test('restricted to no channel: the counts say "none" and the lines say so, from the flags', async ({ page }) => {
        await openPanel(page, importFixtures(IMPORT_NONE_ROWS));
        await chooseFile(page);
        const box = dialog(page, 'Import Roles');
        const rows = box.locator('.rbac-xfer-roles tbody tr');
        await expect(rows).toHaveCount(4);
        const chans = async () => rows.evaluateAll((trs) => trs.map((tr) => tr.querySelectorAll('td')[6].textContent));
        expect(await chans()).toEqual(['none', 'none ' + ARROW + ' every', 'every ' + ARROW + ' none', 'none']);
        const lines = {
            Quiet: 'This role sees no channels currently. This role sees no channels after the import.',
            Reopen: 'This role sees no channels currently. This role sees every channel after the import.',
            Close: 'This role sees every channel currently. This role sees no channels after the import.',
            'Fresh none': 'This role sees no channels after the import.'
        };
        for (const [name, line] of Object.entries(lines)) {
            await rows.filter({ hasText: name }).locator('td').nth(1).click();
            await expect(detail(box, 'Channels of ' + name).locator('.rbac-xfer-notice')).toHaveText(line);
            await expect(detail(box, 'Channels of ' + name).locator('tbody tr')).toHaveCount(0);
        }
    });

    test('sorting the roles table and the detail tables keeps the selection and the ticks', async ({ page }) => {
        await openPanel(page, importFixtures(IMPORT_SEVERAL_ROWS));
        await chooseFile(page);
        const box = dialog(page, 'Import Roles');
        const roles = box.locator('.rbac-xfer-roles');
        const rows = roles.locator('tbody tr');
        const names = () => rows.locator('td:nth-child(2)').allTextContents();
        await rows.filter({ hasText: 'Night' }).locator('td').nth(1).click();
        await box.getByLabel('Import Day').check();
        expect(await names()).toEqual(['Lab', 'Day', 'Night', 'Fresh']);

        await roles.getByRole('columnheader', { name: 'Role' }).click();
        expect(await names()).toEqual(['Day', 'Fresh', 'Lab', 'Night']);
        await roles.getByRole('columnheader', { name: 'Role' }).click();
        expect(await names()).toEqual(['Night', 'Lab', 'Fresh', 'Day']);
        await roles.getByRole('columnheader', { name: 'Channels' }).click();
        expect(await names()).toEqual(['Day', 'Lab', 'Fresh', 'Night']);
        await roles.getByRole('columnheader', { name: 'Import', exact: true }).click();
        expect(await names()).toEqual(['Lab', 'Night', 'Day', 'Fresh']);
        await expect(rows.filter({ hasText: 'Night' })).toHaveClass(/rbac-xfer-selected/);
        await expect(box.getByLabel('Import Day')).toBeChecked();
        await expect(box.getByLabel('Import Fresh')).toBeChecked();
        await expect(box.getByLabel('Import Lab')).not.toBeChecked();
        await expect(box.getByRole('heading', { name: 'Channels of Night' })).toBeVisible();

        // Pick Lab and sort its channels by Match, then by Name in import, descending.
        await rows.filter({ hasText: 'Lab' }).locator('td').nth(1).click();
        const channels = detail(box, 'Channels of Lab');
        const column = async (n) => (await cellsOf(channels)).map((r) => r[n]);
        await channels.getByRole('columnheader', { name: 'Match' }).click();
        expect(await column(4)).toEqual(['by id', 'by id, renamed on this engine', 'deleted on this engine', 'not on this engine']);
        await channels.getByRole('columnheader', { name: 'Name in import' }).click();
        await channels.getByRole('columnheader', { name: 'Name in import' }).click();
        expect(await column(5)).toEqual(['probe two', 'probe one', 'probe nowhere', '']);
        await channels.getByRole('columnheader', { name: 'Id on this engine' }).click();
        expect(await column(1)).toEqual(['', ONE, TWO, 'gone-id'].sort());
        const perms = detail(box, 'Permissions of Lab');
        await perms.getByRole('columnheader', { name: 'After import' }).click();
        await perms.getByRole('columnheader', { name: 'After import' }).click();
        expect((await cellsOf(perms)).map((r) => r[0])).toEqual(['viewChannels', 'viewDashboard', 'oldPermission', 'viewAlerts']);
        await expect(rows.filter({ hasText: 'Lab' })).toHaveClass(/rbac-xfer-selected/);
    });

    test('a new preview keeps the selected role and the ticks', async ({ page }) => {
        await openPanel(page, importFixtures(IMPORT_SEVERAL_ROWS));
        await chooseFile(page);
        const box = dialog(page, 'Import Roles');
        const rows = box.locator('.rbac-xfer-roles tbody tr');
        await rows.filter({ hasText: 'Night' }).locator('td').nth(1).click();
        await box.getByLabel('Import Day').check();
        await box.getByLabel('Import Fresh').uncheck();
        await box.getByLabel(APPLY_LABEL).uncheck();
        await expect(box.getByLabel('Import Day')).toBeEnabled(); // the new preview has arrived
        await expect(rows.filter({ hasText: 'Night' })).toHaveClass(/rbac-xfer-selected/);
        await expect(box.getByLabel('Import Day')).toBeChecked();
        await expect(box.getByLabel('Import Fresh')).not.toBeChecked();
    });

    test('a role with no channel found is ticked like any new role and says it sees no channels', async ({ page }) => {
        const seen = watch(page);
        await openPanel(page, importFixtures(IMPORT_NO_CHANNEL_FOUND));
        await chooseFile(page);
        const box = dialog(page, 'Import Roles');
        const lost = box.getByLabel('Import probe lost');
        await expect(lost).toBeEnabled();
        await expect(lost).toBeChecked();
        await expect(box.getByLabel('Import probe lab')).toBeChecked();
        const row = box.locator('.rbac-xfer-roles tbody tr').nth(0);
        await expect(cell(row, 'action')).toHaveText('New');
        await expect(cell(row, 'chans')).toHaveText('none');
        await expect(cell(row, 'notes')).toContainText('None of those channels exist on this engine.');
        expect(await cellsOf(detail(box, 'Channels of probe lost'))).toEqual([
            ['probe nowhere', '', '', '', 'not on this engine', 'probe nowhere', NOWHERE]]);
        await expect(detail(box, 'Channels of probe lost').locator('.rbac-xfer-notice')).toHaveText(
            'This role sees no channels after the import.');
        await box.getByRole('button', { name: 'Import', exact: true }).click();
        await expect(toast(page, 'Imported 2 role(s).')).toBeVisible();
        expect(seen.applies[0].pick).toEqual(['0', '1']);
    });

    test('the Match column: deleted on this engine (named or not in the import) and not in the import', async ({ page }) => {
        await openPanel(page, importFixtures(IMPORT_MATCH_VALUES));
        await chooseFile(page);
        const box = dialog(page, 'Import Roles');
        await expect(cell(box.locator('.rbac-xfer-roles tbody tr').nth(0), 'chans')).toHaveText('4 ' + ARROW + ' 1');
        expect(await cellsOf(detail(box, 'Channels of Ward'))).toEqual([
            ['probe one', ONE, 'yes', 'yes', 'by id', 'probe one', ONE],
            ['probe gone', '0a1b2c3d-1111-4222-8333-444455556666', 'yes', '', 'deleted on this engine', 'probe gone',
                '0a1b2c3d-1111-4222-8333-444455556666'],
            ['probe nowhere', '', '', '', 'not on this engine', 'probe nowhere', NOWHERE],
            ['probe three', 'now-only-id', 'yes', '', 'not in the import', '', ''],
            ['(no longer exists)', 'gone-id', 'yes', '', 'deleted on this engine', '', '']]);
    });

    test('the legends sit under the headings; unticking the apply box replaces the channels table and its legend', async ({ page }) => {
        await openPanel(page, importFixtures(IMPORT_OVERWRITE_DETAILS));
        await chooseFile(page);
        const box = dialog(page, 'Import Roles');
        await expect(box.getByText(PERMISSIONS_LEGEND, { exact: true })).toBeVisible();
        await expect(box.getByText(CHANNELS_LEGEND, { exact: true })).toBeVisible();
        await expect(box.locator('.rbac-xfer-legend')).toHaveCount(2);
        await expect(detail(box, 'Channels of Lab').getByRole('columnheader')).toHaveText(CHANNEL_HEADERS);

        await box.getByLabel(APPLY_LABEL).uncheck();
        await expect(box.getByText(NOT_APPLIED, { exact: true })).toBeVisible();
        await expect(box.getByRole('heading', { name: 'Channels of Lab' })).toBeVisible();
        await expect(box.getByText(CHANNELS_LEGEND, { exact: true })).toHaveCount(0);
        await expect(box.locator('.rbac-xfer-legend')).toHaveCount(1);
        await expect(box.getByRole('columnheader', { name: 'Match' })).toHaveCount(0);
        // The permissions table stays, legend included.
        await expect(box.getByText(PERMISSIONS_LEGEND, { exact: true })).toBeVisible();
        expect(await cellsOf(detail(box, 'Permissions of Lab'))).toHaveLength(4);

        await box.getByLabel(APPLY_LABEL).check();
        await expect(box.getByText(NOT_APPLIED, { exact: true })).toHaveCount(0);
        await expect(box.getByText(CHANNELS_LEGEND, { exact: true })).toBeVisible();
    });

    test('Import is disabled when nothing is ticked', async ({ page }) => {
        await openPanel(page, importFixtures(IMPORT_PREVIEW_TWO_ROWS));
        await chooseFile(page);
        const box = dialog(page, 'Import Roles');
        await box.locator('.rbac-xfer-roles tbody tr').nth(0).getByRole('checkbox').uncheck();
        await expect(box.getByRole('button', { name: 'Import', exact: true })).toBeDisabled();
    });

    test('the two tick boxes: the second needs the first, and each change previews again', async ({ page }) => {
        const seen = watch(page);
        await openPanel(page, importFixtures((q) =>
            q.get('matchChannelsByName') === 'true' ? IMPORT_NAME_MATCH_ON : IMPORT_NAME_MATCH_OFF));
        await chooseFile(page);
        const box = dialog(page, 'Import Roles');
        const apply = box.getByLabel(APPLY_LABEL);
        const byName = box.getByLabel("Also match channels by name when the id isn't found");
        await expect(apply).toBeChecked();
        await expect(byName).not.toBeChecked();
        await expect(byName).toBeEnabled();

        // Matching is off: a New role with no channel found (restricted to no channel if imported), ticked like any
        // New role; the channel listed as found by name but not used, and the hint.
        const row = box.locator('.rbac-xfer-roles tbody tr').nth(0);
        await expect(cell(row, 'action')).toHaveText('New');
        await expect(cell(row, 'chans')).toHaveText('none');
        await expect(cell(row, 'notes')).toHaveText('The import restricts this role to 1 channel. None of those channels'
            + ' exist on this engine. If imported, this role is restricted to no channels until an administrator sets'
            + ' channels for this role. 1 of those channels matches a channel on this engine by name.');
        expect(await cellsOf(detail(box, 'Channels of probe moved one'))).toEqual([
            ['probe one', ONE, '', '', 'by name, not used', 'probe one', MOVED]]);
        await expect(row.getByRole('checkbox')).toBeEnabled();
        await expect(row.getByRole('checkbox')).toBeChecked();
        await expect(box.getByRole('button', { name: 'Import', exact: true })).toBeEnabled();
        await expect(box.getByText(NAME_MATCH_HINT)).toBeVisible();

        // Ticking the second previews again: the channel is found by name and there is no hint. The row is no
        // longer a no-channel-found row; the user's tick is kept.
        await byName.check();
        await expect(cell(row, 'chans')).toHaveText('1');
        await expect(row.getByRole('checkbox')).toBeChecked();
        expect(await cellsOf(detail(box, 'Channels of probe moved one'))).toEqual([
            ['probe one', ONE, '', 'yes', 'by name', 'probe one', MOVED]]);
        await expect(box.getByText(NAME_MATCH_HINT)).toHaveCount(0);
        await expect(box.getByRole('button', { name: 'Import', exact: true })).toBeEnabled();
        expect(seen.previews.map((p) => [p.applyChannels, p.matchChannelsByName]))
            .toEqual([['true', 'false'], ['true', 'true']]);

        // Unticking the first unticks and disables the second and previews again.
        await apply.uncheck();
        await expect(byName).not.toBeChecked();
        await expect(byName).toBeDisabled();
        await expect(box.getByText(NOT_APPLIED, { exact: true })).toBeVisible();
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
        await box.getByLabel(APPLY_LABEL).uncheck();
        await expect(box.locator('.rbac-xfer-roles tbody tr')).toHaveCount(2);
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
