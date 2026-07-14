// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

/*
 * Map-completeness test: every (taskGroup, taskName) identifier the web host
 * can ask checkTask about must be either mapped (composite or bare) or listed
 * in DELIBERATELY_UNMAPPED — anything else is drift between the host catalog
 * and task-permission-map.js, and this test fails until the map catches up.
 *
 * The catalog is the checked-in snapshot web-task-catalog.json, generated once
 * from oie-web-client web-administrator/RBAC.md §3 (see its $comment) so this
 * repo stays self-contained. Regenerate the snapshot when the host catalog
 * changes; the reverse-direction tests below then flag stale map entries.
 *
 * Run: npm test   (from webadmin/; node --test web/)
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
    TASK_PERMISSIONS,
    GROUP_TASK_PERMISSIONS,
    DELIBERATELY_UNMAPPED,
} from './task-permission-map.js';

const catalog = JSON.parse(
    readFileSync(new URL('./web-task-catalog.json', import.meta.url), 'utf8'));
const groups = catalog.groups;

// Composite mappings that are NOT host catalog entries: the plugin's own
// Settings tab, whose (group, task) identifiers are created by this plugin's
// registerSettingsPanel call, not by the host.
const PLUGIN_OWN_COMPOSITES = [
    'settings_Role-Based Access Control/doRefresh',
    'settings_Role-Based Access Control/doSave',
];

// Bare mappings kept purely for 1:1 Swing parity — no web control carries the
// task today (see the doFilter comment in task-permission-map.js).
const SWING_PARITY_ONLY_TASKS = ['doFilter'];

const allComposites = new Set();
const allTasks = new Set();
for (const [group, tasks] of Object.entries(groups)) {
    for (const task of tasks) {
        allComposites.add(`${group}/${task}`);
        allTasks.add(task);
    }
}

test('catalog snapshot is well-formed', () => {
    assert.ok(typeof catalog.$comment === 'string' && catalog.$comment.includes('RBAC.md'),
        'snapshot must carry its provenance note');
    assert.equal(Object.keys(groups).length, 20, 'RBAC.md §3 defines 20 task groups');
    for (const [group, tasks] of Object.entries(groups)) {
        assert.ok(Array.isArray(tasks) && tasks.length > 0, `group "${group}" must be a non-empty array`);
        assert.equal(new Set(tasks).size, tasks.length, `group "${group}" has duplicate tasks`);
        for (const task of tasks) assert.equal(typeof task, 'string');
    }
    // Spot-checks that the snapshot really is the host catalog shape.
    assert.ok(groups.view.includes('doShowSettings'));
    assert.ok(groups.message.includes('viewImage'), 'the non-do… Swing constant must survive');
    assert.ok(groups['settings_Configuration Map'].includes('doImportMap'));
});

test('every catalog identifier is mapped or deliberately unmapped', () => {
    const unmapped = new Set(DELIBERATELY_UNMAPPED);
    const misses = [];
    for (const [group, tasks] of Object.entries(groups)) {
        for (const task of tasks) {
            const composite = `${group}/${task}`;
            const covered = Object.hasOwn(GROUP_TASK_PERMISSIONS, composite)
                || Object.hasOwn(TASK_PERMISSIONS, task)
                || unmapped.has(composite);
            if (!covered) misses.push(composite);
        }
    }
    assert.deepEqual(misses, [],
        'catalog identifiers with no mapping and no DELIBERATELY_UNMAPPED entry (host drift?)');
});

test('DELIBERATELY_UNMAPPED entries are real catalog identifiers', () => {
    assert.equal(new Set(DELIBERATELY_UNMAPPED).size, DELIBERATELY_UNMAPPED.length,
        'duplicate DELIBERATELY_UNMAPPED entries');
    for (const composite of DELIBERATELY_UNMAPPED) {
        assert.ok(composite.includes('/'), `"${composite}" must be a group/task composite`);
        assert.ok(allComposites.has(composite),
            `"${composite}" is not in the catalog snapshot (stale entry?)`);
    }
});

test('DELIBERATELY_UNMAPPED entries really resolve to the unknown-task allow branch', () => {
    // If a bare mapping existed for the task, checkTask's composite→bare
    // fallthrough would gate the "unmapped" item after all.
    for (const composite of DELIBERATELY_UNMAPPED) {
        const [, task] = composite.split('/');
        assert.ok(!Object.hasOwn(GROUP_TASK_PERMISSIONS, composite),
            `"${composite}" is both composite-mapped and DELIBERATELY_UNMAPPED`);
        assert.ok(!Object.hasOwn(TASK_PERMISSIONS, task),
            `"${composite}" is bare-mapped via "${task}" yet listed DELIBERATELY_UNMAPPED`);
    }
});

test('every composite mapping targets a catalog identifier', () => {
    for (const composite of Object.keys(GROUP_TASK_PERMISSIONS)) {
        if (PLUGIN_OWN_COMPOSITES.includes(composite)) continue;
        assert.ok(allComposites.has(composite),
            `GROUP_TASK_PERMISSIONS["${composite}"] is not in the catalog snapshot (stale mapping?)`);
    }
    // …and the plugin-own exceptions are actually mapped (typo guard).
    for (const composite of PLUGIN_OWN_COMPOSITES) {
        assert.ok(Object.hasOwn(GROUP_TASK_PERMISSIONS, composite),
            `plugin-own composite "${composite}" missing from GROUP_TASK_PERMISSIONS`);
    }
});

test('every bare mapping targets a catalog task', () => {
    for (const task of Object.keys(TASK_PERMISSIONS)) {
        if (SWING_PARITY_ONLY_TASKS.includes(task)) continue;
        assert.ok(allTasks.has(task),
            `TASK_PERMISSIONS["${task}"] is not a task in the catalog snapshot (stale mapping?)`);
    }
});
