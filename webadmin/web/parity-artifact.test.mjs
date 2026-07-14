// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

/*
 * Swing-parity artifact test: task-permission-map.json is the shared, diffable
 * form of the task → permission mapping (a Java-side test can assert Swing's
 * SecureAuthorizationController.buildPermissionMaps() against the same file).
 * This test asserts the JS module equals the JSON artifact EXACTLY — values
 * and key order — so the two cannot drift silently. When a mapping changes,
 * change task-permission-map.js, the JSON, and the Swing map together.
 *
 * NOTE: this file must not call mergeExtensionTaskPermissions() — the exported
 * maps are mutable by design, and a merge here would corrupt the comparison.
 * (node --test runs each test file in its own process, so merges performed by
 * controller.test.mjs cannot leak into this one.)
 *
 * Run: npm test   (from webadmin/; node --test web/)
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { TASK_PERMISSIONS, GROUP_TASK_PERMISSIONS } from './task-permission-map.js';

const artifact = JSON.parse(
    readFileSync(new URL('./task-permission-map.json', import.meta.url), 'utf8'));

test('artifact has exactly the two expected top-level objects', () => {
    assert.deepEqual(Object.keys(artifact), ['taskPermissions', 'groupTaskPermissions']);
});

test('taskPermissions equals TASK_PERMISSIONS exactly', () => {
    assert.deepEqual(artifact.taskPermissions, TASK_PERMISSIONS);
    // Key order too — the artifact is generated FROM the JS module, so a
    // regeneration must be byte-diffable, not just semantically equal.
    assert.deepEqual(Object.keys(artifact.taskPermissions), Object.keys(TASK_PERMISSIONS));
});

test('groupTaskPermissions equals GROUP_TASK_PERMISSIONS exactly', () => {
    assert.deepEqual(artifact.groupTaskPermissions, GROUP_TASK_PERMISSIONS);
    assert.deepEqual(Object.keys(artifact.groupTaskPermissions), Object.keys(GROUP_TASK_PERMISSIONS));
});

test('every mapping value is a non-empty permission string', () => {
    for (const [map, name] of [
        [artifact.taskPermissions, 'taskPermissions'],
        [artifact.groupTaskPermissions, 'groupTaskPermissions'],
    ]) {
        for (const [task, permission] of Object.entries(map)) {
            assert.ok(typeof permission === 'string' && permission.length > 0,
                `${name}["${task}"] must be a non-empty string`);
        }
    }
});
