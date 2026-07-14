// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

/*
 * Controller-semantics tests for createController / mergeExtensionTaskPermissions
 * (the web twin of the Swing SecureAuthorizationController): fail-closed deny
 * with throttled async reload when permissions could not be loaded, composite
 * lookup beating bare lookup, unknown task = allow, putIfAbsent merge, and
 * named regression cases for the subtle Swing-parity mappings.
 *
 * Run: npm test   (from webadmin/; node --test web/)
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import {
    TASK_PERMISSIONS,
    GROUP_TASK_PERMISSIONS,
    RELOAD_BACKOFF_MS,
    mergeExtensionTaskPermissions,
    createController,
} from './task-permission-map.js';

/* ---- helpers ---------------------------------------------------------------- */

// createController reads Date.now() directly; substitute a manual clock and
// restore it when the test ends (the module needs no injection seam for this).
function withFakeNow(t, startMs) {
    const realNow = Date.now;
    let nowMs = startMs;
    Date.now = () => nowMs;
    t.after(() => { Date.now = realNow; });
    return { advance(ms) { nowMs += ms; } };
}

// reload() fires fire-and-forget on the microtask queue; flush it.
const tick = () => new Promise((resolve) => setImmediate(resolve));

// The exported maps are mutable by design (mergeExtensionTaskPermissions).
// Merge for one test only, then remove whatever the merge added so later
// tests in this process see the pristine hardcoded maps.
function mergeScoped(t, mappings) {
    const added = Object.keys(mappings).filter((key) => {
        const map = key.includes('/') ? GROUP_TASK_PERMISSIONS : TASK_PERMISSIONS;
        return !Object.hasOwn(map, key);
    });
    mergeExtensionTaskPermissions(mappings);
    t.after(() => {
        for (const key of added) {
            delete (key.includes('/') ? GROUP_TASK_PERMISSIONS : TASK_PERMISSIONS)[key];
        }
    });
}

const controllerFor = (permissions, reload) =>
    createController({ getPermissions: () => permissions, reload });

/* ---- fail-closed (permissions could not be loaded) --------------------------- */

test('null permissions deny EVERYTHING - mapped, composite and unknown tasks', () => {
    const c = controllerFor(null);
    assert.equal(c.checkTask('view', 'doShowDashboard'), false, 'bare-mapped task');
    assert.equal(c.checkTask('settings_Server', 'doSave'), false, 'composite-mapped task');
    assert.equal(c.checkTask('view', 'doShowSettings'), false, 'deliberately unmapped task');
    assert.equal(c.checkTask('someGroup', 'doSomethingNovel'), false, 'unknown task');
});

test('fail-closed fires reload asynchronously, throttled to RELOAD_BACKOFF_MS', async (t) => {
    const clock = withFakeNow(t, 100000);
    let reloads = 0;
    const c = controllerFor(null, () => { reloads++; });

    assert.equal(c.checkTask('view', 'doShowDashboard'), false);
    assert.equal(reloads, 0, 'reload must be async, never during checkTask');
    await tick();
    assert.equal(reloads, 1);

    // A burst of checks inside the backoff window fires nothing more.
    for (let i = 0; i < 25; i++) c.checkTask('view', 'doShowChannel');
    await tick();
    assert.equal(reloads, 1, 'reload storm inside the backoff window');

    clock.advance(RELOAD_BACKOFF_MS); // exactly the backoff: still throttled (strict >)
    c.checkTask('view', 'doShowChannel');
    await tick();
    assert.equal(reloads, 1, 'boundary is exclusive');

    clock.advance(1);
    c.checkTask('view', 'doShowChannel');
    await tick();
    assert.equal(reloads, 2, 'reload resumes after the backoff elapses');
});

test('fail-closed without a reload dependency, or with a throwing/rejecting one, never throws', async () => {
    assert.equal(controllerFor(undefined).checkTask('view', 'doShowDashboard'), false);

    const throwing = controllerFor(null, () => { throw new Error('boom'); });
    assert.equal(throwing.checkTask('view', 'doShowDashboard'), false);
    await tick();

    const rejecting = controllerFor(null, () => Promise.reject(new Error('boom')));
    assert.equal(rejecting.checkTask('view', 'doShowDashboard'), false);
    await tick(); // an unhandled rejection here would fail the run
});

test('loaded permissions do not trigger reload', async () => {
    let reloads = 0;
    const c = controllerFor(new Set(['viewDashboard']), () => { reloads++; });
    assert.equal(c.checkTask('view', 'doShowDashboard'), true);
    assert.equal(c.checkTask('view', 'doShowChannel'), false);
    await tick();
    assert.equal(reloads, 0);
});

/* ---- lookup semantics --------------------------------------------------------- */

test('unknown task is allowed through (server enforces the real check)', () => {
    const c = controllerFor(new Set()); // empty permission set, load succeeded
    assert.equal(c.checkTask('someGroup', 'doSomethingNovel'), true);
    assert.equal(c.checkTask('user', 'doChangePassword'), true, 'untagged web-only item');
    assert.equal(c.checkTask('view', 'doShowSettings'), true, 'deliberately unmapped nav');
    assert.equal(c.checkTask('other', 'doLogout'), true);
});

test('composite lookup beats bare lookup', (t) => {
    // The pinned live /task-permissions merge adds a bare doRefresh mapping
    // ("View Settings", from the dashboard plugins); the settings tabs' own
    // composite mappings must still win for their groups.
    mergeScoped(t, { doRefresh: 'View Settings' });

    const serverViewer = controllerFor(new Set(['viewServerSettings']));
    assert.equal(serverViewer.checkTask('settings_Server', 'doRefresh'), true,
        'composite mapping grants despite the bare mapping requiring an absent permission');

    const extViewer = controllerFor(new Set(['View Settings']));
    assert.equal(extViewer.checkTask('settings_Server', 'doRefresh'), false,
        'composite mapping denies even though the bare mapping would grant');
    assert.equal(extViewer.checkTask('dashboard_ServerLog', 'doRefresh'), true,
        'groups without a composite mapping fall through to the bare one');
});

test('permission container may be a Set or an array', () => {
    for (const perms of [new Set(['viewChannels']), ['viewChannels']]) {
        const c = controllerFor(perms);
        assert.equal(c.checkTask('channel', 'doRefreshChannels'), true);
        assert.equal(c.checkTask('channel', 'doDeleteChannel'), false);
    }
});

/* ---- mergeExtensionTaskPermissions -------------------------------------------- */

test('merge is putIfAbsent - hardcoded mappings always win', (t) => {
    mergeScoped(t, {
        doDeleteChannel: 'weakPerm', // present -> ignored
        doStart: 'Start / Stop', // present (live pinned shape) -> ignored
        'settings_Server/doSave': 'weakPerm', // present composite -> ignored
        doBrandNewTask: 'somePerm', // absent -> merged bare
        'settings_FooPlugin/doRefresh': 'Foo View', // absent -> merged composite
    });
    assert.equal(TASK_PERMISSIONS.doDeleteChannel, 'manageChannels');
    assert.equal(TASK_PERMISSIONS.doStart, 'startStopChannels');
    assert.equal(GROUP_TASK_PERMISSIONS['settings_Server/doSave'], 'editServerSettings');
    assert.equal(TASK_PERMISSIONS.doBrandNewTask, 'somePerm');
    assert.equal(GROUP_TASK_PERMISSIONS['settings_FooPlugin/doRefresh'], 'Foo View');
});

test('merged keys are routed by shape - "/" means composite, else bare', (t) => {
    mergeScoped(t, { 'settings_FooPlugin/doExportFoo': 'Foo Export', doFooBare: 'Foo Bare' });
    assert.ok(Object.hasOwn(GROUP_TASK_PERMISSIONS, 'settings_FooPlugin/doExportFoo'));
    assert.ok(!Object.hasOwn(TASK_PERMISSIONS, 'settings_FooPlugin/doExportFoo'));
    assert.ok(Object.hasOwn(TASK_PERMISSIONS, 'doFooBare'));
    assert.ok(!Object.hasOwn(GROUP_TASK_PERMISSIONS, 'doFooBare'));

    const c = controllerFor(new Set(['Foo Export']));
    assert.equal(c.checkTask('settings_FooPlugin', 'doExportFoo'), true);
    assert.equal(c.checkTask('anywhere', 'doFooBare'), false);
});

test('merge tolerates null/empty input and skips malformed entries', (t) => {
    const bareBefore = Object.keys(TASK_PERMISSIONS).length;
    const compositeBefore = Object.keys(GROUP_TASK_PERMISSIONS).length;
    mergeExtensionTaskPermissions(null);
    mergeExtensionTaskPermissions(undefined);
    mergeExtensionTaskPermissions({});
    mergeScoped(t, { '': 'perm', doNoPerm: '', doNullPerm: null, doNumberPerm: 42 });
    assert.equal(Object.keys(TASK_PERMISSIONS).length, bareBefore);
    assert.equal(Object.keys(GROUP_TASK_PERMISSIONS).length, compositeBefore);
});

test('merge never touches the prototype ("__proto__" guard)', (t) => {
    // JSON.parse (like the real wire path) creates an OWN "__proto__" key;
    // an object literal would silently set the prototype instead.
    mergeScoped(t, JSON.parse('{"__proto__": "polluted"}'));
    assert.ok(!Object.hasOwn(TASK_PERMISSIONS, '__proto__'));
    assert.equal(Object.getPrototypeOf(TASK_PERMISSIONS), Object.prototype);
    assert.equal({}.polluted, undefined);
});

/* ---- named regression cases (the subtle Swing-parity mappings) ----------------- */

test('doRemoveFilteredMessages needs removeResults, NOT removeMessages', () => {
    const single = controllerFor(new Set(['removeMessages']));
    assert.equal(single.checkTask('message', 'doRemoveMessage'), true);
    assert.equal(single.checkTask('message', 'doRemoveFilteredMessages'), false);

    const filtered = controllerFor(new Set(['removeResults']));
    assert.equal(filtered.checkTask('message', 'doRemoveFilteredMessages'), true);
    assert.equal(filtered.checkTask('message', 'doRemoveMessage'), false);
});

test('message exports need exportMessagesServer, not just viewMessages', () => {
    const viewer = controllerFor(new Set(['viewMessages']));
    assert.equal(viewer.checkTask('message', 'doRefreshMessages'), true);
    assert.equal(viewer.checkTask('message', 'doExportMessages'), false);
    assert.equal(viewer.checkTask('message', 'doExportAttachment'), false);

    const exporter = controllerFor(new Set(['exportMessagesServer']));
    assert.equal(exporter.checkTask('message', 'doExportMessages'), true);
    assert.equal(exporter.checkTask('message', 'doExportAttachment'), true);
});

test('channel-group writes need manageChannels; exports only viewChannelGroups', () => {
    const viewer = controllerFor(new Set(['viewChannelGroups']));
    assert.equal(viewer.checkTask('channelGroup', 'doExportGroup'), true);
    assert.equal(viewer.checkTask('channelGroup', 'doExportAllGroups'), true);
    assert.equal(viewer.checkTask('channelGroup', 'doSaveGroups'), false);
    assert.equal(viewer.checkTask('channelGroup', 'doNewGroup'), false);
    assert.equal(viewer.checkTask('channelGroup', 'doDeleteGroup'), false);

    const manager = controllerFor(new Set(['manageChannels']));
    assert.equal(manager.checkTask('channelGroup', 'doSaveGroups'), true);
    assert.equal(manager.checkTask('channelGroup', 'doAssignChannelToGroup'), true);
    assert.equal(manager.checkTask('channelGroup', 'doExportGroup'), false);
});

test('settings_Role-Based Access Control pair: View Roles / Manage Roles', () => {
    const viewer = controllerFor(new Set(['View Roles']));
    assert.equal(viewer.checkTask('settings_Role-Based Access Control', 'doRefresh'), true);
    assert.equal(viewer.checkTask('settings_Role-Based Access Control', 'doSave'), false);

    const manager = controllerFor(new Set(['Manage Roles']));
    assert.equal(manager.checkTask('settings_Role-Based Access Control', 'doSave'), true);
    assert.equal(manager.checkTask('settings_Role-Based Access Control', 'doRefresh'), false,
        'doRefresh maps to "View Roles" - Manage alone does not imply View');
});
