// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

import test from 'node:test';
import assert from 'node:assert/strict';
import { registerAuthorization, MAX_AUTOMATIC_RETRIES } from './authorization-session.js';
import { GROUP_TASK_PERMISSIONS, RELOAD_BACKOFF_MS } from './task-permission-map.js';

const flush = () => new Promise(resolve => setImmediate(resolve));
const deferred = () => {
    let resolve, reject;
    const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
    return { promise, resolve, reject };
};

function harness(t) {
    t.mock.method(console, 'warn', () => {});
    let now = 100_000;
    t.mock.method(Date, 'now', () => now);
    const state = { user: { id: 7, username: 'viewer' }, webPlugins: [] };
    const listeners = new Map();
    const changes = [];
    const registrations = [];
    const calls = { permissions: 0, tasks: 0 };
    let permissions = async () => new Set(['View Roles']);
    let tasks = async () => ({});
    const roleCalls = [];
    let userRole = async () => ({ isAdmin: false });
    const platform = {
        store: {
            getState: key => state[key],
            setState(key, value) {
                state[key] = value;
                changes.push(key);
                for (const listener of [...(listeners.get(key) ?? [])]) listener(value);
            },
            subscribe(key, listener) {
                const group = listeners.get(key) ?? new Set();
                listeners.set(key, group);
                group.add(listener);
                return () => group.delete(listener);
            }
        },
        setAuthorizationController(controller) { platform.controller = controller; }
    };
    const api = {
        getMyPermissions() { calls.permissions++; return permissions(); },
        getExtensionTaskPermissions() { calls.tasks++; return tasks(); },
        getUserRole(userId) { roleCalls.push(userId); return userRole(userId); }
    };
    t.after(() => platform.store.setState('user', null));
    return {
        platform, api, calls, registrations, changes, roleCalls,
        register: () => registerAuthorization(platform, api, () => registrations.push('Roles')),
        permissions: fn => { permissions = fn; },
        tasks: fn => { tasks = fn; },
        userRole: fn => { userRole = fn; },
        retry: () => {
            now += RELOAD_BACKOFF_MS + 1;
            assert.equal(platform.controller.checkTask('settings_Role-Based Access Control', 'doRefresh'), false);
        },
        setUser: user => platform.store.setState('user', user)
    };
}

for (const prerequisite of ['permissions', 'tasks']) {
    test(`Roles registers once after initial ${prerequisite} failure; simultaneous retries share one request`, async t => {
        const h = harness(t);
        h[prerequisite](async () => { throw new Error('unavailable'); });
        await h.register();
        assert.deepEqual(h.registrations, []);
        const originalPlugins = h.platform.store.getState('webPlugins');
        const perms = deferred(), tasks = deferred();
        h.permissions(() => perms.promise);
        h.tasks(() => tasks.promise);
        h.retry();
        await flush();
        h.retry(); // even after the backoff expires, one request remains in flight
        await flush();
        assert.deepEqual(h.calls, { permissions: 2, tasks: 2 });
        perms.resolve(new Set(['View Roles']));
        await flush();
        assert.deepEqual(h.registrations, [], 'both prerequisites must succeed');
        tasks.resolve({});
        await flush();
        assert.deepEqual(h.registrations, ['Roles']);
        assert.equal(h.platform.controller.checkTask('settings_Role-Based Access Control', 'doRefresh'), true);
        assert.equal(h.platform.controller.checkTask('settings_Role-Based Access Control', 'doSave'), false);
        assert.deepEqual(h.changes, ['webPlugins'], 'one successful recovery publishes one notification');
        assert.notEqual(h.platform.store.getState('webPlugins'), originalPlugins,
            'React external-store subscribers require a fresh snapshot reference');
        await flush();
        assert.deepEqual(h.calls, { permissions: 2, tasks: 2 }, 'healthy checks do not reload');
    });
}

test('healthy initial registration exposes Roles without a retry', async t => {
    const h = harness(t);
    await h.register();
    assert.deepEqual(h.registrations, ['Roles']);
    assert.equal(h.platform.controller.checkTask('settings_Role-Based Access Control', 'doRefresh'), true);
    assert.deepEqual(h.calls, { permissions: 1, tasks: 1 });
});

test('recovery with an empty or Manage-only permission set never registers Roles', async t => {
    for (const recovered of [new Set(), new Set(['Manage Roles'])]) {
        const h = harness(t);
        h.permissions(async () => { throw new Error('unavailable'); });
        await h.register();
        h.permissions(async () => recovered);
        h.retry();
        await flush();
        assert.deepEqual(h.registrations, []);
        assert.equal(h.platform.controller.checkTask('settings_Role-Based Access Control', 'doRefresh'), false);
        assert.deepEqual(h.calls, { permissions: 2, tasks: 2 });
        assert.deepEqual(h.changes, ['webPlugins']);
    }
});

test('a second failed prerequisite keeps the whole snapshot closed until both recover', async t => {
    const h = harness(t);
    h.permissions(async () => { throw new Error('permissions down'); });
    await h.register();
    h.permissions(async () => new Set(['View Roles']));
    h.tasks(async () => { throw new Error('mappings down'); });
    h.retry();
    await flush();
    assert.deepEqual(h.registrations, []);
    assert.deepEqual(h.changes, []);
    h.tasks(async () => ({}));
    h.retry();
    await flush();
    assert.deepEqual(h.registrations, ['Roles']);
});

for (const transition of ['logout', 'different user', 'logout then same user']) {
    test(`recovery response after ${transition} cannot publish permissions, mappings, or Roles`, async t => {
        const h = harness(t);
        h.permissions(async () => { throw new Error('unavailable'); });
        await h.register();
        const perms = deferred();
        const mapping = `settings_Stale ${transition}/doRefresh`;
        h.permissions(() => perms.promise);
        h.tasks(async () => ({ [mapping]: 'View Roles' }));
        h.retry();
        await flush();
        h.setUser(transition === 'different user' ? { id: 8 } : null);
        if (transition === 'logout then same user') h.setUser({ id: 7 });
        perms.resolve(new Set(['View Roles']));
        await flush();
        assert.deepEqual(h.registrations, []);
        assert.equal(Object.hasOwn(GROUP_TASK_PERMISSIONS, mapping), false);
        assert.equal(h.changes.includes('webPlugins'), false);
        h.retry();
        await flush();
        assert.deepEqual(h.calls, { permissions: 2, tasks: 2 }, 'expired registration never retries');
    });
}

test('initial response after logout cannot install a stale controller', async t => {
    const h = harness(t);
    const perms = deferred();
    h.permissions(() => perms.promise);
    const pending = h.register();
    h.setUser(null);
    perms.resolve(new Set(['View Roles']));
    await pending;
    assert.equal(h.platform.controller, undefined);
    assert.deepEqual(h.registrations, []);
});

test('loaded controller denies after logout; a same-user profile update retains access', async t => {
    const h = harness(t);
    await h.register();
    h.setUser({ id: 7, username: 'renamed' });
    assert.equal(h.platform.controller.checkTask('settings_Role-Based Access Control', 'doRefresh'), true);
    h.setUser(null);
    h.setUser({ id: 7 });
    h.retry();
    await flush();
    assert.deepEqual(h.calls, { permissions: 1, tasks: 1 });
});

test('a failed snapshot retries automatically without rendering; success cancels further retries', async t => {
    t.mock.timers.enable({ apis: ['setTimeout'] });
    const h = harness(t);
    h.permissions(async () => { throw new Error('unavailable'); });
    await h.register();
    t.mock.timers.tick(RELOAD_BACKOFF_MS);
    await flush();
    assert.deepEqual(h.calls, { permissions: 2, tasks: 2 });
    assert.deepEqual(h.registrations, []);
    h.permissions(async () => new Set(['View Roles']));
    t.mock.timers.tick(RELOAD_BACKOFF_MS);
    await flush();
    assert.deepEqual(h.registrations, ['Roles']);
    assert.deepEqual(h.changes, ['webPlugins']);
    t.mock.timers.tick(RELOAD_BACKOFF_MS * 4);
    await flush();
    assert.deepEqual(h.calls, { permissions: 3, tasks: 3 });
});

test('logout cancels an automatic retry, even after the same user signs back in', async t => {
    t.mock.timers.enable({ apis: ['setTimeout'] });
    const h = harness(t);
    h.permissions(async () => { throw new Error('unavailable'); });
    await h.register();
    h.setUser(null);
    h.setUser({ id: 7 });
    t.mock.timers.tick(RELOAD_BACKOFF_MS * 4);
    await flush();
    assert.deepEqual(h.calls, { permissions: 1, tasks: 1 });
});

test('automatic retries exhaust their budget; later lazy checks can still recover without restarting timers', async t => {
    t.mock.timers.enable({ apis: ['setTimeout'] });
    const h = harness(t);
    h.permissions(async () => { throw new Error('unavailable'); });
    await h.register();
    for (let attempt = 0; attempt < MAX_AUTOMATIC_RETRIES; attempt++) {
        t.mock.timers.tick(RELOAD_BACKOFF_MS);
        await flush();
    }
    assert.deepEqual(h.calls, { permissions: 4, tasks: 4 }, 'initial fetch plus three automatic attempts');
    t.mock.timers.tick(RELOAD_BACKOFF_MS * 100);
    await flush();
    assert.deepEqual(h.calls, { permissions: 4, tasks: 4 }, 'idle page stops issuing permission requests');
    assert.deepEqual(h.registrations, []);
    assert.deepEqual(h.changes, []);

    h.retry(); // A render-triggered retry still works after the automatic budget.
    await flush();
    assert.deepEqual(h.calls, { permissions: 5, tasks: 5 });
    t.mock.timers.tick(RELOAD_BACKOFF_MS * 100);
    await flush();
    assert.deepEqual(h.calls, { permissions: 5, tasks: 5 }, 'lazy failure does not restart automatic polling');

    h.permissions(async () => new Set(['View Roles']));
    h.retry();
    await flush();
    assert.deepEqual(h.calls, { permissions: 6, tasks: 6 });
    assert.deepEqual(h.registrations, ['Roles']);
    assert.deepEqual(h.changes, ['webPlugins']);
    assert.equal(h.platform.controller.checkTask('settings_Role-Based Access Control', 'doRefresh'), true);
});

/* ---- admin flag for Export Roles and Import Roles ------------------------------ */

const EXPORT_TASK = ['settings_Role-Based Access Control', 'doExportRoles'];
const IMPORT_TASK = ['settings_Role-Based Access Control', 'doImportRoles'];

test('a View Roles holder in the admin role sees both tasks; the role is read with the current user id', async t => {
    const h = harness(t);
    h.userRole(async () => ({ isAdmin: true }));
    await h.register();
    assert.deepEqual(h.roleCalls, [7]);
    assert.equal(h.platform.controller.checkTask(...EXPORT_TASK), true);
    assert.equal(h.platform.controller.checkTask(...IMPORT_TASK), true);
});

test('a View Roles holder in another role sees neither task', async t => {
    const h = harness(t);
    await h.register();
    assert.deepEqual(h.roleCalls, [7]);
    assert.equal(h.platform.controller.checkTask(...EXPORT_TASK), false);
    assert.equal(h.platform.controller.checkTask(...IMPORT_TASK), false);
});

test('without View Roles the role is never read and the tasks stay hidden', async t => {
    const h = harness(t);
    h.permissions(async () => new Set(['viewChannels', 'Manage Roles']));
    await h.register();
    assert.deepEqual(h.roleCalls, []);
    assert.equal(h.platform.controller.checkTask(...EXPORT_TASK), false);
});

test('a failed or empty role read means not an admin and does not fail the permission load', async t => {
    for (const read of [async () => { throw new Error('403'); }, async () => null]) {
        const h = harness(t);
        h.userRole(read);
        await h.register();
        assert.deepEqual(h.registrations, ['Roles'], 'the permission load still counts');
        assert.equal(h.platform.controller.checkTask('settings_Role-Based Access Control', 'doRefresh'), true);
        assert.equal(h.platform.controller.checkTask(...EXPORT_TASK), false);
        assert.deepEqual(h.calls, { permissions: 1, tasks: 1 });
    }
});

test('the admin flag is read again with a recovered load', async t => {
    const h = harness(t);
    h.permissions(async () => { throw new Error('unavailable'); });
    await h.register();
    assert.deepEqual(h.roleCalls, [], 'no permissions, no role read');
    h.permissions(async () => new Set(['View Roles']));
    h.userRole(async () => ({ isAdmin: true }));
    h.retry();
    await flush();
    assert.equal(h.platform.controller.checkTask(...EXPORT_TASK), true);
});

test('a role answer arriving after logout cannot make anyone an admin', async t => {
    const h = harness(t);
    const role = deferred();
    h.userRole(() => role.promise);
    const pending = h.register();
    await flush();
    h.setUser(null);
    role.resolve({ isAdmin: true });
    await pending;
    assert.equal(h.platform.controller, undefined, 'no controller from an ended session');
    assert.deepEqual(h.registrations, []);
});

test('the admin flag is dropped when the user changes', async t => {
    const h = harness(t);
    h.userRole(async () => ({ isAdmin: true }));
    await h.register();
    assert.equal(h.platform.controller.checkTask(...EXPORT_TASK), true);
    h.setUser({ id: 8 });
    assert.equal(h.platform.controller.checkTask(...EXPORT_TASK), false);
    h.setUser({ id: 7 });
    assert.equal(h.platform.controller.checkTask(...EXPORT_TASK), false, 'an ended session never comes back');
});
