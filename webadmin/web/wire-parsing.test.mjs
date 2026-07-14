// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

/*
 * Wire-parsing tests for rbac-api.js against the engine's XStream JSON shapes.
 * The fixture strings are VERBATIM live-engine captures (see
 * ../e2e-fixtures-notes.md, pinned 2026-07-14) plus the documented XStream
 * degenerate forms (singleton collapse, '' for an empty collection).
 *
 * The pure normalizers (stringSet/mapEntries/normalizeRole) receive values
 * AFTER the web host's JSON pipeline has stripped the single root key, so the
 * unwrap/asList below are vendored VERBATIM from the host
 * (oie-web-client web-administrator/client/core/api.js) to exercise the exact
 * pipeline the plugin runs behind.
 *
 * Run: npm test   (from webadmin/; node --test web/)
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { makeApi, stringSet, mapEntries, normalizeRole, roleXml } from './rbac-api.js';

/* ---- host JSON pipeline, vendored verbatim from client/core/api.js ---------- */

function unwrap(parsed) {
    // XStream JSON puts the payload under a single root key.
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        const keys = Object.keys(parsed);
        if (keys.length === 1) return parsed[keys[0]];
    }
    return parsed;
}

/* When the engine returns a singleton or missing list, normalize to an array.
   XStream JSON renders one-element collections as a bare object, and classes
   without an @XStreamAlias use their fully-qualified name as the wrapper key
   (e.g. {"list":{"com.mirth...ServerLogItem":[...]}}). */
function asList(value, key) {
    if (value === null || value === undefined || value === '') return [];
    if (key !== undefined && value && typeof value === 'object' && !Array.isArray(value)) {
        if (value[key] !== undefined) {
            value = value[key];
        } else {
            const keys = Object.keys(value).filter(k => !k.startsWith('@'));
            if (keys.length === 1) {
                const lastSegment = keys[0].split('.').pop().toLowerCase();
                // Unwrap when the lone key is the FQCN form of the expected
                // alias, or when it plainly holds the array we asked for.
                if (lastSegment === key.toLowerCase() || Array.isArray(value[keys[0]])) {
                    value = value[keys[0]];
                }
            }
        }
        if (value === null || value === undefined || value === '') return [];
    }
    return Array.isArray(value) ? value : [value];
}

// A fake platform.api: GET answers unwrap(JSON.parse(fixture)) exactly like
// the host's parseBody does for JSON bodies (null = empty body / 204).
function fakeApiFor(routes) {
    return {
        asList,
        get: async (path) => {
            assert.ok(Object.hasOwn(routes, path), `unexpected GET ${path}`);
            const body = routes[path];
            return body == null ? null : unwrap(JSON.parse(body));
        },
    };
}

/* ---- verbatim live captures (e2e-fixtures-notes.md) -------------------------- */

const WIRE_MY_PERMISSIONS = '{"linked-hash-set":{"string":["viewAlerts","manageAlerts","viewDashboard","viewChannels","viewChannelGroups","manageChannels","clearStatistics","startStopChannels","deployUndeployChannels","viewCodeTemplates","manageCodeTemplates","viewGlobalScripts","editGlobalScripts","viewMessages","removeMessages","removeResults","removeAllMessages","processMessages","reprocessMessages","reprocessResults","importMessages","exportMessagesServer","viewTags","manageTags","viewEvents","removeEvents","manageUsers","manageExtensions","backupServerConfiguration","restoreServerConfiguration","viewServerSettings","editServerSettings","clearLifetimeStats","sendTestEmail","viewConfigurationMap","editConfigurationMap","editDatabaseDrivers","viewDatabaseTasks","manageDatabaseTasks","viewResources","editResources","reloadResources","Manage Roles","View Thread Viewer","View Roles","Save Settings","View Global Maps","View Connection Status","Start / Stop","View Settings","View Server Log"]}}';

const WIRE_ROLES_SINGLETON = '{"list":{"com.diridium.rbac.Role":{"id":1,"name":"Administrator","description":"Full access to all operations and channels","permissions":{"string":["manageExtensions","viewAlerts","exportMessagesServer","deployUndeployChannels","restoreServerConfiguration","manageChannels","processMessages","editResources","sendTestEmail","viewGlobalScripts","reloadResources","removeAllMessages","viewConfigurationMap","viewMessages","viewTags","startStopChannels","viewDatabaseTasks","removeMessages","reprocessResults","viewCodeTemplates","manageAlerts","viewResources","clearLifetimeStats","clearStatistics","viewChannels","backupServerConfiguration","editConfigurationMap","editServerSettings","manageCodeTemplates","manageDatabaseTasks","removeEvents","viewChannelGroups","viewEvents","viewServerSettings","manageUsers","viewDashboard","reprocessMessages","manageTags","importMessages","editDatabaseDrivers","editGlobalScripts","removeResults"]},"channelIds":null,"isAdmin":true}}}';

const WIRE_USER_ROLE = '{"com.diridium.rbac.Role":{"id":1,"name":"Administrator","description":"Full access to all operations and channels","permissions":{"string":["manageExtensions","viewAlerts","exportMessagesServer","deployUndeployChannels","restoreServerConfiguration","manageChannels","processMessages","editResources","sendTestEmail","viewGlobalScripts","reloadResources","removeAllMessages","viewConfigurationMap","viewMessages","viewTags","startStopChannels","viewDatabaseTasks","removeMessages","reprocessResults","viewCodeTemplates","manageAlerts","viewResources","clearLifetimeStats","clearStatistics","viewChannels","backupServerConfiguration","editConfigurationMap","editServerSettings","manageCodeTemplates","manageDatabaseTasks","removeEvents","viewChannelGroups","viewEvents","viewServerSettings","manageUsers","viewDashboard","reprocessMessages","manageTags","importMessages","editDatabaseDrivers","editGlobalScripts","removeResults"]},"channelIds":null,"isAdmin":true}}';

const WIRE_TASK_PERMISSIONS = '{"linked-hash-map":{"entry":[{"string":["doSave","Save Settings"]},{"string":["doStop","Start / Stop"]},{"string":["doStart","Start / Stop"]},{"string":["doRefresh","View Settings"]}]}}';

/* ---- stringSet: Set<String> shapes -------------------------------------------- */

test('stringSet parses the pinned linked-hash-set my-permissions shape', () => {
    const inner = unwrap(JSON.parse(WIRE_MY_PERMISSIONS));
    const wireItems = JSON.parse(WIRE_MY_PERMISSIONS)['linked-hash-set'].string;
    const set = stringSet(inner);
    assert.equal(set.size, wireItems.length, 'no items lost or duplicated');
    assert.ok(set.has('viewDashboard'));
    assert.ok(set.has('View Roles'), 'extension permissions with spaces survive');
    assert.ok(set.has('Start / Stop'));
    assert.ok(!set.has('viewRoles'));
});

test('stringSet parses a singleton set - {"set":{"string":"one"}}', () => {
    const set = stringSet(unwrap(JSON.parse('{"set":{"string":"one"}}')));
    assert.deepEqual([...set], ['one']);
});

test('stringSet parses an empty set - {"linked-hash-set":""}', () => {
    const set = stringSet(unwrap(JSON.parse('{"linked-hash-set":""}')));
    assert.equal(set.size, 0);
});

test('stringSet tolerates null/undefined/bare values', () => {
    assert.equal(stringSet(null).size, 0);
    assert.equal(stringSet(undefined).size, 0);
    assert.equal(stringSet('').size, 0);
    assert.deepEqual([...stringSet(['a', 'b'])], ['a', 'b'], 'bare array tolerated');
    assert.deepEqual([...stringSet('x')], ['x'], 'bare string tolerated');
});

/* ---- roles list: FQCN root + singleton collapse -------------------------------- */

test('getRoles parses the pinned singleton FQCN roles list (bare object, not array)', async () => {
    const rbac = makeApi(fakeApiFor({ '/extensions/rbac/roles': WIRE_ROLES_SINGLETON }));
    const roles = await rbac.getRoles();
    assert.equal(roles.length, 1);
    const role = roles[0];
    assert.equal(role.id, 1);
    assert.equal(role.name, 'Administrator');
    assert.equal(role.description, 'Full access to all operations and channels');
    assert.equal(role.isAdmin, true);
    assert.equal(role.permissions.size, 42);
    assert.ok(role.permissions.has('removeResults'));
    assert.ok(role.channelIds instanceof Set);
    assert.equal(role.channelIds.size, 0, '"channelIds":null (unrestricted) -> empty Set');
});

test('getRoles parses a multi-role FQCN array list', async () => {
    const two = '{"list":{"com.diridium.rbac.Role":['
        + '{"id":1,"name":"Administrator","description":"","permissions":{"string":["manageUsers"]},"channelIds":null,"isAdmin":true},'
        + '{"id":2,"name":"Read Only","description":"ro","permissions":{"string":"viewDashboard"},"channelIds":{"string":["abc-123"]},"isAdmin":false}'
        + ']}}';
    const rbac = makeApi(fakeApiFor({ '/extensions/rbac/roles': two }));
    const roles = await rbac.getRoles();
    assert.equal(roles.length, 2);
    assert.deepEqual([...roles[1].permissions], ['viewDashboard'], 'singleton permissions Set');
    assert.deepEqual([...roles[1].channelIds], ['abc-123']);
    assert.equal(roles[1].isAdmin, false);
});

test('getRoles falls back to an aliased "role" array root (schi precedent)', async () => {
    const aliased = '{"list":{"role":[{"id":7,"name":"R","description":"","permissions":"","channelIds":"","isAdmin":false}]}}';
    const rbac = makeApi(fakeApiFor({ '/extensions/rbac/roles': aliased }));
    const roles = await rbac.getRoles();
    assert.equal(roles.length, 1);
    assert.equal(roles[0].id, 7);
    assert.equal(roles[0].permissions.size, 0, '"" (empty XStream set) -> empty Set');
});

test('getRoles answers [] for an empty list', async () => {
    const rbac = makeApi(fakeApiFor({ '/extensions/rbac/roles': '{"list":""}' }));
    assert.deepEqual(await rbac.getRoles(), []);
});

/* ---- single role: FQCN root / unassigned user ---------------------------------- */

test('getUserRole parses the pinned single-Role FQCN root', async () => {
    const rbac = makeApi(fakeApiFor({ '/extensions/rbac/users/3/role': WIRE_USER_ROLE }));
    const role = await rbac.getUserRole(3);
    assert.equal(role.name, 'Administrator');
    assert.equal(role.isAdmin, true);
    assert.equal(role.permissions.size, 42);
});

test('getUserRole answers null for an unassigned user (204 / empty body)', async () => {
    const rbac = makeApi(fakeApiFor({ '/extensions/rbac/users/9/role': null }));
    assert.equal(await rbac.getUserRole(9), null);
});

/* ---- task-permissions: Map<String,String> entry pairs --------------------------- */

test('getExtensionTaskPermissions parses the pinned linked-hash-map entry pairs', async () => {
    const rbac = makeApi(fakeApiFor({ '/extensions/rbac/task-permissions': WIRE_TASK_PERMISSIONS }));
    assert.deepEqual(await rbac.getExtensionTaskPermissions(), {
        doSave: 'Save Settings',
        doStop: 'Start / Stop',
        doStart: 'Start / Stop',
        doRefresh: 'View Settings',
    });
});

test('mapEntries handles the singleton entry collapse', () => {
    const inner = unwrap(JSON.parse('{"linked-hash-map":{"entry":{"string":["doSave","Save Settings"]}}}'));
    assert.deepEqual(mapEntries(inner), [['doSave', 'Save Settings']]);
});

test('mapEntries handles empty / null / non-object maps', () => {
    assert.deepEqual(mapEntries(unwrap(JSON.parse('{"linked-hash-map":""}'))), []);
    assert.deepEqual(mapEntries(null), []);
    assert.deepEqual(mapEntries(''), []);
});

test('mapEntries handles split-typed and plain-object entries', () => {
    assert.deepEqual(
        mapEntries({ entry: [{ string: 'viewImage', boolean: true }] }),
        [['viewImage', 'true']],
        'values occasionally split as {string:k, <type>:v}');
    assert.deepEqual(
        mapEntries({ doSave: 'Save Settings', '@class': 'ignored' }),
        [['doSave', 'Save Settings']],
        'plain-object form, @-attributes skipped');
});

/* ---- normalizeRole edges --------------------------------------------------------- */

test('normalizeRole coerces missing/degenerate fields', () => {
    assert.equal(normalizeRole(null), null);
    assert.equal(normalizeRole('x'), null);

    const bare = normalizeRole({});
    assert.deepEqual(
        { ...bare, permissions: [...bare.permissions], channelIds: [...bare.channelIds] },
        { id: null, name: '', description: '', permissions: [], channelIds: [], isAdmin: false });

    assert.equal(normalizeRole({ id: '' }).id, null);
    assert.equal(normalizeRole({ id: '5' }).id, 5);
    assert.equal(normalizeRole({ isAdmin: 'true' }).isAdmin, true, 'host XML-fallback parser shape');
    assert.equal(normalizeRole({ isAdmin: 'false' }).isAdmin, false);
});

/* ---- roleXml: the XStream XML write path ------------------------------------------ */

test('roleXml create omits <id>; update includes it', () => {
    const role = { id: 3, name: 'RO', description: 'd', permissions: ['a'], channelIds: [], isAdmin: false };
    assert.equal(
        roleXml(role),
        '<com.diridium.rbac.Role><name>RO</name><description>d</description>'
        + '<permissions><string>a</string></permissions><channelIds></channelIds>'
        + '<isAdmin>false</isAdmin></com.diridium.rbac.Role>');
    assert.ok(roleXml(role, { includeId: true }).startsWith('<com.diridium.rbac.Role><id>3</id><name>'));
});

test('roleXml escapes markup in text fields', () => {
    const xml = roleXml({ name: 'A & B <x>', description: '</description>', permissions: ['p&q'], channelIds: [] });
    assert.ok(xml.includes('<name>A &amp; B &lt;x&gt;</name>'));
    assert.ok(xml.includes('<description>&lt;/description&gt;</description>'));
    assert.ok(xml.includes('<string>p&amp;q</string>'));
});
