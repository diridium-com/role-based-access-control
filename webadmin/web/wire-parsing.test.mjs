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
import { makeApi, stringSet, mapEntries, normalizeRole, roleXml, normalizeImportResult } from './rbac-api.js';

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

/* ---- role import: verbatim captures (wire-probe-2.log, rbac 1.2.0 on OIE 4.7.0) ---- */

// preview, two rows (one new, one unchanged)
const WIRE_IMPORT_PREVIEW_TWO_ROWS =
    '{"com.diridium.rbac.RoleImportResult":{"importable":true,"formatVersion":1,"sourceRbacVersion":"1.2.0","sourceEngineVersion":"4.7.0","applyChannels":true,"matchChannelsByName":false,"applied":false,"planToken":"5ba1268962581bdbd0ddb491d164bea2910cd8c2b77dfc0d71fe1e0346647395","rows":{"com.diridium.rbac.RoleImportRow":[{"index":0,"name":"probe lab","action":"CREATE","droppedPermissions":null,"unmatchedChannels":null,"matchedChannelCount":2,"channels":"FROM_FILE","descriptionChanged":false,"addedPermissions":null,"removedPermissions":null,"addedChannels":null,"removedChannels":null},{"index":1,"name":"probe everyone","action":"UNCHANGED","droppedPermissions":null,"unmatchedChannels":null,"matchedChannelCount":0,"channels":"FROM_FILE","descriptionChanged":false,"addedPermissions":null,"removedPermissions":null,"addedChannels":null,"removedChannels":null}]},"channelNameMatches":null}}';

// preview, one match by name, matching off
const WIRE_IMPORT_NAME_MATCH_OFF =
    '{"com.diridium.rbac.RoleImportResult":{"importable":true,"formatVersion":1,"sourceRbacVersion":"e2e","sourceEngineVersion":"e2e","applyChannels":true,"matchChannelsByName":false,"applied":false,"planToken":"43d8bc80c396901a0a702aa5d8f18dd57477abf2dea2de533a00c5ebfc897146","rows":{"com.diridium.rbac.RoleImportRow":{"index":0,"name":"probe moved one","action":"SKIP","reason":"None of its 1 channels exist on this engine, and a role with no channels sees every channel. Matching channels by name finds 1 of them.","droppedPermissions":null,"unmatchedChannels":{"string":"probe one (8163af3f-7ed2-4a0c-b326-34830263c504)"},"matchedChannelCount":0,"channels":"FROM_FILE","descriptionChanged":false,"addedPermissions":null,"removedPermissions":null,"addedChannels":null,"removedChannels":null}},"channelNameMatches":{"com.diridium.rbac.ChannelNameMatch":{"name":"probe one","fileChannelId":"8163af3f-7ed2-4a0c-b326-34830263c504","channelId":"4c468ff3-0cf7-4e8b-88e7-a7d8a3b538bf"}}}}';

// preview, one match by name, matching on
const WIRE_IMPORT_NAME_MATCH_ONE_ON =
    '{"com.diridium.rbac.RoleImportResult":{"importable":true,"formatVersion":1,"sourceRbacVersion":"e2e","sourceEngineVersion":"e2e","applyChannels":true,"matchChannelsByName":true,"applied":false,"planToken":"b7fdd89af2d6b418cb36fe1ebeb910f9a47b18458cf7b03832896537756eaf45","rows":{"com.diridium.rbac.RoleImportRow":{"index":0,"name":"probe moved one","action":"CREATE","droppedPermissions":null,"unmatchedChannels":null,"matchedChannelCount":1,"channels":"FROM_FILE","descriptionChanged":false,"addedPermissions":null,"removedPermissions":null,"addedChannels":null,"removedChannels":null}},"channelNameMatches":{"com.diridium.rbac.ChannelNameMatch":{"name":"probe one","fileChannelId":"8163af3f-7ed2-4a0c-b326-34830263c504","channelId":"4c468ff3-0cf7-4e8b-88e7-a7d8a3b538bf"}}}}';

// preview, two matches by name, matching on
const WIRE_IMPORT_NAME_MATCH_TWO_ON =
    '{"com.diridium.rbac.RoleImportResult":{"importable":true,"formatVersion":1,"sourceRbacVersion":"e2e","sourceEngineVersion":"e2e","applyChannels":true,"matchChannelsByName":true,"applied":false,"planToken":"8983436faf4e3d69112384f89dc779805862880e6cf032c82eacd4406cd6eeae","rows":{"com.diridium.rbac.RoleImportRow":{"index":0,"name":"probe moved two","action":"CREATE","droppedPermissions":null,"unmatchedChannels":null,"matchedChannelCount":2,"channels":"FROM_FILE","descriptionChanged":false,"addedPermissions":null,"removedPermissions":null,"addedChannels":null,"removedChannels":null}},"channelNameMatches":{"com.diridium.rbac.ChannelNameMatch":[{"name":"probe one","fileChannelId":"e0472e0d-bf15-436c-931b-679d9fa2954c","channelId":"4c468ff3-0cf7-4e8b-88e7-a7d8a3b538bf"},{"name":"probe two","fileChannelId":"4d20b4dd-0fc5-4989-9131-c3555229abba","channelId":"ee366a8b-755b-4f73-9f1b-abe1801cc121"}]}}}';

// preview, overwrite adding one permission
const WIRE_IMPORT_OVERWRITE_ADD_ONE =
    '{"com.diridium.rbac.RoleImportResult":{"importable":true,"formatVersion":1,"sourceRbacVersion":"e2e","sourceEngineVersion":"e2e","applyChannels":true,"matchChannelsByName":false,"applied":false,"planToken":"10069c37ca0d76cf44a58d7b7c08d61fc204c1ece0a87a958376134fb9c290ed","rows":{"com.diridium.rbac.RoleImportRow":{"index":0,"name":"probe everyone","action":"OVERWRITE","droppedPermissions":null,"unmatchedChannels":null,"matchedChannelCount":0,"channels":"FROM_FILE","descriptionChanged":false,"addedPermissions":{"string":"viewDashboard"},"removedPermissions":null,"addedChannels":null,"removedChannels":null}},"channelNameMatches":null}}';

// preview, overwrite adding two and removing one, restricting to two channels
const WIRE_IMPORT_OVERWRITE_ADD_TWO_REMOVE_ONE =
    '{"com.diridium.rbac.RoleImportResult":{"importable":true,"formatVersion":1,"sourceRbacVersion":"e2e","sourceEngineVersion":"e2e","applyChannels":true,"matchChannelsByName":false,"applied":false,"planToken":"16cb921869f3b48d62bee84d3513f1aec63a63f9a2e737a8ca12df89c626c3fe","rows":{"com.diridium.rbac.RoleImportRow":{"index":0,"name":"probe everyone","action":"OVERWRITE","reason":"Restricted to 2 channel(s) after the import; here it sees every channel.","droppedPermissions":null,"unmatchedChannels":null,"matchedChannelCount":2,"channels":"FROM_FILE","descriptionChanged":false,"addedPermissions":{"string":["viewAlerts","viewDashboard"]},"removedPermissions":{"string":"viewChannels"},"addedChannels":null,"removedChannels":null}},"channelNameMatches":null}}';

// preview, channels not applied
const WIRE_IMPORT_CHANNELS_NOT_APPLIED =
    '{"com.diridium.rbac.RoleImportResult":{"importable":true,"formatVersion":1,"sourceRbacVersion":"e2e","sourceEngineVersion":"e2e","applyChannels":false,"matchChannelsByName":false,"applied":false,"planToken":"ba9176b9ceb5446084c249f9a6404f4cdac02fe6ed04704b4b8b3fa03befd7d3","rows":{"com.diridium.rbac.RoleImportRow":{"index":0,"name":"probe moved one","action":"CREATE","reason":"Sees every channel here; where it was exported it was restricted to 1 channel(s). Set its channels before assigning users.","droppedPermissions":null,"unmatchedChannels":null,"matchedChannelCount":0,"channels":"EVERY_CHANNEL","descriptionChanged":false,"addedPermissions":null,"removedPermissions":null,"addedChannels":null,"removedChannels":null}},"channelNameMatches":null}}';

// preview, refused file
const WIRE_IMPORT_REFUSED =
    '{"com.diridium.rbac.RoleImportResult":{"importable":false,"refusal":"This file is format 2, written by rbac 9. This rbac reads format 1.","applyChannels":true,"matchChannelsByName":false,"applied":false,"rows":null,"channelNameMatches":null}}';

// apply, one row written
const WIRE_IMPORT_APPLIED =
    '{"com.diridium.rbac.RoleImportResult":{"importable":true,"formatVersion":1,"sourceRbacVersion":"1.2.0","sourceEngineVersion":"4.7.0","applyChannels":true,"matchChannelsByName":false,"applied":true,"planToken":"5ba1268962581bdbd0ddb491d164bea2910cd8c2b77dfc0d71fe1e0346647395","rows":{"com.diridium.rbac.RoleImportRow":{"index":0,"name":"probe lab","action":"CREATE","droppedPermissions":null,"unmatchedChannels":null,"matchedChannelCount":2,"channels":"FROM_FILE","descriptionChanged":false,"addedPermissions":null,"removedPermissions":null,"addedChannels":null,"removedChannels":null}},"channelNameMatches":null}}';

const importResult = (wire) => normalizeImportResult(unwrap(JSON.parse(wire)));

// Every list is an array of plain strings, every version a string: a quirk that
// leaks through (null, a bare string, a bare object, a number) fails here.
function assertPlainRow(row) {
    for (const key of ['droppedPermissions', 'unmatchedChannels', 'addedPermissions',
        'removedPermissions', 'addedChannels', 'removedChannels']) {
        assert.ok(Array.isArray(row[key]), `${key} is an array`);
        for (const v of row[key]) assert.equal(typeof v, 'string');
    }
    assert.equal(typeof row.index, 'number');
    assert.equal(typeof row.name, 'string');
    assert.equal(typeof row.action, 'string');
    assert.equal(typeof row.reason, 'string');
    assert.equal(typeof row.channels, 'string');
    assert.equal(typeof row.matchedChannelCount, 'number');
    assert.equal(typeof row.descriptionChanged, 'boolean');
}

function assertPlainResult(r) {
    assert.ok(Array.isArray(r.rows));
    assert.ok(Array.isArray(r.channelNameMatches));
    for (const field of ['refusal', 'formatVersion', 'sourceRbacVersion', 'sourceEngineVersion', 'planToken']) {
        assert.equal(typeof r[field], 'string', field);
    }
    for (const field of ['importable', 'applyChannels', 'matchChannelsByName', 'applied']) {
        assert.equal(typeof r[field], 'boolean', field);
    }
    r.rows.forEach(assertPlainRow);
    for (const m of r.channelNameMatches) {
        assert.deepEqual(Object.keys(m).sort(), ['channelId', 'fileChannelId', 'name']);
    }
}

test('every captured import result normalizes to plain arrays, strings and booleans', () => {
    for (const wire of [WIRE_IMPORT_PREVIEW_TWO_ROWS, WIRE_IMPORT_NAME_MATCH_OFF, WIRE_IMPORT_NAME_MATCH_ONE_ON,
        WIRE_IMPORT_NAME_MATCH_TWO_ON, WIRE_IMPORT_OVERWRITE_ADD_ONE, WIRE_IMPORT_OVERWRITE_ADD_TWO_REMOVE_ONE,
        WIRE_IMPORT_CHANNELS_NOT_APPLIED, WIRE_IMPORT_REFUSED, WIRE_IMPORT_APPLIED]) {
        assertPlainResult(importResult(wire));
    }
});

test('import preview with two rows: an array of rows, null lists become [], formatVersion 1 becomes "1"', () => {
    const r = importResult(WIRE_IMPORT_PREVIEW_TWO_ROWS);
    assert.equal(r.importable, true);
    assert.equal(r.formatVersion, '1', 'the number 1 on the wire');
    assert.equal(r.sourceRbacVersion, '1.2.0');
    assert.equal(r.sourceEngineVersion, '4.7.0');
    assert.equal(r.planToken, '5ba1268962581bdbd0ddb491d164bea2910cd8c2b77dfc0d71fe1e0346647395');
    assert.equal(r.applied, false);
    assert.equal(r.refusal, '', 'absent on an importable file');
    assert.deepEqual(r.channelNameMatches, [], '"channelNameMatches":null');
    assert.deepEqual(r.rows.map((x) => [x.index, x.name, x.action, x.channels, x.matchedChannelCount]), [
        [0, 'probe lab', 'CREATE', 'FROM_FILE', 2],
        [1, 'probe everyone', 'UNCHANGED', 'FROM_FILE', 0]
    ]);
    assert.equal(r.rows[0].reason, '', 'absent reason');
    assert.deepEqual(r.rows[0].addedPermissions, []);
});

test('import preview with one row: a bare row object becomes a one-element array; a bare string becomes a one-element list', () => {
    const skipped = importResult(WIRE_IMPORT_NAME_MATCH_OFF);
    assert.equal(skipped.rows.length, 1);
    assert.equal(skipped.rows[0].action, 'SKIP');
    assert.match(skipped.rows[0].reason, /^None of its 1 channels exist on this engine/);
    assert.deepEqual(skipped.rows[0].unmatchedChannels, ['probe one (8163af3f-7ed2-4a0c-b326-34830263c504)'],
        '{"string":"..."} for one element');
    assert.equal(skipped.sourceRbacVersion, 'e2e');

    const add = importResult(WIRE_IMPORT_OVERWRITE_ADD_ONE);
    assert.equal(add.rows[0].action, 'OVERWRITE');
    assert.deepEqual(add.rows[0].addedPermissions, ['viewDashboard']);
    assert.deepEqual(add.rows[0].removedPermissions, []);
});

test('import preview lists keep the wire order of several elements', () => {
    const r = importResult(WIRE_IMPORT_OVERWRITE_ADD_TWO_REMOVE_ONE);
    assert.deepEqual(r.rows[0].addedPermissions, ['viewAlerts', 'viewDashboard']);
    assert.deepEqual(r.rows[0].removedPermissions, ['viewChannels'], 'one element beside two');
    assert.equal(r.rows[0].reason, 'Restricted to 2 channel(s) after the import; here it sees every channel.');
    assert.equal(r.rows[0].matchedChannelCount, 2);
});

test('channelNameMatches: one match arrives as a bare object, two as an array, none as null', () => {
    const one = importResult(WIRE_IMPORT_NAME_MATCH_OFF);
    assert.deepEqual(one.channelNameMatches, [{
        name: 'probe one',
        fileChannelId: '8163af3f-7ed2-4a0c-b326-34830263c504',
        channelId: '4c468ff3-0cf7-4e8b-88e7-a7d8a3b538bf'
    }]);
    assert.equal(one.matchChannelsByName, false);

    const on = importResult(WIRE_IMPORT_NAME_MATCH_ONE_ON);
    assert.equal(on.matchChannelsByName, true);
    assert.equal(on.rows[0].action, 'CREATE');
    assert.equal(on.rows[0].matchedChannelCount, 1);

    const two = importResult(WIRE_IMPORT_NAME_MATCH_TWO_ON);
    assert.deepEqual(two.channelNameMatches.map((m) => m.name), ['probe one', 'probe two']);

    assert.deepEqual(importResult(WIRE_IMPORT_PREVIEW_TWO_ROWS).channelNameMatches, []);
});

test('a refused file has importable false, the refusal text, no rows, and empty version strings', () => {
    const r = importResult(WIRE_IMPORT_REFUSED);
    assert.equal(r.importable, false);
    assert.equal(r.refusal, 'This file is format 2, written by rbac 9. This rbac reads format 1.');
    assert.deepEqual(r.rows, [], '"rows":null');
    assert.equal(r.formatVersion, '');
    assert.equal(r.sourceRbacVersion, '');
    assert.equal(r.planToken, '');
});

test('channels not applied: EVERY_CHANNEL with its reason; an applied result says so', () => {
    const r = importResult(WIRE_IMPORT_CHANNELS_NOT_APPLIED);
    assert.equal(r.applyChannels, false);
    assert.equal(r.rows[0].channels, 'EVERY_CHANNEL');
    assert.match(r.rows[0].reason, /^Sees every channel here; where it was exported it was restricted to 1 channel\(s\)\./);
    const applied = importResult(WIRE_IMPORT_APPLIED);
    assert.equal(applied.applied, true);
    assert.equal(applied.rows.length, 1);
});

test('normalizeImportResult takes the root key too, and tolerates nothing at all', () => {
    const wrapped = normalizeImportResult(JSON.parse(WIRE_IMPORT_PREVIEW_TWO_ROWS));
    assert.equal(wrapped.rows.length, 2);
    for (const nothing of [null, undefined, '', 'text']) {
        const r = normalizeImportResult(nothing);
        assertPlainResult(r);
        assert.equal(r.importable, false);
    }
});

test('normalizeImportResult coerces a string flag, a string number and array-shaped lists', () => {
    const r = normalizeImportResult({
        importable: 'true', formatVersion: 1, applied: 'false',
        rows: [{ index: '3', name: 'R', action: 'OVERWRITE', addedPermissions: ['a', 'b'], removedChannels: 'c',
            matchedChannelCount: '2', descriptionChanged: 'true' }],
        channelNameMatches: null
    });
    assert.equal(r.importable, true);
    assert.equal(r.formatVersion, '1');
    assert.equal(r.applied, false);
    assert.equal(r.rows[0].index, 3);
    assert.equal(r.rows[0].matchedChannelCount, 2);
    assert.equal(r.rows[0].descriptionChanged, true);
    assert.deepEqual(r.rows[0].addedPermissions, ['a', 'b']);
    assert.deepEqual(r.rows[0].removedChannels, ['c']);
});

/* ---- export and import calls ------------------------------------------------------- */

test('exportRoles asks for the file as raw text with one roleId per role', async () => {
    const seen = [];
    const rbac = makeApi({
        asList,
        get: async (path, params, opts) => { seen.push([path, params, opts]); return '<?xml version="1.0"?>\n<rbacRoles/>\n'; }
    });
    const text = await rbac.exportRoles(new Set([3, 7]));
    assert.equal(text, '<?xml version="1.0"?>\n<rbacRoles/>\n', 'the server text as is');
    assert.deepEqual(seen, [['/extensions/rbac/roles/_export', { roleId: [3, 7] }, { raw: true }]]);
});

test('importRoles posts the file as text/plain with the settings as query parameters and normalizes the answer', async () => {
    const seen = [];
    const rbac = makeApi({
        asList,
        post: async (path, body, opts) => { seen.push([path, body, opts]); return unwrap(JSON.parse(WIRE_IMPORT_APPLIED)); }
    });
    const result = await rbac.importRoles('<rbacRoles/>', {
        dryRun: false, applyChannels: true, matchChannelsByName: false, pick: [0, 2], planToken: 'tok'
    });
    assert.deepEqual(seen, [['/extensions/rbac/roles/_import', '<rbacRoles/>', {
        params: { dryRun: false, applyChannels: true, matchChannelsByName: false, pick: [0, 2], planToken: 'tok' },
        contentType: 'text/plain'
    }]]);
    assert.equal(result.applied, true);
    assertPlainResult(result);
});
