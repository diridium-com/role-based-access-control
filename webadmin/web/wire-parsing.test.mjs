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
        { id: null, name: '', description: '', permissions: [], channelIds: [], restricted: false, isAdmin: false });

    assert.equal(normalizeRole({ id: '' }).id, null);
    assert.equal(normalizeRole({ id: '5' }).id, 5);
    assert.equal(normalizeRole({ isAdmin: 'true' }).isAdmin, true, 'host XML-fallback parser shape');
    assert.equal(normalizeRole({ isAdmin: 'false' }).isAdmin, false);
});

test('normalizeRole reads restricted: a boolean, the XML fallback string, absent from an old server is false', () => {
    assert.equal(normalizeRole({ restricted: true }).restricted, true);
    assert.equal(normalizeRole({ restricted: 'true' }).restricted, true);
    assert.equal(normalizeRole({ restricted: false }).restricted, false);
    assert.equal(normalizeRole({ restricted: 'false' }).restricted, false);
    assert.equal(normalizeRole({ channelIds: { string: 'a' } }).restricted, false, 'no flag: false, whatever the list');
});

/* ---- roleXml: the XStream XML write path ------------------------------------------ */

test('roleXml create omits <id>; update includes it', () => {
    const role = { id: 3, name: 'RO', description: 'd', permissions: ['a'], channelIds: [], restricted: false, isAdmin: false };
    assert.equal(
        roleXml(role),
        '<com.diridium.rbac.Role><name>RO</name><description>d</description>'
        + '<permissions><string>a</string></permissions><channelIds></channelIds>'
        + '<restricted>false</restricted><isAdmin>false</isAdmin></com.diridium.rbac.Role>');
    assert.ok(roleXml({ ...role, restricted: true }).includes('<channelIds></channelIds><restricted>true</restricted><isAdmin>'),
        'restricted with no channels is written as such');
    assert.ok(roleXml({ name: 'x' }).includes('<restricted>false</restricted>'), 'no flag: false');
    assert.ok(roleXml(role, { includeId: true }).startsWith('<com.diridium.rbac.Role><id>3</id><name>'));
});

test('roleXml escapes markup in text fields', () => {
    const xml = roleXml({ name: 'A & B <x>', description: '</description>', permissions: ['p&q'], channelIds: [] });
    assert.ok(xml.includes('<name>A &amp; B &lt;x&gt;</name>'));
    assert.ok(xml.includes('<description>&lt;/description&gt;</description>'));
    assert.ok(xml.includes('<string>p&amp;q</string>'));
});

/* ---- role import: verbatim captures (wire-probe-7.log, 2026-11-04, this branch's server on OIE 4.7.0, Derby) ---- */

// preview, two rows (one new with two channels, one unchanged)
const WIRE_IMPORT_PREVIEW_TWO_ROWS =
    '{"com.diridium.rbac.RoleImportResult":{"importable":true,"formatVersion":1,"sourceRbacVersion":"1.2.0","sourceEngineVersion":"4.7.0","applyChannels":true,"matchChannelsByName":false,"applied":false,"planToken":"c38874654c2450d71db312ca48812b02ad4b76226049e9a705dbfaf9510a2c00","rows":{"com.diridium.rbac.RoleImportRow":[{"index":0,"name":"probe lab","action":"CREATE","droppedPermissions":null,"matchedChannelCount":2,"channels":"FROM_FILE","noChannelFound":false,"existsHere":false,"restrictedNow":false,"restrictedAfter":true,"descriptionAfter":"rbac e2e","permissionsNow":null,"permissionsAfter":{"string":["viewChannels","viewDashboard"]},"channelsNow":null,"channelsAfter":{"com.diridium.rbac.RoleImportChannel":[{"id":"b033ec2d-6258-4b0f-b829-0854d8ffc975","name":"probe one","fileId":"b033ec2d-6258-4b0f-b829-0854d8ffc975","fileName":"probe one","match":"BY_ID","used":true},{"id":"d3e1ce7e-7b3b-49b6-926e-0a3e083079b9","name":"probe two","fileId":"d3e1ce7e-7b3b-49b6-926e-0a3e083079b9","fileName":"probe two","match":"BY_ID","used":true}]}},{"index":1,"name":"probe everyone","action":"UNCHANGED","reason":"Identical to the role on this engine.","droppedPermissions":null,"matchedChannelCount":0,"channels":"FROM_FILE","noChannelFound":false,"existsHere":true,"restrictedNow":false,"restrictedAfter":false,"descriptionNow":"rbac e2e","descriptionAfter":"rbac e2e","permissionsNow":{"string":"viewChannels"},"permissionsAfter":{"string":"viewChannels"},"channelsNow":null,"channelsAfter":null}]},"channelNameMatches":null}}';

// preview, an overwrite: channels now (one deleted here) and after (one renamed here), several permissions each
const WIRE_IMPORT_OVERWRITE_DETAILS =
    '{"com.diridium.rbac.RoleImportResult":{"importable":true,"formatVersion":1,"sourceRbacVersion":"1.2.0","sourceEngineVersion":"4.7.0","applyChannels":true,"matchChannelsByName":false,"applied":false,"planToken":"ccbf758aaa36415ab173abf2b1da56869ed22f19aa4772d42f9b41d2a748b58c","rows":{"com.diridium.rbac.RoleImportRow":[{"index":0,"name":"probe lab","action":"OVERWRITE","droppedPermissions":null,"matchedChannelCount":2,"channels":"FROM_FILE","noChannelFound":false,"existsHere":true,"restrictedNow":true,"restrictedAfter":true,"descriptionNow":"rbac e2e","descriptionAfter":"rbac e2e","permissionsNow":{"string":["viewAlerts","viewChannels"]},"permissionsAfter":{"string":["viewChannels","viewDashboard"]},"channelsNow":{"com.diridium.rbac.RoleImportChannel":{"id":"d3e1ce7e-7b3b-49b6-926e-0a3e083079b9","name":"probe two renamed","match":"BY_ID","used":true}},"channelsAfter":{"com.diridium.rbac.RoleImportChannel":[{"id":"b033ec2d-6258-4b0f-b829-0854d8ffc975","name":"probe one","fileId":"b033ec2d-6258-4b0f-b829-0854d8ffc975","fileName":"probe one","match":"BY_ID","used":true},{"id":"d3e1ce7e-7b3b-49b6-926e-0a3e083079b9","name":"probe two renamed","fileId":"d3e1ce7e-7b3b-49b6-926e-0a3e083079b9","fileName":"probe two","match":"BY_ID","used":true}]}},{"index":1,"name":"probe everyone","action":"UNCHANGED","reason":"Identical to the role on this engine.","droppedPermissions":null,"matchedChannelCount":0,"channels":"FROM_FILE","noChannelFound":false,"existsHere":true,"restrictedNow":false,"restrictedAfter":false,"descriptionNow":"rbac e2e","descriptionAfter":"rbac e2e","permissionsNow":{"string":"viewChannels"},"permissionsAfter":{"string":"viewChannels"},"channelsNow":null,"channelsAfter":null}]},"channelNameMatches":null}}';

// preview, one match by name, matching off (the role is skipped)
const WIRE_IMPORT_NAME_MATCH_OFF =
    '{"com.diridium.rbac.RoleImportResult":{"importable":true,"formatVersion":1,"sourceRbacVersion":"e2e","sourceEngineVersion":"e2e","applyChannels":true,"matchChannelsByName":false,"applied":false,"planToken":"996f40ef1821c4f0ae00da90be77a913db02992d0777340bb2c3dc7bb5acb376","rows":{"com.diridium.rbac.RoleImportRow":{"index":0,"name":"probe moved one","action":"CREATE","reason":"The import restricts this role to 1 channel. None of those channels exist on this engine. If imported, this role is restricted to no channels until an administrator sets channels for this role. 1 of those channels matches a channel on this engine by name.","droppedPermissions":null,"matchedChannelCount":0,"channels":"FROM_FILE","noChannelFound":true,"existsHere":false,"restrictedNow":false,"restrictedAfter":true,"descriptionAfter":"rbac e2e","permissionsNow":null,"permissionsAfter":{"string":"viewChannels"},"channelsNow":null,"channelsAfter":{"com.diridium.rbac.RoleImportChannel":{"id":"b033ec2d-6258-4b0f-b829-0854d8ffc975","name":"probe one","fileId":"0cf2fccd-0d1c-480c-9f40-ea3aa9780bd1","fileName":"probe one","match":"BY_NAME","used":false}}}},"channelNameMatches":{"com.diridium.rbac.ChannelNameMatch":{"name":"probe one","fileChannelId":"0cf2fccd-0d1c-480c-9f40-ea3aa9780bd1","channelId":"b033ec2d-6258-4b0f-b829-0854d8ffc975"}}}}';

// preview, one match by name, matching on (the role is new)
const WIRE_IMPORT_NAME_MATCH_ONE_ON =
    '{"com.diridium.rbac.RoleImportResult":{"importable":true,"formatVersion":1,"sourceRbacVersion":"e2e","sourceEngineVersion":"e2e","applyChannels":true,"matchChannelsByName":true,"applied":false,"planToken":"8c2b8358d32d92a53f328c56a5b292cd8f438a1d7c5de20f8c2144944fa4e1fb","rows":{"com.diridium.rbac.RoleImportRow":{"index":0,"name":"probe moved one","action":"CREATE","droppedPermissions":null,"matchedChannelCount":1,"channels":"FROM_FILE","noChannelFound":false,"existsHere":false,"restrictedNow":false,"restrictedAfter":true,"descriptionAfter":"rbac e2e","permissionsNow":null,"permissionsAfter":{"string":"viewChannels"},"channelsNow":null,"channelsAfter":{"com.diridium.rbac.RoleImportChannel":{"id":"b033ec2d-6258-4b0f-b829-0854d8ffc975","name":"probe one","fileId":"0cf2fccd-0d1c-480c-9f40-ea3aa9780bd1","fileName":"probe one","match":"BY_NAME","used":true}}}},"channelNameMatches":{"com.diridium.rbac.ChannelNameMatch":{"name":"probe one","fileChannelId":"0cf2fccd-0d1c-480c-9f40-ea3aa9780bd1","channelId":"b033ec2d-6258-4b0f-b829-0854d8ffc975"}}}}';

// preview, two matches by name, matching on (wire-probe-2.log, 2026-11-02, before the row's now and after
// fields existed: used only for channelNameMatches)
const WIRE_IMPORT_NAME_MATCH_TWO_ON =
    '{"com.diridium.rbac.RoleImportResult":{"importable":true,"formatVersion":1,"sourceRbacVersion":"e2e","sourceEngineVersion":"e2e","applyChannels":true,"matchChannelsByName":true,"applied":false,"planToken":"8983436faf4e3d69112384f89dc779805862880e6cf032c82eacd4406cd6eeae","rows":{"com.diridium.rbac.RoleImportRow":{"index":0,"name":"probe moved two","action":"CREATE","droppedPermissions":null,"unmatchedChannels":null,"matchedChannelCount":2,"channels":"FROM_FILE","descriptionChanged":false,"addedPermissions":null,"removedPermissions":null,"addedChannels":null,"removedChannels":null}},"channelNameMatches":{"com.diridium.rbac.ChannelNameMatch":[{"name":"probe one","fileChannelId":"e0472e0d-bf15-436c-931b-679d9fa2954c","channelId":"4c468ff3-0cf7-4e8b-88e7-a7d8a3b538bf"},{"name":"probe two","fileChannelId":"4d20b4dd-0fc5-4989-9131-c3555229abba","channelId":"ee366a8b-755b-4f73-9f1b-abe1801cc121"}]}}}';

// preview, a new row with a channel found by id, one not found, one not found with no name in the file, and a
// permission this engine doesn't offer
const WIRE_IMPORT_NOT_FOUND_AND_DROPPED =
    '{"com.diridium.rbac.RoleImportResult":{"importable":true,"formatVersion":1,"sourceRbacVersion":"e2e","sourceEngineVersion":"e2e","applyChannels":true,"matchChannelsByName":false,"applied":false,"planToken":"7e01d1564672a54cdcb24218ec295e77b044cd18c36936286cbbd2ba628ca7fa","rows":{"com.diridium.rbac.RoleImportRow":{"index":0,"name":"probe mixed","action":"CREATE","reason":"Of the 3 channels in the import, 2 are not on this engine. 1 permission in the import is not offered by this engine and is left out.","droppedPermissions":{"string":"Run Lab Reports"},"matchedChannelCount":1,"channels":"FROM_FILE","noChannelFound":false,"existsHere":false,"restrictedNow":false,"restrictedAfter":true,"descriptionAfter":"rbac e2e","permissionsNow":null,"permissionsAfter":{"string":"viewChannels"},"channelsNow":null,"channelsAfter":{"com.diridium.rbac.RoleImportChannel":[{"id":"b033ec2d-6258-4b0f-b829-0854d8ffc975","name":"probe one","fileId":"b033ec2d-6258-4b0f-b829-0854d8ffc975","fileName":"probe one","match":"BY_ID","used":true},{"id":"f118db1f-b762-4e90-9fbb-49b90b0a0dee","name":"probe nowhere","fileId":"f118db1f-b762-4e90-9fbb-49b90b0a0dee","fileName":"probe nowhere","match":"NOT_FOUND","used":false},{"id":"6c70d764-c002-4547-8cd2-21c939bf7175","fileId":"6c70d764-c002-4547-8cd2-21c939bf7175","fileName":null,"match":"NOT_FOUND","used":false}]}}},"channelNameMatches":null}}';

// preview, channels not applied: an existing role keeps its own, a new role sees every channel
const WIRE_IMPORT_CHANNELS_NOT_APPLIED =
    '{"com.diridium.rbac.RoleImportResult":{"importable":true,"formatVersion":1,"sourceRbacVersion":"e2e","sourceEngineVersion":"e2e","applyChannels":false,"matchChannelsByName":false,"applied":false,"planToken":"f28ab0ccc4070b8fea2b8ca0aeca1c944b2bf760efe406d8ebe3400d80595956","rows":{"com.diridium.rbac.RoleImportRow":[{"index":0,"name":"probe lab","action":"OVERWRITE","reason":"This role keeps the channels currently set on this engine.","droppedPermissions":null,"matchedChannelCount":0,"channels":"KEPT","noChannelFound":false,"existsHere":true,"restrictedNow":true,"restrictedAfter":true,"descriptionNow":"rbac e2e","descriptionAfter":"rbac e2e","permissionsNow":{"string":["viewAlerts","viewChannels"]},"permissionsAfter":{"string":"viewChannels"},"channelsNow":{"com.diridium.rbac.RoleImportChannel":{"id":"d3e1ce7e-7b3b-49b6-926e-0a3e083079b9","name":"probe two renamed","match":"BY_ID","used":true}},"channelsAfter":{"com.diridium.rbac.RoleImportChannel":{"id":"d3e1ce7e-7b3b-49b6-926e-0a3e083079b9","name":"probe two renamed","match":"BY_ID","used":true}}},{"index":1,"name":"probe fresh","action":"CREATE","reason":"The import restricts this role to 1 channel. Restrictions are not applied, so this role is restricted to no channels on this engine until an administrator sets channels for this role.","droppedPermissions":null,"matchedChannelCount":0,"channels":"NO_CHANNEL","noChannelFound":false,"existsHere":false,"restrictedNow":false,"restrictedAfter":true,"descriptionAfter":"rbac e2e","permissionsNow":null,"permissionsAfter":{"string":"viewChannels"},"channelsNow":null,"channelsAfter":null}]},"channelNameMatches":null}}';

// preview, refused file (wire-probe-2.log; the shape has no rows)
const WIRE_IMPORT_REFUSED =
    '{"com.diridium.rbac.RoleImportResult":{"importable":false,"refusal":"This file is format 2, written by rbac 9. This rbac reads format 1.","applyChannels":true,"matchChannelsByName":false,"applied":false,"rows":null,"channelNameMatches":null}}';

// apply, one row written
const WIRE_IMPORT_APPLIED =
    '{"com.diridium.rbac.RoleImportResult":{"importable":true,"formatVersion":1,"sourceRbacVersion":"e2e","sourceEngineVersion":"e2e","applyChannels":true,"matchChannelsByName":false,"applied":true,"planToken":"7e01d1564672a54cdcb24218ec295e77b044cd18c36936286cbbd2ba628ca7fa","rows":{"com.diridium.rbac.RoleImportRow":{"index":0,"name":"probe mixed","action":"CREATE","reason":"Of the 3 channels in the import, 2 are not on this engine. 1 permission in the import is not offered by this engine and is left out.","droppedPermissions":{"string":"Run Lab Reports"},"matchedChannelCount":1,"channels":"FROM_FILE","noChannelFound":false,"existsHere":false,"restrictedNow":false,"restrictedAfter":true,"descriptionAfter":"rbac e2e","permissionsNow":null,"permissionsAfter":{"string":"viewChannels"},"channelsNow":null,"channelsAfter":{"com.diridium.rbac.RoleImportChannel":[{"id":"b033ec2d-6258-4b0f-b829-0854d8ffc975","name":"probe one","fileId":"b033ec2d-6258-4b0f-b829-0854d8ffc975","fileName":"probe one","match":"BY_ID","used":true},{"id":"f118db1f-b762-4e90-9fbb-49b90b0a0dee","name":"probe nowhere","fileId":"f118db1f-b762-4e90-9fbb-49b90b0a0dee","fileName":"probe nowhere","match":"NOT_FOUND","used":false},{"id":"6c70d764-c002-4547-8cd2-21c939bf7175","fileId":"6c70d764-c002-4547-8cd2-21c939bf7175","fileName":null,"match":"NOT_FOUND","used":false}]}}},"channelNameMatches":null}}';

const importResult = (wire) => normalizeImportResult(unwrap(JSON.parse(wire)));

// Every list is an array of plain strings, every version a string: a quirk that
// leaks through (null, a bare string, a bare object, a number) fails here.
function assertPlainRow(row) {
    for (const key of ['droppedPermissions', 'permissionsNow', 'permissionsAfter']) {
        assert.ok(Array.isArray(row[key]), `${key} is an array`);
        for (const v of row[key]) assert.equal(typeof v, 'string');
    }
    for (const key of ['channelsNow', 'channelsAfter']) {
        assert.ok(Array.isArray(row[key]), `${key} is an array`);
        for (const c of row[key]) {
            assert.equal(typeof c.id, 'string');
            assert.ok(c.name === null || typeof c.name === 'string', 'name is a string or null');
            assert.ok(c.fileName === null || typeof c.fileName === 'string', 'fileName is a string or null');
            assert.ok(c.fileId === null || typeof c.fileId === 'string', 'fileId is a string or null');
            assert.equal(typeof c.match, 'string');
            assert.equal(typeof c.used, 'boolean');
        }
    }
    assert.equal(typeof row.index, 'number');
    assert.equal(typeof row.name, 'string');
    assert.equal(typeof row.action, 'string');
    assert.equal(typeof row.reason, 'string');
    assert.equal(typeof row.channels, 'string');
    assert.equal(typeof row.matchedChannelCount, 'number');
    assert.equal(typeof row.existsHere, 'boolean');
    assert.equal(typeof row.noChannelFound, 'boolean');
    assert.equal(typeof row.descriptionNow, 'string');
    assert.equal(typeof row.descriptionAfter, 'string');
    for (const gone of ['unmatchedChannels', 'descriptionChanged', 'addedPermissions', 'removedPermissions',
        'addedChannels', 'removedChannels']) {
        assert.ok(!(gone in row), `${gone} is no longer part of a row`);
    }
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
    for (const wire of [WIRE_IMPORT_PREVIEW_TWO_ROWS, WIRE_IMPORT_OVERWRITE_DETAILS, WIRE_IMPORT_NAME_MATCH_OFF,
        WIRE_IMPORT_NAME_MATCH_ONE_ON, WIRE_IMPORT_NAME_MATCH_TWO_ON, WIRE_IMPORT_NOT_FOUND_AND_DROPPED,
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
    assert.equal(r.planToken, 'c38874654c2450d71db312ca48812b02ad4b76226049e9a705dbfaf9510a2c00');
    assert.equal(r.applied, false);
    assert.equal(r.refusal, '', 'absent on an importable file');
    assert.deepEqual(r.channelNameMatches, [], '"channelNameMatches":null');
    assert.deepEqual(r.rows.map((x) => [x.index, x.name, x.action, x.channels, x.matchedChannelCount]), [
        [0, 'probe lab', 'CREATE', 'FROM_FILE', 2],
        [1, 'probe everyone', 'UNCHANGED', 'FROM_FILE', 0]
    ]);
    assert.equal(r.rows[0].reason, '', 'absent reason');
    assert.deepEqual(r.rows.map((x) => x.noChannelFound), [false, false], 'the captured fixtures predate noChannelFound: absent is false');
    assert.deepEqual(r.rows[0].permissionsNow, [], 'absent list');
});

test('import preview with one row: a bare row object becomes a one-element array; a bare string becomes a one-element list', () => {
    const skipped = importResult(WIRE_IMPORT_NAME_MATCH_OFF);
    assert.equal(skipped.rows.length, 1);
    assert.equal(skipped.rows[0].action, 'CREATE');
    assert.equal(skipped.rows[0].noChannelFound, true, 'offered, flagged, not skipped');
    assert.match(skipped.rows[0].reason, /^The import restricts this role to 1 channel\. None of those channels exist on this engine\./);
    assert.equal(skipped.sourceRbacVersion, 'e2e');

    const overwrite = importResult(WIRE_IMPORT_OVERWRITE_DETAILS);
    assert.equal(overwrite.rows[0].action, 'OVERWRITE');
});

test('import preview row details: the role now and after, lists of one as bare values, absent names as null', () => {
    const [lab, everyone] = importResult(WIRE_IMPORT_OVERWRITE_DETAILS).rows;
    assert.equal(lab.existsHere, true);
    assert.equal(lab.descriptionNow, 'rbac e2e');
    assert.equal(lab.descriptionAfter, 'rbac e2e');
    assert.deepEqual(lab.permissionsNow, ['viewAlerts', 'viewChannels']);
    assert.deepEqual(lab.permissionsAfter, ['viewChannels', 'viewDashboard']);
    assert.deepEqual(lab.droppedPermissions, []);
    assert.deepEqual(lab.channelsNow, [
        { id: 'd3e1ce7e-7b3b-49b6-926e-0a3e083079b9', name: 'probe two renamed', fileId: null, fileName: null, match: 'BY_ID', used: true }
    ], 'a now list: no file id or name, a bare object for one entry; the deleted channel left with the channel');
    assert.deepEqual(lab.channelsAfter, [
        { id: 'b033ec2d-6258-4b0f-b829-0854d8ffc975', name: 'probe one', fileId: 'b033ec2d-6258-4b0f-b829-0854d8ffc975', fileName: 'probe one', match: 'BY_ID', used: true },
        { id: 'd3e1ce7e-7b3b-49b6-926e-0a3e083079b9', name: 'probe two renamed', fileId: 'd3e1ce7e-7b3b-49b6-926e-0a3e083079b9', fileName: 'probe two', match: 'BY_ID', used: true }
    ], 'an array of channels in file order; a found-by-id entry\'s fileId is its id; the renamed one keeps the file\'s name');
    assert.deepEqual(everyone.permissionsNow, ['viewChannels'], '{"string":"..."} for one element');
    assert.deepEqual(everyone.channelsNow, [], '"channelsNow":null');

    const mixed = importResult(WIRE_IMPORT_NOT_FOUND_AND_DROPPED).rows[0];
    assert.equal(mixed.existsHere, false);
    assert.equal(mixed.descriptionNow, '', 'absent on the wire for a role that is not here');
    assert.deepEqual(mixed.permissionsNow, []);
    assert.deepEqual(mixed.droppedPermissions, ['Run Lab Reports'], 'a bare string');
    assert.deepEqual(mixed.channelsAfter.map((c) => [c.name, c.fileName, c.match, c.used]), [
        ['probe one', 'probe one', 'BY_ID', true],
        ['probe nowhere', 'probe nowhere', 'NOT_FOUND', false],
        [null, null, 'NOT_FOUND', false]
    ], 'a nameless channel in the file: no name, "fileName":null');
    const skipped = importResult(WIRE_IMPORT_NAME_MATCH_OFF).rows[0];
    assert.deepEqual(skipped.channelsAfter, [{ id: 'b033ec2d-6258-4b0f-b829-0854d8ffc975', name: 'probe one',
        fileId: '0cf2fccd-0d1c-480c-9f40-ea3aa9780bd1', fileName: 'probe one', match: 'BY_NAME', used: false }],
        'a bare channel object; a match by name, not used: its fileId is the file\'s, not the id here');
    assert.deepEqual(mixed.channelsAfter.map((c) => c.fileId), [
        'b033ec2d-6258-4b0f-b829-0854d8ffc975', 'f118db1f-b762-4e90-9fbb-49b90b0a0dee', '6c70d764-c002-4547-8cd2-21c939bf7175'
    ], 'a not-found entry\'s fileId is its id');
});

test('import preview lists keep the wire order of several elements', () => {
    const r = importResult(WIRE_IMPORT_OVERWRITE_DETAILS);
    assert.equal(r.rows[0].matchedChannelCount, 2);
    assert.deepEqual(r.rows[0].channelsAfter.map((c) => c.name), ['probe one', 'probe two renamed'], 'file order');
    assert.deepEqual(r.rows[0].permissionsNow, ['viewAlerts', 'viewChannels'], 'sorted by the server');
});

test('channelNameMatches: one match arrives as a bare object, two as an array, none as null', () => {
    const one = importResult(WIRE_IMPORT_NAME_MATCH_OFF);
    assert.deepEqual(one.channelNameMatches, [{
        name: 'probe one',
        fileChannelId: '0cf2fccd-0d1c-480c-9f40-ea3aa9780bd1',
        channelId: 'b033ec2d-6258-4b0f-b829-0854d8ffc975'
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

test('channels not applied: NO_CHANNEL with its reason; an applied result says so', () => {
    const r = importResult(WIRE_IMPORT_CHANNELS_NOT_APPLIED);
    assert.equal(r.applyChannels, false);
    assert.equal(r.rows[0].channels, 'KEPT');
    assert.deepEqual(r.rows[0].channelsAfter, r.rows[0].channelsNow, 'the existing role keeps its channels');
    assert.equal(r.rows[1].channels, 'NO_CHANNEL');
    assert.match(r.rows[1].reason, /^The import restricts this role to 1 channel\. Restrictions are not applied, so this role is restricted to no channels on this engine/);
    assert.equal(r.rows[1].restrictedAfter, true);
    assert.equal(r.rows[0].restrictedNow, true);
    assert.equal(r.rows[0].reason, 'This role keeps the channels currently set on this engine.');
    const applied = importResult(WIRE_IMPORT_APPLIED);
    assert.equal(applied.applied, true);
    assert.equal(applied.rows.length, 1);
});

test('noChannelFound: a real boolean on the wire is read as is', () => {
    const raw = { importable: true, rows: [{ index: 0, name: 'R', action: 'CREATE', noChannelFound: true },
        { index: 1, name: 'S', action: 'CREATE', noChannelFound: false }] };
    assert.deepEqual(normalizeImportResult(raw).rows.map((x) => x.noChannelFound), [true, false]);
});

test('restrictedNow and restrictedAfter: booleans and strings; absent is false', () => {
    const raw = { importable: true, rows: [
        { index: 0, name: 'A', action: 'OVERWRITE', restrictedNow: true, restrictedAfter: false },
        { index: 1, name: 'B', action: 'OVERWRITE', restrictedNow: 'false', restrictedAfter: 'true' },
        { index: 2, name: 'C', action: 'CREATE' }] };
    const rows = normalizeImportResult(raw).rows;
    assert.deepEqual(rows.map((x) => [x.restrictedNow, x.restrictedAfter]), [[true, false], [false, true], [false, false]]);
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
        rows: [{ index: '3', name: 'R', action: 'OVERWRITE', permissionsAfter: ['a', 'b'], permissionsNow: 'c',
            matchedChannelCount: '2', existsHere: 'true', noChannelFound: 'true',
            channelsAfter: [{ id: 'x', name: 'X', fileId: 'x', fileName: 'X', match: 'BY_ID', used: 'true' }] }],
        channelNameMatches: null
    });
    assert.equal(r.importable, true);
    assert.equal(r.formatVersion, '1');
    assert.equal(r.applied, false);
    assert.equal(r.rows[0].index, 3);
    assert.equal(r.rows[0].matchedChannelCount, 2);
    assert.equal(r.rows[0].existsHere, true);
    assert.equal(r.rows[0].noChannelFound, true);
    assert.deepEqual(r.rows[0].permissionsAfter, ['a', 'b']);
    assert.deepEqual(r.rows[0].permissionsNow, ['c']);
    assert.deepEqual(r.rows[0].channelsAfter, [{ id: 'x', name: 'X', fileId: 'x', fileName: 'X', match: 'BY_ID', used: true }]);
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
