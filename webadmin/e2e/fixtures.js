// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

/*
 * Canned engine responses in the XStream wire shapes the web administrator
 * expects (its api.js unwraps a single root key and asList() normalizes
 * one-element collections). Keys are "METHOD /path" (no /api prefix, no query
 * string); `*` matches a single path segment. Values: string → text/plain,
 * { __status, body } → that HTTP status, object/array → application/json.
 *
 * The host-side fixtures are a trimmed vendored copy of the oie-web-client
 * e2e defaults. The RBAC wire shapes (linked-hash-set / linked-hash-map roots,
 * the com.diridium.rbac.Role FQCN root, XStream singleton collapse,
 * channelIds:null) are pinned from live engine captures — see
 * ../e2e-fixtures-notes.md (captured 2026-07-14 against rbac 1.1.0).
 */

/* ---- host (web administrator) fixtures -------------------------------------- */

export const SAMPLE_USER = { id: 1, username: 'admin', firstName: 'Admin', lastName: 'User' };

export const SAMPLE_STATUSES = [
    { channelId: 'c-started', name: 'Demo Started', state: 'STARTED', statistics: {} },
    { channelId: 'c-stopped', name: 'Demo Stopped', state: 'STOPPED', statistics: {} },
];

export const SAMPLE_CHANNELS = [
    { '@version': '4.5.0', id: 'c-started', name: 'Demo Started', revision: 1 },
    { '@version': '4.5.0', id: 'c-stopped', name: 'Demo Stopped', revision: 1 },
];

export const SAMPLE_USERS = [
    { id: 1, username: 'admin', firstName: 'Admin', lastName: 'User', email: 'admin@example.com' },
    { id: 2, username: 'operator', firstName: 'Op', lastName: 'Erator', email: 'op@example.com' },
];

// One message (source connector only) so the message browser has a selectable row.
export const SAMPLE_MESSAGE = {
    messageId: '12345',
    channelId: 'c-started',
    serverId: 's1',
    receivedDate: { time: 1700000000000 },
    processed: true,
    connectorMessages: { entry: [{
        int: 0,
        connectorMessage: {
            metaDataId: 0,
            connectorName: 'Source',
            status: 'RECEIVED',
            receivedDate: { time: 1700000000000 },
            raw: { content: 'MSH|^~\\&|SENDER|FAC|RECV|FAC|20231101||ADT^A01|MSG00001|P|2.3' }
        }
    }] }
};

/** Authenticated happy-path defaults. Tests override individual keys as needed. */
export const DEFAULT_FIXTURES = {
    // Auth — current returns a user, so boot skips the login screen by default
    // (the login-flow spec overrides these to drive the real form).
    'GET /users/current': { user: SAMPLE_USER },
    'POST /users/_login': { status: 'SUCCESS', message: 'ok' },
    'POST /users/_logout': '',
    'GET /users/*/preferences/firstlogin': 'false',

    // Server identity (status bar / shell).
    'GET /server/version': '4.5.0',
    'GET /server/id': 'e2e-server-1',
    'GET /server/timezone': 'EST (UTC -5)',
    'GET /server/settings': { serverSettings: { serverName: 'E2E Engine', environmentName: 'test' } },
    'GET /server/about': '',
    'GET /server/channelTags': '<set/>',
    'GET /server/channelDependencies': '',
    'GET /server/channelMetadata': {},

    // Dashboard + channels.
    'GET /channels/statuses': { list: { dashboardStatus: SAMPLE_STATUSES } },
    'GET /channels/statistics': { list: { channelStatistics: [] } },
    'GET /channels': { list: { channel: SAMPLE_CHANNELS } },
    'GET /channels/idsAndNames': { map: { entry: [
        { string: ['c-started', 'Demo Started'] },
        { string: ['c-stopped', 'Demo Stopped'] }
    ] } },
    'GET /channelgroups': '',

    // Users view + the roles panel's user-role assignment table.
    'GET /users': { list: { user: SAMPLE_USERS } },

    // Settings tabs visited by the matrix.
    'GET /server/configurationMap': { map: { entry: [
        { string: 'db.url', 'com.mirth.connect.util.ConfigurationProperty': { value: 'jdbc:postgresql://db/oie', comment: 'Primary DB' } }
    ] } },

    // Message browser (channel c-started): one message, then empty pages.
    'GET /channels/c-started/messages': (req) => {
        const offset = Number(new URL(req.url()).searchParams.get('offset') || 0);
        return { list: { message: offset > 0 ? [] : [SAMPLE_MESSAGE] } };
    },
    'GET /channels/c-started/messages/count': { long: 1 },
    // The browser bounds each search at the channel's current maximum message id.
    'GET /channels/c-started/messages/maxMessageId': { long: 12345 },
    'GET /channels/c-started/messages/12345': SAMPLE_MESSAGE,
    'GET /channels/c-started/messages/12345/attachments': '',
    'GET /channels/c-started/connectorNames': { map: { entry: [{ int: 0, string: 'Source' }] } },
    'GET /channels/c-started/metaDataColumns': '',

    // Extensions (restart watcher / extensions view) — empty maps.
    'GET /extensions/connectors': {},
    'GET /extensions/plugins': {},

    // Channel lifecycle — accept and no-op.
    'POST /channels/*/_start': '',
    'POST /channels/*/_stop': '',
    'POST /channels/*/_deploy': '',
};

/* ---- RBAC wire shapes (pinned live captures) --------------------------------- */

// GET /extensions/rbac/my-permissions for an Administrator-role holder —
// verbatim live capture: the full core catalog plus the extension permissions
// (rbac's own "View Roles"/"Manage Roles" and the dashboard-plugin ones).
export const FULL_PERMISSIONS = [
    'viewAlerts', 'manageAlerts', 'viewDashboard', 'viewChannels', 'viewChannelGroups',
    'manageChannels', 'clearStatistics', 'startStopChannels', 'deployUndeployChannels',
    'viewCodeTemplates', 'manageCodeTemplates', 'viewGlobalScripts', 'editGlobalScripts',
    'viewMessages', 'removeMessages', 'removeResults', 'removeAllMessages',
    'processMessages', 'reprocessMessages', 'reprocessResults', 'importMessages',
    'exportMessagesServer', 'viewTags', 'manageTags', 'viewEvents', 'removeEvents',
    'manageUsers', 'manageExtensions', 'backupServerConfiguration',
    'restoreServerConfiguration', 'viewServerSettings', 'editServerSettings',
    'clearLifetimeStats', 'sendTestEmail', 'viewConfigurationMap', 'editConfigurationMap',
    'editDatabaseDrivers', 'viewDatabaseTasks', 'manageDatabaseTasks', 'viewResources',
    'editResources', 'reloadResources', 'Manage Roles', 'View Thread Viewer',
    'View Roles', 'Save Settings', 'View Global Maps', 'View Connection Status',
    'Start / Stop', 'View Settings', 'View Server Log'
];

// The plugin's read-only preset (rbac-core READ_ONLY_PERMISSIONS): all 13 view
// permissions and nothing else.
export const READ_ONLY_PERMISSIONS = [
    'viewDashboard', 'viewChannels', 'viewChannelGroups', 'viewTags',
    'viewMessages', 'viewAlerts', 'viewCodeTemplates', 'viewGlobalScripts',
    'viewEvents', 'viewServerSettings', 'viewConfigurationMap',
    'viewDatabaseTasks', 'viewResources'
];

/** Set<String> wire shape: {"linked-hash-set":{"string":[...]}}; empty set → "". */
export function permissionSet(perms) {
    if (!perms.length) return { 'linked-hash-set': '' };
    return { 'linked-hash-set': { string: perms.length === 1 ? perms[0] : perms } };
}

/** Map<String,String> wire shape: {"linked-hash-map":{"entry":[{"string":[k,v]}]}}. */
export function taskPermissionMap(entries) {
    if (!entries.length) return { 'linked-hash-map': '' };
    return { 'linked-hash-map': { entry: entries.map(([k, v]) => ({ string: [k, v] })) } };
}

// GET /extensions/rbac/task-permissions — verbatim live capture: bare task
// names declared by the other installed extensions (dashboard plugins).
export const LIVE_TASK_PERMISSIONS = taskPermissionMap([
    ['doSave', 'Save Settings'],
    ['doStop', 'Start / Stop'],
    ['doStart', 'Start / Stop'],
    ['doRefresh', 'View Settings']
]);

// Roles in the live capture shape: FQCN root (Role has no XStream alias),
// channelIds:null and restricted:false for an unrestricted role, isAdmin and
// restricted real JSON booleans.
export const ADMIN_ROLE = {
    id: 1, name: 'Administrator',
    description: 'Full access to all operations and channels',
    permissions: { string: FULL_PERMISSIONS.filter((p) => !p.includes(' ')) },
    channelIds: null,
    restricted: false,
    isAdmin: true
};

export const READ_ONLY_ROLE = {
    id: 2, name: 'Read Only',
    description: 'View-only access',
    permissions: { string: READ_ONLY_PERMISSIONS },
    channelIds: null,
    restricted: false,
    isAdmin: false
};

/** {"list":{"com.diridium.rbac.Role":...}} — a one-role list collapses to a bare object (XStream). */
export function rolesList(roles) {
    return { list: { 'com.diridium.rbac.Role': roles.length === 1 ? roles[0] : roles } };
}

/** Baseline RBAC servlet fixtures for an admin session; specs override per profile. */
export function rbacFixtures({
    myPermissions = FULL_PERMISSIONS,
    taskPermissions = LIVE_TASK_PERMISSIONS,
    roles = [ADMIN_ROLE, READ_ONLY_ROLE],
    userRole = ADMIN_ROLE
} = {}) {
    return {
        'GET /extensions/rbac/my-permissions': Array.isArray(myPermissions) ? permissionSet(myPermissions) : myPermissions,
        'GET /extensions/rbac/permissions': permissionSet(FULL_PERMISSIONS),
        'GET /extensions/rbac/task-permissions': taskPermissions,
        'GET /extensions/rbac/roles': rolesList(roles),
        'GET /extensions/rbac/users/*/role': { 'com.diridium.rbac.Role': userRole }
    };
}

/* ---- role export and import (the export file and the refusal are verbatim from the wire probe, rbac 1.2.0 on OIE 4.7.0) ---- */

// GET /extensions/rbac/roles/_export: text/plain, the file as written.
export const EXPORT_FILE = `<?xml version="1.0" encoding="UTF-8"?>
<rbacRoles formatVersion="1" rbacVersion="1.2.0" engineVersion="4.7.0">
  <role>
    <name>probe lab</name>
    <description>rbac e2e</description>
    <permissions>
      <permission>viewChannels</permission>
      <permission>viewDashboard</permission>
    </permissions>
    <channels restricted="true">
      <channel id="4c468ff3-0cf7-4e8b-88e7-a7d8a3b538bf" name="probe one"/>
      <channel id="ee366a8b-755b-4f73-9f1b-abe1801cc121" name="probe two"/>
    </channels>
  </role>
  <role>
    <name>probe everyone</name>
    <description>rbac e2e</description>
    <permissions>
      <permission>viewChannels</permission>
    </permissions>
    <channels restricted="false"/>
  </role>
</rbacRoles>
`;

// POST /extensions/rbac/roles/_import answers, built by hand in the shape a real
// engine sends (captured in web/wire-parsing.test.mjs from wire-probe-3.log):
// lists under their FQCN root, one element as a bare object or string, an empty
// list as null, a null name or description left out.
const RESULT = 'com.diridium.rbac.RoleImportResult';
const wireList = (fqcn, items) => (items.length === 0 ? null : { [fqcn]: items.length === 1 ? items[0] : items });
const wireStrings = (items) => (items.length === 0 ? null : { string: items.length === 1 ? items[0] : items });
const wireChannels = (items) => wireList('com.diridium.rbac.RoleImportChannel', items);
// A channel from the file, found by id: its id in the file is its id. A "now" entry overrides fileId and fileName with null.
const channel = (id, name, over = {}) => ({ id, name, fileId: id, fileName: name, match: 'BY_ID', used: true, ...over });
const nowChannel = (id, name, over = {}) => channel(id, name, { fileId: null, fileName: null, ...over });

function wireRow(over) {
    const row = {
        index: 0, name: 'role', action: 'CREATE', droppedPermissions: [], matchedChannelCount: 0, channels: 'FROM_FILE',
        noChannelFound: false, existsHere: false, restrictedNow: false, restrictedAfter: false, descriptionNow: null, descriptionAfter: '',
        permissionsNow: [], permissionsAfter: [], channelsNow: [], channelsAfter: [], ...over
    };
    return {
        ...row,
        droppedPermissions: wireStrings(row.droppedPermissions),
        permissionsNow: wireStrings(row.permissionsNow),
        permissionsAfter: wireStrings(row.permissionsAfter),
        channelsNow: wireChannels(row.channelsNow),
        channelsAfter: wireChannels(row.channelsAfter)
    };
}

function wireResult(rows, over = {}) {
    return {
        [RESULT]: {
            importable: true, formatVersion: 1, sourceRbacVersion: '1.2.0', sourceEngineVersion: '4.7.0',
            applyChannels: true, matchChannelsByName: false, applied: false, planToken: 'hand-written-token',
            rows: wireList('com.diridium.rbac.RoleImportRow', rows),
            channelNameMatches: null, ...over
        }
    };
}

const ONE = '4c468ff3-0cf7-4e8b-88e7-a7d8a3b538bf';
const TWO = 'ee366a8b-755b-4f73-9f1b-abe1801cc121';
const NEW_LAB = wireRow({
    index: 0, name: 'probe lab', action: 'CREATE', matchedChannelCount: 2, restrictedAfter: true,
    descriptionAfter: 'rbac e2e', permissionsAfter: ['viewChannels', 'viewDashboard'],
    channelsAfter: [channel(ONE, 'probe one'), channel(TWO, 'probe two')]
});
export const IMPORT_PREVIEW_TWO_ROWS = wireResult([
    NEW_LAB,
    wireRow({
        index: 1, name: 'probe everyone', action: 'UNCHANGED', existsHere: true,
        descriptionNow: 'rbac e2e', descriptionAfter: 'rbac e2e',
        permissionsNow: ['viewChannels'], permissionsAfter: ['viewChannels'],
        reason: 'Identical to the role on this engine.'
    })
]);

const MOVED = '8163af3f-7ed2-4a0c-b326-34830263c504';
const NAME_MATCH = { name: 'probe one', fileChannelId: MOVED, channelId: ONE };
// Notes as the server composes them (RoleImportPlanner.notes). A role whose only channel is found by name alone
// has no channel found while matching by name is off: New, restricted to no channel, ticked like any New role.
export const IMPORT_NAME_MATCH_OFF = wireResult([wireRow({
    index: 0, name: 'probe moved one', action: 'CREATE', noChannelFound: true, restrictedAfter: true,
    reason: 'The import restricts this role to 1 channel. None of those channels exist on this engine. If imported,'
        + ' this role is restricted to no channels until an administrator sets channels for this role.'
        + ' 1 of those channels matches a channel on this engine by name.',
    descriptionAfter: 'moved', permissionsAfter: ['viewChannels'],
    channelsAfter: [channel(ONE, 'probe one', { fileId: MOVED, match: 'BY_NAME', used: false })]
})], { channelNameMatches: { 'com.diridium.rbac.ChannelNameMatch': NAME_MATCH } });
export const IMPORT_NAME_MATCH_ON = wireResult([wireRow({
    index: 0, name: 'probe moved one', action: 'CREATE', matchedChannelCount: 1, restrictedAfter: true,
    reason: '1 of those channels matches a channel on this engine by name.',
    descriptionAfter: 'moved', permissionsAfter: ['viewChannels'],
    channelsAfter: [channel(ONE, 'probe one', { fileId: MOVED, match: 'BY_NAME' })]
})], { matchChannelsByName: true, channelNameMatches: { 'com.diridium.rbac.ChannelNameMatch': NAME_MATCH } });

// An Overwrite of the role "Lab": a renamed channel, a deleted one in the Now list, a dropped permission.
const NOWHERE = 'bbb4ce36-25d9-4830-9644-7fcd5682f5fd';
const LAB_OVERWRITE = wireRow({
    index: 0, name: 'Lab', action: 'OVERWRITE', existsHere: true, matchedChannelCount: 2,
    restrictedNow: true, restrictedAfter: true,
    droppedPermissions: ['oldPermission'],
    reason: 'Of the 3 channels in the import, 1 is not on this engine.'
        + ' 1 permission in the import is not offered by this engine and is left out.',
    descriptionNow: 'Lab staff', descriptionAfter: 'Lab team',
    permissionsNow: ['viewAlerts', 'viewChannels'], permissionsAfter: ['viewChannels', 'viewDashboard'],
    channelsNow: [nowChannel(ONE, 'probe one'), nowChannel('gone-id', null, { match: 'NOT_FOUND' })],
    channelsAfter: [channel(ONE, 'probe one renamed', { fileName: 'probe one' }), channel(TWO, 'probe two'),
        channel(NOWHERE, 'probe nowhere', { match: 'NOT_FOUND', used: false })]
});
export const IMPORT_OVERWRITE_DETAILS = wireResult([LAB_OVERWRITE]);

// Four roles: Lab (as above), one that goes from one channel to every channel and gains a permission, one that
// goes from every channel to two, and a new one.
export const IMPORT_SEVERAL_ROWS = wireResult([
    LAB_OVERWRITE,
    wireRow({
        index: 1, name: 'Day', action: 'OVERWRITE', existsHere: true, matchedChannelCount: 0, restrictedNow: true,
        reason: 'On this engine this role is restricted to 1 channel. The import removes the restriction, so after the'
            + ' import this role will see every channel.',
        descriptionNow: 'Day shift', descriptionAfter: 'Day team',
        permissionsNow: ['viewChannels'], permissionsAfter: ['viewChannels', 'viewDashboard', 'viewAlerts'],
        channelsNow: [nowChannel(ONE, 'probe one')], channelsAfter: []
    }),
    wireRow({
        index: 2, name: 'Night', action: 'OVERWRITE', existsHere: true, matchedChannelCount: 2, restrictedAfter: true,
        reason: 'On this engine this role sees every channel. The import restricts this role to 2 channels.',
        descriptionNow: 'Night shift', descriptionAfter: 'Night team',
        permissionsNow: ['viewChannels'], permissionsAfter: ['viewChannels'],
        channelsNow: [], channelsAfter: [channel(ONE, 'probe one'), channel(TWO, 'probe two')]
    }),
    { ...NEW_LAB, index: 3, name: 'Fresh' }
]);

// An Overwrite of "Ward" showing every Match value: found by id, deleted on this engine but named in the import,
// in the import but not on this engine, a channel the role has that the import does not name, and a deleted one
// the import does not name.
const GONE_NAMED = '0a1b2c3d-1111-4222-8333-444455556666';
export const IMPORT_MATCH_VALUES = wireResult([wireRow({
    index: 0, name: 'Ward', action: 'OVERWRITE', existsHere: true, matchedChannelCount: 1,
    restrictedNow: true, restrictedAfter: true,
    reason: 'Of the 3 channels in the import, 2 are not on this engine.',
    descriptionNow: 'Ward staff', descriptionAfter: 'Ward team',
    permissionsNow: ['viewChannels'], permissionsAfter: ['viewChannels'],
    channelsNow: [nowChannel(ONE, 'probe one'), nowChannel('now-only-id', 'probe three'),
        nowChannel('gone-id', null, { match: 'NOT_FOUND' }), nowChannel(GONE_NAMED, null, { match: 'NOT_FOUND' })],
    channelsAfter: [channel(ONE, 'probe one'),
        channel(GONE_NAMED, null, { fileName: 'probe gone', match: 'NOT_FOUND', used: false }),
        channel(NOWHERE, 'probe nowhere', { match: 'NOT_FOUND', used: false })]
})]);

// Roles restricted to no channel: one that stays so, one that goes to every channel, one that goes from every
// channel to none, and a New role restricted to no channel.
export const IMPORT_NONE_ROWS = wireResult([
    wireRow({
        index: 0, name: 'Quiet', action: 'OVERWRITE', existsHere: true, restrictedNow: true, restrictedAfter: true,
        descriptionNow: 'Quiet', descriptionAfter: 'Quiet team',
        permissionsNow: ['viewChannels'], permissionsAfter: ['viewChannels']
    }),
    wireRow({
        index: 1, name: 'Reopen', action: 'OVERWRITE', existsHere: true, restrictedNow: true,
        descriptionNow: 'Reopen', descriptionAfter: 'Reopen team',
        permissionsNow: ['viewChannels'], permissionsAfter: ['viewChannels']
    }),
    wireRow({
        index: 2, name: 'Close', action: 'OVERWRITE', existsHere: true, restrictedAfter: true,
        descriptionNow: 'Close', descriptionAfter: 'Close team',
        permissionsNow: ['viewChannels'], permissionsAfter: ['viewChannels']
    }),
    wireRow({ index: 3, name: 'Fresh none', action: 'CREATE', restrictedAfter: true, descriptionAfter: 'none',
        permissionsAfter: ['viewChannels'] })
]);

// A New role whose import channels exist nowhere on this engine, with the apply box ticked: it is restricted to no channel.
export const IMPORT_NO_CHANNEL_FOUND = wireResult([wireRow({
    index: 0, name: 'probe lost', action: 'CREATE', noChannelFound: true, restrictedAfter: true,
    reason: 'The import restricts this role to 1 channel. None of those channels exist on this engine. If imported,'
        + ' this role is restricted to no channels until an administrator sets channels for this role.',
    descriptionAfter: 'lost', permissionsAfter: ['viewChannels'],
    channelsAfter: [channel(NOWHERE, 'probe nowhere', { match: 'NOT_FOUND', used: false })]
}), { ...NEW_LAB, index: 1 }]);

export const IMPORT_APPLIED = wireResult([NEW_LAB], { applied: true });
export const IMPORT_REFUSED = JSON.parse(
    '{"com.diridium.rbac.RoleImportResult":{"importable":false,"refusal":"This file is format 2, written by rbac 9. This rbac reads format 1.","applyChannels":true,"matchChannelsByName":false,"applied":false,"rows":null,"channelNameMatches":null}}');
