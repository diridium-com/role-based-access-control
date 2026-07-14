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
    'GET /server/channelTags': '',
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
// channelIds:null for an unrestricted role, isAdmin a real JSON boolean.
export const ADMIN_ROLE = {
    id: 1, name: 'Administrator',
    description: 'Full access to all operations and channels',
    permissions: { string: FULL_PERMISSIONS.filter((p) => !p.includes(' ')) },
    channelIds: null,
    isAdmin: true
};

export const READ_ONLY_ROLE = {
    id: 2, name: 'Read Only',
    description: 'View-only access',
    permissions: { string: READ_ONLY_PERMISSIONS },
    channelIds: null,
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
