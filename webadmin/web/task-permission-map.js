// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

/*
 * Hand-maintained task → permission map and authorization controller for the
 * OIE web administrator — the web twin of the Swing client's
 * SecureAuthorizationController.buildPermissionMaps() in
 * client/src/main/java/com/mirth/connect/plugins/auth/client/SecureAuthorizationController.java.
 *
 * The web administrator's task identifiers are verbatim Swing TaskConstants
 * (see oie-web-client web-administrator/RBAC.md §3 — 100% catalog parity), so
 * this map is a mechanical 1:1 port of the Swing one. Keep BOTH files in
 * lockstep, and keep the sibling task-permission-map.json parity artifact in
 * lockstep with this file: a unit test asserts this module equals the JSON,
 * and a Java-side test can diff Swing's map against the same JSON. When a
 * mapping changes, change all three.
 *
 * Semantics (mirroring the Swing controller): a mapped task is shown only if
 * the user's permission set contains the mapped permission; an unmapped task
 * is allowed through (the server-side controller enforces the real check);
 * when the permission set could not be loaded at all, EVERY task is denied
 * (fail closed) while a throttled async reload retries in the background.
 */

/**
 * Bare taskName → permission, for task names that are unique across groups.
 * Port of the Swing taskPermissionMap. Section comments match the Swing file.
 */
export const TASK_PERMISSIONS = {
    // ========== View Navigation ==========
    doShowDashboard: 'viewDashboard',
    doShowChannel: 'viewChannels',
    doShowUsers: 'manageUsers',
    // doShowSettings intentionally unmapped - always shown; individual tabs gated below
    doShowAlerts: 'viewAlerts',
    doShowEvents: 'viewEvents',
    doShowExtensions: 'manageExtensions',

    // ========== Dashboard ==========
    doRefreshStatuses: 'viewDashboard',
    // doFilter has no tagged control in the web administrator today (RBAC.md's
    // dashboard group does not list it) — kept anyway for 1:1 Swing parity, so
    // the JSON parity artifact equals the Swing map and a future tagged filter
    // control hides correctly.
    doFilter: 'viewDashboard',
    doSendMessage: 'processMessages', // shared task name: dashboard + message groups
    doShowMessages: 'viewMessages',
    doRemoveAllMessages: 'removeAllMessages', // shared task name: dashboard + message groups
    doClearStats: 'clearStatistics',
    doStart: 'startStopChannels',
    doPause: 'startStopChannels',
    doStop: 'startStopChannels',
    doHalt: 'startStopChannels',
    doUndeployChannel: 'deployUndeployChannels',
    doStartConnector: 'startStopChannels',
    doStopConnector: 'startStopChannels',

    // ========== Channels ==========
    doRefreshChannels: 'viewChannels',
    doRedeployAll: 'deployUndeployChannels',
    doDeployChannel: 'deployUndeployChannels',
    doDeployInDebug: 'deployUndeployChannels',
    doEditGlobalScripts: 'viewGlobalScripts',
    doEditCodeTemplates: 'viewCodeTemplates',
    doNewChannel: 'manageChannels',
    doImportChannel: 'manageChannels',
    doExportAllChannels: 'viewChannels',
    doExportChannel: 'viewChannels', // shared task name: channel + channelEdit groups
    doDeleteChannel: 'manageChannels',
    doCloneChannel: 'manageChannels',
    doEditChannel: 'manageChannels',
    doEnableChannel: 'manageChannels',
    doDisableChannel: 'manageChannels',
    doViewMessages: 'viewMessages',

    // ========== Channel Edit ==========
    doSaveChannel: 'manageChannels',
    doValidate: 'manageChannels',
    doNewDestination: 'manageChannels',
    doDeleteDestination: 'manageChannels',
    doCloneDestination: 'manageChannels',
    doEnableDestination: 'manageChannels',
    doDisableDestination: 'manageChannels',
    doMoveDestinationUp: 'manageChannels',
    doMoveDestinationDown: 'manageChannels',
    doEditFilter: 'manageChannels',
    doEditTransformer: 'manageChannels',
    doEditResponseTransformer: 'manageChannels',
    doImportConnector: 'manageChannels',
    doExportConnector: 'viewChannels',
    doValidateChannelScripts: 'manageChannels',
    doDeployFromChannelView: 'deployUndeployChannels',
    doDebugDeployFromChannelView: 'deployUndeployChannels',

    // ========== Channel Groups ==========
    // Engine gates updateChannelGroups (which covers create/update/delete) on
    // Permissions.CHANNELS_MANAGE — only the read/export paths use viewChannelGroups.
    doSaveGroups: 'manageChannels',
    doNewGroup: 'manageChannels',
    doAssignChannelToGroup: 'manageChannels',
    doEditGroupDetails: 'manageChannels',
    doImportGroup: 'manageChannels',
    doDeleteGroup: 'manageChannels',
    doExportAllGroups: 'viewChannelGroups',
    doExportGroup: 'viewChannelGroups',

    // ========== Messages ==========
    doRefreshMessages: 'viewMessages',
    doImportMessages: 'importMessages',
    // doExportMessages / doExportAttachment are deliberately gated on the stronger
    // exportMessagesServer permission even though the export dialogs also offer a
    // purely local (client-side) export whose REST calls only need viewMessages.
    // Hiding both buttons from a viewMessages-only role over-restricts the local
    // path, but that is the PHI-conservative (fail-safe) direction and not a
    // security hole, so it is kept.
    doExportMessages: 'exportMessagesServer',
    // Bulk-by-filter operations use a different engine permission than the
    // single-message variants. Engine: removeMessages (filtered) is gated on
    // MESSAGES_REMOVE_RESULTS; reprocessMessages (filtered) on MESSAGES_REPROCESS_RESULTS.
    doRemoveFilteredMessages: 'removeResults',
    doRemoveMessage: 'removeMessages',
    doReprocessFilteredMessages: 'reprocessResults',
    doReprocessMessage: 'reprocessMessages',
    viewImage: 'viewMessages',
    doExportAttachment: 'exportMessagesServer',

    // ========== Alerts ==========
    doRefreshAlerts: 'viewAlerts',
    doNewAlert: 'manageAlerts',
    doImportAlert: 'manageAlerts',
    doExportAlerts: 'viewAlerts',
    doExportAlert: 'viewAlerts', // shared task name: alert + alertEdit groups
    doDeleteAlert: 'manageAlerts',
    doEditAlert: 'manageAlerts',
    doEnableAlert: 'manageAlerts',
    doDisableAlert: 'manageAlerts',

    // ========== Alert Edit ==========
    doSaveAlerts: 'manageAlerts',

    // ========== Users ==========
    doRefreshUser: 'manageUsers',
    doNewUser: 'manageUsers',
    doEditUser: 'manageUsers',
    doDeleteUser: 'manageUsers',

    // ========== Events ==========
    doRefreshEvents: 'viewEvents',
    doExportAllEvents: 'viewEvents',

    // ========== Code Templates ==========
    doRefreshCodeTemplates: 'viewCodeTemplates',
    doSaveCodeTemplates: 'manageCodeTemplates',
    doNewCodeTemplate: 'manageCodeTemplates',
    doNewLibrary: 'manageCodeTemplates',
    doImportCodeTemplates: 'manageCodeTemplates',
    doImportLibraries: 'manageCodeTemplates',
    doExportCodeTemplate: 'viewCodeTemplates',
    doExportLibrary: 'viewCodeTemplates',
    doExportAllLibraries: 'viewCodeTemplates',
    doDeleteCodeTemplate: 'manageCodeTemplates',
    doDeleteLibrary: 'manageCodeTemplates',
    doValidateCodeTemplate: 'viewCodeTemplates',

    // ========== Global Scripts ==========
    doSaveGlobalScripts: 'editGlobalScripts',
    doValidateCurrentGlobalScript: 'viewGlobalScripts',
    doImportGlobalScripts: 'editGlobalScripts',
    doExportGlobalScripts: 'viewGlobalScripts',

    // ========== Extensions ==========
    doRefreshExtensions: 'manageExtensions',
    doEnableExtension: 'manageExtensions',
    doDisableExtension: 'manageExtensions',
    doShowExtensionProperties: 'manageExtensions',
    doUninstallExtension: 'manageExtensions',
};

/**
 * "taskGroup/taskName" → permission, for settings panels where the generic
 * doRefresh/doSave task names are shared by every tab. Port of the Swing
 * groupTaskPermissionMap (checked BEFORE the bare map, exactly like Swing).
 */
export const GROUP_TASK_PERMISSIONS = {
    // ========== Settings Panels (group-specific for shared doRefresh/doSave) ==========

    // Server Settings
    'settings_Server/doRefresh': 'viewServerSettings',
    'settings_Server/doSave': 'editServerSettings',
    'settings_Server/doBackup': 'backupServerConfiguration',
    'settings_Server/doRestore': 'restoreServerConfiguration',
    'settings_Server/doClearAllStats': 'clearLifetimeStats',

    // Tags
    'settings_Tags/doRefresh': 'viewTags',
    'settings_Tags/doSave': 'manageTags',

    // Configuration Map (the in-panel Add Row button rides doSave — RBAC.md §3)
    'settings_Configuration Map/doRefresh': 'viewConfigurationMap',
    'settings_Configuration Map/doSave': 'editConfigurationMap',
    'settings_Configuration Map/doImportMap': 'editConfigurationMap',
    'settings_Configuration Map/doExportMap': 'viewConfigurationMap',

    // Database Tasks
    'settings_Database Tasks/doRefresh': 'viewDatabaseTasks',
    'settings_Database Tasks/doSave': 'manageDatabaseTasks',
    'settings_Database Tasks/doRunDatabaseTask': 'manageDatabaseTasks',
    'settings_Database Tasks/doCancelDatabaseTask': 'manageDatabaseTasks',

    // Resources
    'settings_Resources/doRefresh': 'viewResources',
    'settings_Resources/doSave': 'editResources',
    'settings_Resources/doAddResource': 'editResources',
    'settings_Resources/doRemoveResource': 'editResources',
    'settings_Resources/doReloadResource': 'reloadResources',

    // RBAC plugin settings panel (RbacServletInterface.PLUGIN_NAME /
    // PERMISSION_VIEW / PERMISSION_MANAGE)
    'settings_Role-Based Access Control/doRefresh': 'View Roles',
    'settings_Role-Based Access Control/doSave': 'Manage Roles',
};

/**
 * Catalog identifiers (RBAC.md §3, as "taskGroup/taskName") that are known and
 * deliberately NOT mapped, so they fall through checkTask's unknown-task allow
 * branch. The map-completeness unit test requires every catalog identifier to
 * be either mapped above or listed here — anything else is drift.
 *
 * Web-only items with no Swing task (RBAC.md §4: Change Password, Install
 * Extension, Add/Remove Tag, editor Back buttons, …) are intentionally left
 * UNTAGGED in the host, so they never reach checkTask and have no identifier
 * to list here.
 */
export const DELIBERATELY_UNMAPPED = [
    // Settings nav is always shown (like Swing); individual tabs are gated instead.
    'view/doShowSettings',

    // The engine's "Administrator" settings tab only reads/writes the CURRENT
    // user's own client preferences, and its backing REST ops
    // (setUserPreferences/setUserPreference) are self-scoped server-side, so it
    // is safe to show to everyone.
    'settings_Administrator/doRefresh',
    'settings_Administrator/doSave',
    'settings_Administrator/doSetAdminDefaults',

    // The "Other" rail pane — help/about/logout style items, never gated in Swing.
    'other/goToUserAPI',
    'other/goToClientAPI',
    'other/doHelp',
    'other/goToAbout',
    'other/goToMirth',
    'other/doReportIssue',
    'other/doLogout',
];

/** Minimum interval between fail-closed reload() attempts (Swing RETRY_BACKOFF_MS). */
export const RELOAD_BACKOFF_MS = 15000;

/**
 * Merges plugin-supplied task→permission mappings (the RBAC servlet's
 * /task-permissions endpoint) into the local maps — the web port of the Swing
 * controller's mergeExtensionTaskPermissions().
 *
 * Keys containing "/" are treated as group-prefixed composites (e.g.
 * "settings_FooPlugin/doRefresh") and merged into GROUP_TASK_PERMISSIONS;
 * bare keys go into TASK_PERMISSIONS. Hardcoded entries win (putIfAbsent) so
 * a misbehaving plugin cannot weaken a core mapping we already know about.
 *
 * @param {Record<string, string>|null|undefined} extensionTaskPerms null/empty is a no-op
 */
export function mergeExtensionTaskPermissions(extensionTaskPerms) {
    if (extensionTaskPerms == null) return;
    for (const [taskName, permission] of Object.entries(extensionTaskPerms)) {
        if (!taskName || typeof permission !== 'string' || !permission) continue;
        if (taskName === '__proto__') continue; // plain-object maps: never touch the prototype key
        const map = taskName.includes('/') ? GROUP_TASK_PERMISSIONS : TASK_PERMISSIONS;
        if (!Object.hasOwn(map, taskName)) {
            map[taskName] = permission; // putIfAbsent — hardcoded wins
        }
    }
}

/**
 * Creates the authorization controller to hand to
 * platform.setAuthorizationController() — the web port of the Swing
 * controller's checkTask()/lazy-retry semantics.
 *
 * Resolution order: (1) GROUP_TASK_PERMISSIONS["group/task"]; (2)
 * TASK_PERMISSIONS[task]; (3) unknown task — allow (the server enforces the
 * real check). If getPermissions() returns null/undefined the controller
 * fails closed (denies EVERYTHING, mapped or not) and fires reload()
 * asynchronously, at most once per RELOAD_BACKOFF_MS, so a persistently
 * failing load cannot turn every render into a request storm. checkTask
 * itself is always synchronous and never throws.
 *
 * @param {object} deps
 * @param {() => (Set<string>|string[]|null)} deps.getPermissions the user's
 *        loaded permission set, or null while it could not be loaded
 * @param {() => (void|Promise<void>)} [deps.reload] re-fetches permissions;
 *        fired fire-and-forget from the fail-closed path
 * @returns {{ checkTask(taskGroup: string, taskName: string): boolean }}
 */
export function createController({ getPermissions, reload }) {
    let lastReloadAttemptMs = 0;
    return {
        checkTask(taskGroup, taskName) {
            const permissions = getPermissions();
            if (permissions == null) {
                const now = Date.now();
                if (typeof reload === 'function' && now - lastReloadAttemptMs > RELOAD_BACKOFF_MS) {
                    lastReloadAttemptMs = now;
                    // Async and fire-and-forget: checkTask runs synchronously
                    // during render, so the retry must never block or throw.
                    Promise.resolve().then(reload).catch(() => {});
                }
                return false; // fail closed — permissions couldn't be loaded
            }

            const composite = `${taskGroup}/${taskName}`;
            let required;
            if (Object.hasOwn(GROUP_TASK_PERMISSIONS, composite)) {
                required = GROUP_TASK_PERMISSIONS[composite];
            } else if (Object.hasOwn(TASK_PERMISSIONS, taskName)) {
                required = TASK_PERMISSIONS[taskName];
            }
            if (required == null) {
                return true; // unknown task — allow (server enforces the real check)
            }
            return typeof permissions.has === 'function'
                ? permissions.has(required)
                : permissions.includes(required);
        },
    };
}
