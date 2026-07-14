// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.mirth.connect.plugins.auth.client;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.diridium.rbac.RbacServletInterface;
import com.mirth.connect.client.core.TaskConstants;
import com.mirth.connect.client.ui.AuthorizationController;
import com.mirth.connect.client.ui.PlatformUI;

/**
 * Client-side authorization controller installed by {@link com.diridium.rbac.RbacClientPlugin}
 * via reflection on the engine's static {@code AuthorizationControllerFactory}.
 *
 * <p>This class lives in the {@code com.mirth.connect.plugins.auth.client}
 * package by necessity — the engine's factory expects the FQCN to be in that
 * package. Don't move it.</p>
 *
 * <p>{@link #checkTask} runs synchronously for every UI button/menu/task
 * rendered by the administrator client. It looks up the task name (and
 * optional group prefix) in a hand-maintained map of task→permission and
 * compares against the user's loaded permission set fetched via the
 * {@code getMyPermissions} REST endpoint at {@link #initialize}.</p>
 *
 * <p>Two states. While the user's permissions ARE loaded, a mapped task is
 * shown only if the user holds the mapped permission, and a task with no
 * mapping is allowed through (the server-side controller enforces the real
 * check). When permissions cannot be loaded at all, the controller fails
 * closed and denies EVERY task — mapped or not — so no privileged action is
 * exposed on a half-initialized client.</p>
 */
public class SecureAuthorizationController implements AuthorizationController {

    private static final Logger log = LoggerFactory.getLogger(SecureAuthorizationController.class);

    private volatile Set<String> userPermissions;
    private volatile boolean loaded = false;

    // Backoff for the lazy retry in checkTask. The engine calls checkTask once per task
    // component on the EDT for every view switch, so a persistently failing load (e.g. the
    // plugin is in migration-failed mode and getMyPermissions always throws) would otherwise
    // fire a burst of blocking REST calls on every repaint. Retry at most once per interval;
    // between attempts checkTask falls through to the fail-closed path.
    private volatile long lastLoadAttemptMs = 0;
    private static final long RETRY_BACKOFF_MS = 15_000;

    // taskName → permission (for unique task names)
    private final Map<String, String> taskPermissionMap = new HashMap<>();

    // "taskGroup/taskName" → permission (for settings panels where doRefresh/doSave are shared)
    private final Map<String, String> groupTaskPermissionMap = new HashMap<>();

    /**
     * Builds the in-memory task→permission map immediately so
     * {@link #checkTask} is a pure lookup. Construction itself does not
     * call any engine services; permissions are loaded lazily on the first
     * {@link #initialize} or {@link #checkTask} call.
     */
    public SecureAuthorizationController() {
        log.info("RBAC SecureAuthorizationController instantiated");
        buildPermissionMaps();
    }

    /**
     * {@inheritDoc}
     * <p>The engine calls this after login completes. Fetches the user's
     * granted permissions via the {@code getMyPermissions} REST endpoint
     * and caches them locally. If the call fails (network, server down,
     * permissions endpoint denied), {@link #checkTask} fails closed until
     * a subsequent lazy retry succeeds.</p>
     */
    @Override
    public void initialize() {
        loadPermissions();
    }

    private void loadPermissions() {
        lastLoadAttemptMs = System.currentTimeMillis();
        try {
            RbacServletInterface rbac = PlatformUI.MIRTH_FRAME.mirthClient.getServlet(RbacServletInterface.class);
            userPermissions = rbac.getMyPermissions();
            mergeExtensionTaskPermissions(rbac.getExtensionTaskPermissions());
            loaded = true;
            log.info("RBAC: Loaded {} permissions for current user", userPermissions.size());
        } catch (Exception e) {
            log.error("RBAC: Failed to load user permissions", e);
            userPermissions = null;
            loaded = false;
        }
    }

    /**
     * Merges plugin-supplied task→permission mappings into our local maps.
     *
     * <p>Keys containing {@code "/"} are treated as group-prefixed composites
     * (e.g. {@code "settings_FooPlugin/doRefresh"}) and stored in the
     * group-specific map; bare keys go into the task-name-only map.</p>
     *
     * <p>Hardcoded entries win via {@link Map#putIfAbsent} so a misbehaving
     * plugin cannot weaken an engine-core mapping we already know about.</p>
     *
     * @param extensionTaskPerms the map returned by the RBAC servlet's
     *                           {@code getExtensionTaskPermissions} endpoint;
     *                           {@code null} or empty is a no-op
     */
    void mergeExtensionTaskPermissions(Map<String, String> extensionTaskPerms) {
        if (extensionTaskPerms == null || extensionTaskPerms.isEmpty()) {
            return;
        }
        for (Map.Entry<String, String> entry : extensionTaskPerms.entrySet()) {
            String taskName = entry.getKey();
            String permission = entry.getValue();
            if (taskName == null || permission == null) {
                continue;
            }
            if (taskName.contains("/")) {
                groupTaskPermissionMap.putIfAbsent(taskName, permission);
            } else {
                taskPermissionMap.putIfAbsent(taskName, permission);
            }
        }
    }

    /**
     * {@inheritDoc}
     * <p>Resolution order: (1) group-specific mapping
     * {@code taskGroup/taskName} (used by settings panels that share
     * generic task names like {@code SETTINGS_REFRESH}); (2) task-name-only
     * mapping; (3) unknown task — allow (server enforces). If the
     * user-permission set hasn't been loaded yet, performs a lazy retry;
     * if it's still null afterward, denies (fail closed).</p>
     *
     * @param taskGroup the task group identifier (e.g.,
     *                  {@code SETTINGS_SERVER_KEY}); may be irrelevant for
     *                  most tasks but matters for settings panels
     * @param taskName  the task constant being checked
     * @return {@code true} to show/enable the task; {@code false} to hide it
     */
    @Override
    public boolean checkTask(String taskGroup, String taskName) {
        // Lazy retry if initialize() failed, but at most once per backoff interval so a
        // persistent failure does not turn every EDT repaint into a REST-call storm.
        if (!loaded && System.currentTimeMillis() - lastLoadAttemptMs > RETRY_BACKOFF_MS) {
            loadPermissions();
        }

        if (userPermissions == null) {
            log.warn("RBAC checkTask: permissions not loaded, denying {}/{}", taskGroup, taskName);
            return false; // Fail-closed - permissions couldn't be loaded
        }

        // Check group-specific mapping first (for settings panels with shared task names)
        String compositeKey = taskGroup + "/" + taskName;
        String requiredPermission = groupTaskPermissionMap.get(compositeKey);

        // Fall back to task-name-only mapping
        if (requiredPermission == null) {
            requiredPermission = taskPermissionMap.get(taskName);
        }

        if (requiredPermission == null) {
            return true; // Unknown task - allow (server enforces the real check)
        }

        boolean allowed = userPermissions.contains(requiredPermission);
        if (!allowed) {
            log.debug("RBAC checkTask: denied {}/{} (requires '{}')", taskGroup, taskName, requiredPermission);
        }
        return allowed;
    }

    /**
     * Hand-maintained task-name &rarr; permission map. The server-side
     * operation map is derived from {@code @MirthOperation} annotations at
     * runtime, but this client map is written by hand and has drifted from
     * engine truth three times in this project's history (channel-group writes,
     * and the {@code _FILTERED} message variants that use {@code *Results}
     * permissions).
     *
     * <p><b>On every engine version bump, re-check this map against the engine's
     * {@code @MirthOperation(permission=...)} annotations</b>, paying special
     * attention to {@code _FILTERED}/{@code _ALL}/{@code _BULK} variants and
     * group/composite tasks where the engine reuses an operation name but gates
     * on a different permission by signature. {@code PermissionMapDriftTest}
     * catches permission strings that don't exist at all; it cannot catch a
     * mapping to a real-but-wrong permission, which is what this manual pass is
     * for.</p>
     *
     * <p><b>Web twin:</b> the web administrator ships the same map in
     * {@code webadmin/web/task-permission-map.js}, with
     * {@code webadmin/web/task-permission-map.json} as the checked-in parity
     * artifact both sides can diff against. When a mapping here changes,
     * change all three.</p>
     */
    private void buildPermissionMaps() {
        // ========== View Navigation ==========
        taskPermissionMap.put(TaskConstants.VIEW_DASHBOARD, "viewDashboard");
        taskPermissionMap.put(TaskConstants.VIEW_CHANNEL, "viewChannels");
        taskPermissionMap.put(TaskConstants.VIEW_USERS, "manageUsers");
        // VIEW_SETTINGS intentionally unmapped - always shown; individual tabs gated below
        taskPermissionMap.put(TaskConstants.VIEW_ALERTS, "viewAlerts");
        taskPermissionMap.put(TaskConstants.VIEW_EVENTS, "viewEvents");
        taskPermissionMap.put(TaskConstants.VIEW_EXTENSIONS, "manageExtensions");

        // ========== Dashboard ==========
        taskPermissionMap.put(TaskConstants.DASHBOARD_REFRESH, "viewDashboard");
        taskPermissionMap.put(TaskConstants.DASHBOARD_FILTER, "viewDashboard");
        taskPermissionMap.put(TaskConstants.DASHBOARD_SEND_MESSAGE, "processMessages");
        taskPermissionMap.put(TaskConstants.DASHBOARD_SHOW_MESSAGES, "viewMessages");
        taskPermissionMap.put(TaskConstants.DASHBOARD_REMOVE_ALL_MESSAGES, "removeAllMessages");
        taskPermissionMap.put(TaskConstants.DASHBOARD_CLEAR_STATS, "clearStatistics");
        taskPermissionMap.put(TaskConstants.DASHBOARD_START, "startStopChannels");
        taskPermissionMap.put(TaskConstants.DASHBOARD_PAUSE, "startStopChannels");
        taskPermissionMap.put(TaskConstants.DASHBOARD_STOP, "startStopChannels");
        taskPermissionMap.put(TaskConstants.DASHBOARD_HALT, "startStopChannels");
        taskPermissionMap.put(TaskConstants.DASHBOARD_UNDEPLOY, "deployUndeployChannels");
        taskPermissionMap.put(TaskConstants.DASHBOARD_START_CONNECTOR, "startStopChannels");
        taskPermissionMap.put(TaskConstants.DASHBOARD_STOP_CONNECTOR, "startStopChannels");

        // ========== Channels ==========
        taskPermissionMap.put(TaskConstants.CHANNEL_REFRESH, "viewChannels");
        taskPermissionMap.put(TaskConstants.CHANNEL_REDEPLOY_ALL, "deployUndeployChannels");
        taskPermissionMap.put(TaskConstants.CHANNEL_DEPLOY, "deployUndeployChannels");
        taskPermissionMap.put(TaskConstants.CHANNEL_DEPLOY_DEBUG, "deployUndeployChannels");
        taskPermissionMap.put(TaskConstants.CHANNEL_EDIT_GLOBAL_SCRIPTS, "viewGlobalScripts");
        taskPermissionMap.put(TaskConstants.CHANNEL_EDIT_CODE_TEMPLATES, "viewCodeTemplates");
        taskPermissionMap.put(TaskConstants.CHANNEL_NEW_CHANNEL, "manageChannels");
        taskPermissionMap.put(TaskConstants.CHANNEL_IMPORT_CHANNEL, "manageChannels");
        taskPermissionMap.put(TaskConstants.CHANNEL_EXPORT_ALL_CHANNELS, "viewChannels");
        taskPermissionMap.put(TaskConstants.CHANNEL_EXPORT_CHANNEL, "viewChannels");
        taskPermissionMap.put(TaskConstants.CHANNEL_DELETE_CHANNEL, "manageChannels");
        taskPermissionMap.put(TaskConstants.CHANNEL_CLONE, "manageChannels");
        taskPermissionMap.put(TaskConstants.CHANNEL_EDIT, "manageChannels");
        taskPermissionMap.put(TaskConstants.CHANNEL_ENABLE, "manageChannels");
        taskPermissionMap.put(TaskConstants.CHANNEL_DISABLE, "manageChannels");
        taskPermissionMap.put(TaskConstants.CHANNEL_VIEW_MESSAGES, "viewMessages");

        // ========== Channel Edit ==========
        taskPermissionMap.put(TaskConstants.CHANNEL_EDIT_SAVE, "manageChannels");
        taskPermissionMap.put(TaskConstants.CHANNEL_EDIT_VALIDATE, "manageChannels");
        taskPermissionMap.put(TaskConstants.CHANNEL_EDIT_NEW_DESTINATION, "manageChannels");
        taskPermissionMap.put(TaskConstants.CHANNEL_EDIT_DELETE_DESTINATION, "manageChannels");
        taskPermissionMap.put(TaskConstants.CHANNEL_EDIT_CLONE_DESTINATION, "manageChannels");
        taskPermissionMap.put(TaskConstants.CHANNEL_EDIT_ENABLE_DESTINATION, "manageChannels");
        taskPermissionMap.put(TaskConstants.CHANNEL_EDIT_DISABLE_DESTINATION, "manageChannels");
        taskPermissionMap.put(TaskConstants.CHANNEL_EDIT_MOVE_DESTINATION_UP, "manageChannels");
        taskPermissionMap.put(TaskConstants.CHANNEL_EDIT_MOVE_DESTINATION_DOWN, "manageChannels");
        taskPermissionMap.put(TaskConstants.CHANNEL_EDIT_FILTER, "manageChannels");
        taskPermissionMap.put(TaskConstants.CHANNEL_EDIT_TRANSFORMER, "manageChannels");
        taskPermissionMap.put(TaskConstants.CHANNEL_EDIT_RESPONSE_TRANSFORMER, "manageChannels");
        taskPermissionMap.put(TaskConstants.CHANNEL_EDIT_IMPORT_CONNECTOR, "manageChannels");
        taskPermissionMap.put(TaskConstants.CHANNEL_EDIT_EXPORT_CONNECTOR, "viewChannels");
        taskPermissionMap.put(TaskConstants.CHANNEL_EDIT_EXPORT, "viewChannels");
        taskPermissionMap.put(TaskConstants.CHANNEL_EDIT_VALIDATE_SCRIPT, "manageChannels");
        taskPermissionMap.put(TaskConstants.CHANNEL_EDIT_DEPLOY, "deployUndeployChannels");
        taskPermissionMap.put(TaskConstants.CHANNEL_EDIT_DEBUG_DEPLOY, "deployUndeployChannels");

        // ========== Channel Groups ==========
        // Engine gates updateChannelGroups (which covers create/update/delete) on
        // Permissions.CHANNELS_MANAGE — only the read/export paths use viewChannelGroups.
        taskPermissionMap.put(TaskConstants.CHANNEL_GROUP_SAVE, "manageChannels");
        taskPermissionMap.put(TaskConstants.CHANNEL_GROUP_NEW_GROUP, "manageChannels");
        taskPermissionMap.put(TaskConstants.CHANNEL_GROUP_ASSIGN_CHANNEL, "manageChannels");
        taskPermissionMap.put(TaskConstants.CHANNEL_GROUP_EDIT_DETAILS, "manageChannels");
        taskPermissionMap.put(TaskConstants.CHANNEL_GROUP_IMPORT_GROUP, "manageChannels");
        taskPermissionMap.put(TaskConstants.CHANNEL_GROUP_DELETE_GROUP, "manageChannels");
        taskPermissionMap.put(TaskConstants.CHANNEL_GROUP_EXPORT_ALL_GROUPS, "viewChannelGroups");
        taskPermissionMap.put(TaskConstants.CHANNEL_GROUP_EXPORT_GROUP, "viewChannelGroups");

        // ========== Messages ==========
        taskPermissionMap.put(TaskConstants.MESSAGE_REFRESH, "viewMessages");
        taskPermissionMap.put(TaskConstants.MESSAGE_SEND, "processMessages");
        taskPermissionMap.put(TaskConstants.MESSAGE_IMPORT, "importMessages");
        // MESSAGE_EXPORT / MESSAGE_EXPORT_ATTACHMENT are deliberately gated on the stronger
        // exportMessagesServer permission even though the export dialogs also offer a purely
        // local (client-side) export whose REST calls only need viewMessages. Hiding both
        // buttons from a viewMessages-only role over-restricts the local path, but that is
        // the PHI-conservative (fail-safe) direction and not a security hole, so it is kept.
        taskPermissionMap.put(TaskConstants.MESSAGE_EXPORT, "exportMessagesServer");
        taskPermissionMap.put(TaskConstants.MESSAGE_REMOVE_ALL, "removeAllMessages");
        // Bulk-by-filter operations use a different engine permission than the
        // single-message variants. Engine: removeMessages (filtered) is gated on
        // MESSAGES_REMOVE_RESULTS; reprocessMessages (filtered) on MESSAGES_REPROCESS_RESULTS.
        taskPermissionMap.put(TaskConstants.MESSAGE_REMOVE_FILTERED, "removeResults");
        taskPermissionMap.put(TaskConstants.MESSAGE_REMOVE, "removeMessages");
        taskPermissionMap.put(TaskConstants.MESSAGE_REPROCESS_FILTERED, "reprocessResults");
        taskPermissionMap.put(TaskConstants.MESSAGE_REPROCESS, "reprocessMessages");
        taskPermissionMap.put(TaskConstants.MESSAGE_VIEW_IMAGE, "viewMessages");
        taskPermissionMap.put(TaskConstants.MESSAGE_EXPORT_ATTACHMENT, "exportMessagesServer");

        // ========== Alerts ==========
        taskPermissionMap.put(TaskConstants.ALERT_REFRESH, "viewAlerts");
        taskPermissionMap.put(TaskConstants.ALERT_NEW, "manageAlerts");
        taskPermissionMap.put(TaskConstants.ALERT_IMPORT, "manageAlerts");
        taskPermissionMap.put(TaskConstants.ALERT_EXPORT_ALL, "viewAlerts");
        taskPermissionMap.put(TaskConstants.ALERT_EXPORT, "viewAlerts");
        taskPermissionMap.put(TaskConstants.ALERT_DELETE, "manageAlerts");
        taskPermissionMap.put(TaskConstants.ALERT_EDIT, "manageAlerts");
        taskPermissionMap.put(TaskConstants.ALERT_ENABLE, "manageAlerts");
        taskPermissionMap.put(TaskConstants.ALERT_DISABLE, "manageAlerts");

        // ========== Alert Edit ==========
        taskPermissionMap.put(TaskConstants.ALERT_EDIT_SAVE, "manageAlerts");

        // ========== Users ==========
        taskPermissionMap.put(TaskConstants.USER_REFRESH, "manageUsers");
        taskPermissionMap.put(TaskConstants.USER_NEW, "manageUsers");
        taskPermissionMap.put(TaskConstants.USER_EDIT, "manageUsers");
        taskPermissionMap.put(TaskConstants.USER_DELETE, "manageUsers");

        // ========== Events ==========
        taskPermissionMap.put(TaskConstants.EVENT_REFRESH, "viewEvents");
        taskPermissionMap.put(TaskConstants.EVENT_EXPORT_ALL, "viewEvents");

        // ========== Code Templates ==========
        taskPermissionMap.put(TaskConstants.CODE_TEMPLATE_REFRESH, "viewCodeTemplates");
        taskPermissionMap.put(TaskConstants.CODE_TEMPLATE_SAVE, "manageCodeTemplates");
        taskPermissionMap.put(TaskConstants.CODE_TEMPLATE_NEW, "manageCodeTemplates");
        taskPermissionMap.put(TaskConstants.CODE_TEMPLATE_LIBRARY_NEW, "manageCodeTemplates");
        taskPermissionMap.put(TaskConstants.CODE_TEMPLATE_IMPORT, "manageCodeTemplates");
        taskPermissionMap.put(TaskConstants.CODE_TEMPLATE_LIBRARY_IMPORT, "manageCodeTemplates");
        taskPermissionMap.put(TaskConstants.CODE_TEMPLATE_EXPORT, "viewCodeTemplates");
        taskPermissionMap.put(TaskConstants.CODE_TEMPLATE_LIBRARY_EXPORT, "viewCodeTemplates");
        taskPermissionMap.put(TaskConstants.CODE_TEMPLATE_LIBRARY_EXPORT_ALL, "viewCodeTemplates");
        taskPermissionMap.put(TaskConstants.CODE_TEMPLATE_DELETE, "manageCodeTemplates");
        taskPermissionMap.put(TaskConstants.CODE_TEMPLATE_LIBRARY_DELETE, "manageCodeTemplates");
        taskPermissionMap.put(TaskConstants.CODE_TEMPLATE_VALIDATE, "viewCodeTemplates");

        // ========== Global Scripts ==========
        taskPermissionMap.put(TaskConstants.GLOBAL_SCRIPT_SAVE, "editGlobalScripts");
        taskPermissionMap.put(TaskConstants.GLOBAL_SCRIPT_VALIDATE, "viewGlobalScripts");
        taskPermissionMap.put(TaskConstants.GLOBAL_SCRIPT_IMPORT, "editGlobalScripts");
        taskPermissionMap.put(TaskConstants.GLOBAL_SCRIPT_EXPORT, "viewGlobalScripts");

        // ========== Extensions ==========
        taskPermissionMap.put(TaskConstants.EXTENSIONS_REFRESH, "manageExtensions");
        taskPermissionMap.put(TaskConstants.EXTENSIONS_ENABLE, "manageExtensions");
        taskPermissionMap.put(TaskConstants.EXTENSIONS_DISABLE, "manageExtensions");
        taskPermissionMap.put(TaskConstants.EXTENSIONS_SHOW_PROPERTIES, "manageExtensions");
        taskPermissionMap.put(TaskConstants.EXTENSIONS_UNINSTALL, "manageExtensions");

        // ========== Settings Panels (group-specific for shared doRefresh/doSave) ==========

        // Server Settings
        addSettingsMapping(TaskConstants.SETTINGS_SERVER_KEY,
                "viewServerSettings", "editServerSettings");
        groupTaskPermissionMap.put(TaskConstants.SETTINGS_SERVER_KEY + "/" + TaskConstants.SETTINGS_SERVER_BACKUP, "backupServerConfiguration");
        groupTaskPermissionMap.put(TaskConstants.SETTINGS_SERVER_KEY + "/" + TaskConstants.SETTINGS_SERVER_RESTORE, "restoreServerConfiguration");
        groupTaskPermissionMap.put(TaskConstants.SETTINGS_SERVER_KEY + "/" + TaskConstants.SETTINGS_CLEAR_ALL_STATS, "clearLifetimeStats");

        // Tags
        addSettingsMapping(TaskConstants.SETTINGS_TAGS_KEY,
                "viewTags", "manageTags");

        // Configuration Map
        addSettingsMapping(TaskConstants.SETTINGS_CONFIGURATION_MAP_KEY,
                "viewConfigurationMap", "editConfigurationMap");
        groupTaskPermissionMap.put(TaskConstants.SETTINGS_CONFIGURATION_MAP_KEY + "/" + TaskConstants.SETTINGS_CONFIGURATION_MAP_IMPORT, "editConfigurationMap");
        groupTaskPermissionMap.put(TaskConstants.SETTINGS_CONFIGURATION_MAP_KEY + "/" + TaskConstants.SETTINGS_CONFIGURATION_MAP_EXPORT, "viewConfigurationMap");

        // Database Tasks
        addSettingsMapping(TaskConstants.SETTINGS_DATABASE_TASKS_KEY,
                "viewDatabaseTasks", "manageDatabaseTasks");
        groupTaskPermissionMap.put(TaskConstants.SETTINGS_DATABASE_TASKS_KEY + "/" + TaskConstants.SETTINGS_RUN_DATABASE_TASK, "manageDatabaseTasks");
        groupTaskPermissionMap.put(TaskConstants.SETTINGS_DATABASE_TASKS_KEY + "/" + TaskConstants.SETTINGS_CANCEL_DATABASE_TASK, "manageDatabaseTasks");

        // Resources
        addSettingsMapping(TaskConstants.SETTINGS_RESOURCES_KEY,
                "viewResources", "editResources");
        groupTaskPermissionMap.put(TaskConstants.SETTINGS_RESOURCES_KEY + "/" + TaskConstants.SETTINGS_ADD_RESOURCE, "editResources");
        groupTaskPermissionMap.put(TaskConstants.SETTINGS_RESOURCES_KEY + "/" + TaskConstants.SETTINGS_REMOVE_RESOURCE, "editResources");
        groupTaskPermissionMap.put(TaskConstants.SETTINGS_RESOURCES_KEY + "/" + TaskConstants.SETTINGS_RELOAD_RESOURCE, "reloadResources");

        // The engine's sixth core settings tab, "Administrator" (settings_Administrator), is
        // intentionally NOT mapped: it only reads/writes the CURRENT user's own client
        // preferences, and its backing REST ops (setUserPreferences/setUserPreference) are
        // self-scoped server-side, so it is safe to show to everyone. Leaving it unmapped
        // lets it fall through checkTask's unknown-task allow branch.

        // RBAC plugin settings panel
        String rbacKey = TaskConstants.SETTINGS_KEY_PREFIX + RbacServletInterface.PLUGIN_NAME;
        addSettingsMapping(rbacKey, RbacServletInterface.PERMISSION_VIEW, RbacServletInterface.PERMISSION_MANAGE);
    }

    private void addSettingsMapping(String settingsKey, String viewPermission, String editPermission) {
        groupTaskPermissionMap.put(settingsKey + "/" + TaskConstants.SETTINGS_REFRESH, viewPermission);
        groupTaskPermissionMap.put(settingsKey + "/" + TaskConstants.SETTINGS_SAVE, editPermission);
    }
}
