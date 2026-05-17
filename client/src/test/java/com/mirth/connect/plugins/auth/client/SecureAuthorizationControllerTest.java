// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.mirth.connect.plugins.auth.client;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;
import java.util.Set;

import com.diridium.rbac.RbacServletInterface;
import com.mirth.connect.client.core.TaskConstants;

import org.junit.jupiter.api.Test;

/**
 * Tests for client-side task gating. The {@code loadPermissions} path
 * touches {@code PlatformUI.MIRTH_FRAME} which requires the OIE client UI
 * to be running, so these tests bypass {@code initialize()} and seed
 * {@code userPermissions} directly via reflection.
 */
class SecureAuthorizationControllerTest {

    @Test
    void checkTask_unknownTaskName_returnsTrue() throws Exception {
        // Server enforces the real decision; the client allows unmapped tasks through.
        SecureAuthorizationController c = withPermissions(Set.of());
        assertTrue(c.checkTask("any-group", "totallyUnknownTask"));
    }

    @Test
    void checkTask_permissionsNull_failsClosed() throws Exception {
        // Simulates "loadPermissions threw, userPermissions stayed null".
        // The client must deny rather than allow.
        SecureAuthorizationController c = new SecureAuthorizationController();
        setField(c, "loaded", true);
        // userPermissions stays null
        assertFalse(c.checkTask("group", TaskConstants.VIEW_CHANNEL));
    }

    @Test
    void checkTask_grantedPermission_allowsTask() throws Exception {
        SecureAuthorizationController c = withPermissions(Set.of("viewChannels"));
        assertTrue(c.checkTask("group", TaskConstants.VIEW_CHANNEL));
    }

    @Test
    void checkTask_missingPermission_deniesTask() throws Exception {
        SecureAuthorizationController c = withPermissions(Set.of("viewDashboard"));
        assertFalse(c.checkTask("group", TaskConstants.VIEW_CHANNEL));
    }

    @Test
    void checkTask_settingsRefresh_resolvesByGroup() throws Exception {
        // SETTINGS_REFRESH is shared across many settings panels; the group-specific
        // mapping picks the right permission per panel.
        SecureAuthorizationController granted = withPermissions(Set.of("viewServerSettings"));
        assertTrue(granted.checkTask(TaskConstants.SETTINGS_SERVER_KEY, TaskConstants.SETTINGS_REFRESH));

        SecureAuthorizationController denied = withPermissions(Set.of());
        assertFalse(denied.checkTask(TaskConstants.SETTINGS_SERVER_KEY, TaskConstants.SETTINGS_REFRESH));
    }

    @Test
    void checkTask_rbacSettingsPanel_requiresViewRoles() throws Exception {
        String rbacKey = TaskConstants.SETTINGS_KEY_PREFIX + RbacServletInterface.PLUGIN_NAME;

        SecureAuthorizationController granted = withPermissions(Set.of(RbacServletInterface.PERMISSION_VIEW));
        assertTrue(granted.checkTask(rbacKey, TaskConstants.SETTINGS_REFRESH));

        SecureAuthorizationController denied = withPermissions(Set.of());
        assertFalse(denied.checkTask(rbacKey, TaskConstants.SETTINGS_REFRESH));
    }

    @Test
    void checkTask_rbacSettingsSave_requiresManageRoles() throws Exception {
        String rbacKey = TaskConstants.SETTINGS_KEY_PREFIX + RbacServletInterface.PLUGIN_NAME;

        SecureAuthorizationController granted = withPermissions(Set.of(RbacServletInterface.PERMISSION_MANAGE));
        assertTrue(granted.checkTask(rbacKey, TaskConstants.SETTINGS_SAVE));

        SecureAuthorizationController denied = withPermissions(Set.of(RbacServletInterface.PERMISSION_VIEW));
        assertFalse(denied.checkTask(rbacKey, TaskConstants.SETTINGS_SAVE));
    }

    @Test
    void checkTask_channelManagement() throws Exception {
        SecureAuthorizationController c = withPermissions(Set.of("manageChannels"));
        assertTrue(c.checkTask("group", TaskConstants.CHANNEL_NEW_CHANNEL));
        assertTrue(c.checkTask("group", TaskConstants.CHANNEL_DELETE_CHANNEL));
        assertTrue(c.checkTask("group", TaskConstants.CHANNEL_EDIT));
    }

    @Test
    void checkTask_userManagement() throws Exception {
        SecureAuthorizationController c = withPermissions(Set.of("manageUsers"));
        assertTrue(c.checkTask("group", TaskConstants.USER_NEW));
        assertTrue(c.checkTask("group", TaskConstants.USER_EDIT));
        assertTrue(c.checkTask("group", TaskConstants.USER_DELETE));
    }

    @Test
    void checkTask_messageProcessing_requiresProcessMessages() throws Exception {
        SecureAuthorizationController c = withPermissions(Set.of("processMessages"));
        assertTrue(c.checkTask("group", TaskConstants.DASHBOARD_SEND_MESSAGE));
        assertTrue(c.checkTask("group", TaskConstants.MESSAGE_SEND));
    }

    @Test
    void checkTask_channelStartStop_requiresStartStopChannels() throws Exception {
        SecureAuthorizationController c = withPermissions(Set.of("startStopChannels"));
        assertTrue(c.checkTask("group", TaskConstants.DASHBOARD_START));
        assertTrue(c.checkTask("group", TaskConstants.DASHBOARD_STOP));
        assertTrue(c.checkTask("group", TaskConstants.DASHBOARD_HALT));
        assertTrue(c.checkTask("group", TaskConstants.DASHBOARD_PAUSE));
    }

    @Test
    void checkTask_deployUndeploy_requiresDeployUndeployChannels() throws Exception {
        SecureAuthorizationController c = withPermissions(Set.of("deployUndeployChannels"));
        assertTrue(c.checkTask("group", TaskConstants.CHANNEL_DEPLOY));
        assertTrue(c.checkTask("group", TaskConstants.DASHBOARD_UNDEPLOY));
    }

    @Test
    void checkTask_viewExtensions_requiresManageExtensions() throws Exception {
        SecureAuthorizationController c = withPermissions(Set.of("manageExtensions"));
        assertTrue(c.checkTask("group", TaskConstants.VIEW_EXTENSIONS));
        assertTrue(c.checkTask("group", TaskConstants.EXTENSIONS_UNINSTALL));
    }

    @Test
    void checkTask_channelGroupWrites_requireManageChannels() throws Exception {
        // Engine gates updateChannelGroups (which covers all group create/update/delete)
        // on Permissions.CHANNELS_MANAGE. viewChannelGroups alone must NOT enable
        // these UI actions, otherwise the user clicks Save and the server 403s.
        SecureAuthorizationController viewOnly = withPermissions(Set.of("viewChannelGroups"));
        assertFalse(viewOnly.checkTask("group", TaskConstants.CHANNEL_GROUP_SAVE));
        assertFalse(viewOnly.checkTask("group", TaskConstants.CHANNEL_GROUP_NEW_GROUP));
        assertFalse(viewOnly.checkTask("group", TaskConstants.CHANNEL_GROUP_ASSIGN_CHANNEL));
        assertFalse(viewOnly.checkTask("group", TaskConstants.CHANNEL_GROUP_EDIT_DETAILS));
        assertFalse(viewOnly.checkTask("group", TaskConstants.CHANNEL_GROUP_IMPORT_GROUP));
        assertFalse(viewOnly.checkTask("group", TaskConstants.CHANNEL_GROUP_DELETE_GROUP));

        SecureAuthorizationController manager = withPermissions(Set.of("manageChannels"));
        assertTrue(manager.checkTask("group", TaskConstants.CHANNEL_GROUP_SAVE));
        assertTrue(manager.checkTask("group", TaskConstants.CHANNEL_GROUP_NEW_GROUP));
        assertTrue(manager.checkTask("group", TaskConstants.CHANNEL_GROUP_ASSIGN_CHANNEL));
        assertTrue(manager.checkTask("group", TaskConstants.CHANNEL_GROUP_EDIT_DETAILS));
        assertTrue(manager.checkTask("group", TaskConstants.CHANNEL_GROUP_IMPORT_GROUP));
        assertTrue(manager.checkTask("group", TaskConstants.CHANNEL_GROUP_DELETE_GROUP));
    }

    @Test
    void checkTask_filteredMessageOps_useResultsPermissions() throws Exception {
        // Engine gates the bulk-by-filter variants on different permissions than
        // single-message variants: removeMessages (filtered) → MESSAGES_REMOVE_RESULTS
        // ("removeResults"), reprocessMessages (filtered) → MESSAGES_REPROCESS_RESULTS
        // ("reprocessResults"). A user with only removeMessages/reprocessMessages
        // cannot fire the filtered actions.
        SecureAuthorizationController singleOnly = withPermissions(Set.of("removeMessages", "reprocessMessages"));
        assertFalse(singleOnly.checkTask("group", TaskConstants.MESSAGE_REMOVE_FILTERED));
        assertFalse(singleOnly.checkTask("group", TaskConstants.MESSAGE_REPROCESS_FILTERED));

        SecureAuthorizationController bulkOnly = withPermissions(Set.of("removeResults", "reprocessResults"));
        assertTrue(bulkOnly.checkTask("group", TaskConstants.MESSAGE_REMOVE_FILTERED));
        assertTrue(bulkOnly.checkTask("group", TaskConstants.MESSAGE_REPROCESS_FILTERED));
        // Single-message variants must still require their own permission.
        assertFalse(bulkOnly.checkTask("group", TaskConstants.MESSAGE_REMOVE));
        assertFalse(bulkOnly.checkTask("group", TaskConstants.MESSAGE_REPROCESS));
    }

    @Test
    void checkTask_channelGroupExports_requireViewChannelGroups() throws Exception {
        // Reads/exports stay at viewChannelGroups — the engine doesn't gate those on manage.
        SecureAuthorizationController c = withPermissions(Set.of("viewChannelGroups"));
        assertTrue(c.checkTask("group", TaskConstants.CHANNEL_GROUP_EXPORT_ALL_GROUPS));
        assertTrue(c.checkTask("group", TaskConstants.CHANNEL_GROUP_EXPORT_GROUP));

        SecureAuthorizationController denied = withPermissions(Set.of("manageChannels"));
        // manageChannels alone (without viewChannelGroups) should NOT enable exports.
        assertFalse(denied.checkTask("group", TaskConstants.CHANNEL_GROUP_EXPORT_ALL_GROUPS));
        assertFalse(denied.checkTask("group", TaskConstants.CHANNEL_GROUP_EXPORT_GROUP));
    }

    // ========== Extension task permission merging ==========

    @Test
    void mergeExtensionTaskPermissions_addsBareTaskToTaskNameMap() throws Exception {
        SecureAuthorizationController c = withPermissions(Set.of("viewChannels"));
        c.mergeExtensionTaskPermissions(java.util.Map.of("viewChannelHistory", "viewChannels"));
        // Now a plugin-supplied task name is recognized and gated
        assertTrue(c.checkTask("anyGroup", "viewChannelHistory"));
    }

    @Test
    void mergeExtensionTaskPermissions_deniesWhenUserLacksPermission() throws Exception {
        SecureAuthorizationController c = withPermissions(Set.of("viewDashboard"));
        c.mergeExtensionTaskPermissions(java.util.Map.of("viewChannelHistory", "viewChannels"));
        // viewChannels not granted → plugin task is denied
        assertFalse(c.checkTask("anyGroup", "viewChannelHistory"));
    }

    @Test
    void mergeExtensionTaskPermissions_groupPrefixedKey_goesToGroupMap() throws Exception {
        // "settings_FooPlugin/doRefresh" should be a group-specific mapping
        SecureAuthorizationController c = withPermissions(Set.of("viewServerSettings"));
        c.mergeExtensionTaskPermissions(java.util.Map.of(
                "settings_FooPlugin/doRefresh", "viewServerSettings"));
        assertTrue(c.checkTask("settings_FooPlugin", "doRefresh"));
        // A different group with same task name remains unaffected (bare task map empty for this name)
        // since the entry was group-specific, checkTask("otherGroup", "doRefresh") would fall through
        // to the bare map (no entry) then to "unknown task → allow"
        assertTrue(c.checkTask("otherGroup", "doRefresh"));
    }

    @Test
    void mergeExtensionTaskPermissions_hardcodedEntryWins() throws Exception {
        // Hardcoded: VIEW_CHANNEL → "viewChannels"
        // Try to override via extension: VIEW_CHANNEL → "viewDashboard"
        SecureAuthorizationController c = withPermissions(Set.of("viewChannels"));
        c.mergeExtensionTaskPermissions(java.util.Map.of(TaskConstants.VIEW_CHANNEL, "viewDashboard"));
        // Hardcoded entry should still apply (user has viewChannels → allowed)
        assertTrue(c.checkTask("group", TaskConstants.VIEW_CHANNEL));

        SecureAuthorizationController denied = withPermissions(Set.of("viewDashboard"));
        denied.mergeExtensionTaskPermissions(java.util.Map.of(TaskConstants.VIEW_CHANNEL, "viewDashboard"));
        // If the override had taken effect, viewDashboard would be enough — but it won't,
        // because hardcoded says viewChannels is required.
        assertFalse(denied.checkTask("group", TaskConstants.VIEW_CHANNEL));
    }

    @Test
    void mergeExtensionTaskPermissions_nullOrEmpty_isNoop() throws Exception {
        SecureAuthorizationController c = withPermissions(Set.of());
        c.mergeExtensionTaskPermissions(null);
        c.mergeExtensionTaskPermissions(java.util.Map.of());
        // Still allows unknown tasks (no merge happened)
        assertTrue(c.checkTask("any", "unrecognized-task"));
    }

    // ========== Helpers ==========

    private SecureAuthorizationController withPermissions(Set<String> perms) throws Exception {
        SecureAuthorizationController c = new SecureAuthorizationController();
        setField(c, "userPermissions", perms);
        setField(c, "loaded", true);
        return c;
    }

    private void setField(Object target, String name, Object value) throws Exception {
        Field f = target.getClass().getDeclaredField(name);
        f.setAccessible(true);
        f.set(target, value);
    }
}
