// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Arrays;

import com.mirth.connect.model.ExtensionPermission;
import com.mirth.connect.server.controllers.ConfigurationController;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

/**
 * Verifies that the plugin advertises the expected extension permissions:
 * two entries (VIEW + MANAGE), each carrying the right operation names
 * and task constants. Drift here means the OIE permission UI would expose
 * the wrong toggles to administrators.
 */
class RbacServicePluginTest {

    @Test
    void getExtensionPermissions_returnsViewAndManage() {
        ExtensionPermission[] perms = new RbacServicePlugin().getExtensionPermissions();
        assertEquals(2, perms.length);
    }

    @Test
    void viewPermission_carriesPluginName() {
        ExtensionPermission view = viewPermission();
        assertEquals(RbacServletInterface.PLUGIN_NAME, view.getExtensionName());
        assertEquals(RbacServletInterface.PERMISSION_VIEW, view.getDisplayName());
    }

    @Test
    void viewPermission_includesReadOperations() {
        ExtensionPermission view = viewPermission();
        assertTrue(operationNames(view).contains("getRoles"));
        assertTrue(operationNames(view).contains("getRole"));
        assertTrue(operationNames(view).contains("getUserRole"));
        assertTrue(operationNames(view).contains("getMyPermissions"));
        assertTrue(operationNames(view).contains("getAvailablePermissions"));
    }

    @Test
    void viewPermission_declaresNoTasks() {
        // RBAC declares no task names: the settings tab is gated client-side by
        // group-prefixed composite keys, and bare doRefresh/doSave collided with
        // the engine's Data Pruner.
        assertTrue(taskNames(viewPermission()).isEmpty());
    }

    @Test
    void managePermission_carriesPluginName() {
        ExtensionPermission manage = managePermission();
        assertEquals(RbacServletInterface.PLUGIN_NAME, manage.getExtensionName());
        assertEquals(RbacServletInterface.PERMISSION_MANAGE, manage.getDisplayName());
    }

    @Test
    void managePermission_includesWriteOperations() {
        ExtensionPermission manage = managePermission();
        assertTrue(operationNames(manage).contains("createRole"));
        assertTrue(operationNames(manage).contains("updateRole"));
        assertTrue(operationNames(manage).contains("deleteRole"));
        assertTrue(operationNames(manage).contains("assignUserRole"));
        assertTrue(operationNames(manage).contains("removeUserRole"));
    }

    @Test
    void managePermission_declaresNoTasks() {
        assertTrue(taskNames(managePermission()).isEmpty());
    }

    @Test
    void permissions_doNotClaimSharedPluginPropertyOps() {
        // RBAC never serves getPluginProperties/setPluginProperties; claiming them
        // collided with the engine's Data Pruner.
        assertTrue(!operationNames(viewPermission()).contains("getPluginProperties"));
        assertTrue(!operationNames(managePermission()).contains("setPluginProperties"));
    }

    @Test
    void getPluginPointName_returnsConstant() {
        assertEquals(RbacServletInterface.PLUGIN_NAME, new RbacServicePlugin().getPluginPointName());
    }

    // ========== verifyMigrationComplete ==========

    @AfterEach
    void resetMigrationStatus() {
        MigrationStatus.markOk();
    }

    @Test
    void verifyMigrationComplete_versionMatches_returnsTrue() {
        try (MockedStatic<ConfigurationController> mocked = stubStoredVersion(
                String.valueOf(RbacMigrator.LATEST_VERSION))) {
            assertTrue(new RbacServicePlugin().verifyMigrationComplete());
            assertTrue(MigrationStatus.isOk());
        }
    }

    @Test
    void verifyMigrationComplete_versionUnset_returnsFalseAndMarksFailed() {
        try (MockedStatic<ConfigurationController> mocked = stubStoredVersion(null)) {
            assertFalse(new RbacServicePlugin().verifyMigrationComplete());
            assertFalse(MigrationStatus.isOk());
        }
    }

    @Test
    void verifyMigrationComplete_versionNotInteger_returnsFalseAndMarksFailed() {
        try (MockedStatic<ConfigurationController> mocked = stubStoredVersion("banana")) {
            assertFalse(new RbacServicePlugin().verifyMigrationComplete());
            assertFalse(MigrationStatus.isOk());
        }
    }

    @Test
    void verifyMigrationComplete_versionBehind_returnsFalseAndMarksFailed() {
        try (MockedStatic<ConfigurationController> mocked = stubStoredVersion(
                String.valueOf(RbacMigrator.LATEST_VERSION - 1))) {
            assertFalse(new RbacServicePlugin().verifyMigrationComplete());
            assertFalse(MigrationStatus.isOk());
        }
    }

    private static MockedStatic<ConfigurationController> stubStoredVersion(String value) {
        ConfigurationController config = mock(ConfigurationController.class);
        when(config.getProperty(RbacServletInterface.PLUGIN_NAME, RbacMigrator.VERSION_PROPERTY))
                .thenReturn(value);
        MockedStatic<ConfigurationController> mocked = Mockito.mockStatic(ConfigurationController.class);
        mocked.when(ConfigurationController::getInstance).thenReturn(config);
        return mocked;
    }

    private static ExtensionPermission viewPermission() {
        return new RbacServicePlugin().getExtensionPermissions()[0];
    }

    private static ExtensionPermission managePermission() {
        return new RbacServicePlugin().getExtensionPermissions()[1];
    }

    private static java.util.List<String> operationNames(ExtensionPermission p) {
        return Arrays.asList(p.getOperationNames());
    }

    private static java.util.List<String> taskNames(ExtensionPermission p) {
        return Arrays.asList(p.getTaskNames());
    }
}
