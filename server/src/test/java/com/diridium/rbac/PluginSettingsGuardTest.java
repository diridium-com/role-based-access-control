// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.Set;

import com.mirth.connect.client.core.ExtensionOperation;
import com.mirth.connect.client.core.Operation;
import com.mirth.connect.client.core.Operation.ExecuteType;

import org.junit.jupiter.api.Test;

class PluginSettingsGuardTest {

    private static final String RBAC = RbacServletInterface.PLUGIN_NAME;
    private static final String GET = "getPluginProperties";
    private static final String SET = "setPluginProperties";

    private final PluginSettingsGuard guard = new PluginSettingsGuard(() -> Set.of("Data Pruner", "File Reader", RBAC));

    /** What the engine's ExtensionServlet passes for these calls: the name as the URL spells it. */
    private static ExtensionOperation call(String extensionName, String operation) {
        return new ExtensionOperation(extensionName, operation, operation, ExecuteType.SYNC, true);
    }

    @Test
    void rbacsOwnSettings_needTheAdminRole() {
        assertEquals(PluginSettingsGuard.READING_RBAC_NEEDS_ADMIN, guard.refusal(call(RBAC, GET)));
        assertEquals(PluginSettingsGuard.CHANGING_RBAC_NEEDS_ADMIN, guard.refusal(call(RBAC, SET)));
    }

    @Test
    void aNameInAnotherCase_isRefused() {
        // MySQL and SQL Server would read and write the real settings under either name.
        assertEquals("There's no installed extension named 'role-based access control'.",
                guard.refusal(call("role-based access control", GET)));
        assertEquals("There's no installed extension named 'data pruner'.", guard.refusal(call("data pruner", SET)));
        assertEquals("There's no installed extension named 'DATA PRUNER'.", guard.refusal(call("DATA PRUNER", GET)));
    }

    @Test
    void aNameWithExtraSpaces_isRefused() {
        // SQL Server ignores trailing spaces when it compares.
        assertEquals("There's no installed extension named 'Data Pruner '.", guard.refusal(call("Data Pruner ", SET)));
    }

    @Test
    void aNameNoExtensionHas_isRefused() {
        assertEquals("There's no installed extension named 'Nothing Here'.", guard.refusal(call("Nothing Here", GET)));
        assertEquals("There's no installed extension named 'null'.", guard.refusal(call(null, GET)));
    }

    @Test
    void anInstalledExtensionsExactName_isLeftToTheUsualChecks() {
        assertNull(guard.refusal(call("Data Pruner", GET)));
        assertNull(guard.refusal(call("Data Pruner", SET)));
        assertNull(guard.refusal(call("File Reader", GET)), "a connector's name counts too");
    }

    @Test
    void otherCalls_areLeftAlone() {
        assertNull(guard.refusal(call("data pruner", "getStatus")));
        assertNull(guard.refusal(call(RBAC, "getRoles")));
        assertNull(guard.refusal(call(RBAC, "exportRoles")));
        assertNull(guard.refusal(new Operation("getServerSettings", "Get server settings", ExecuteType.SYNC, true)));
    }
}
