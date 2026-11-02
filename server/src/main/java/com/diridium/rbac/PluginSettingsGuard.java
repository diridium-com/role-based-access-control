// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import java.util.HashSet;
import java.util.Set;
import java.util.function.Supplier;

import com.mirth.connect.client.core.ExtensionOperation;
import com.mirth.connect.client.core.Operation;
import com.mirth.connect.client.core.api.servlets.ExtensionServletInterface;
import com.mirth.connect.server.controllers.ControllerFactory;
import com.mirth.connect.server.controllers.ExtensionController;

/**
 * Decides the engine's two plugin-settings calls, {@code GET} and {@code PUT}
 * {@code /extensions/{name}/properties}, before rbac looks up a permission for them.
 *
 * <p>The engine checks these calls under the extension name exactly as the URL spells
 * it, then reads and writes the settings with {@code WHERE CATEGORY = <name>}, which
 * MySQL and SQL Server compare ignoring case by default. rbac keys permissions by the
 * exact name and allows a call it has no mapping for, so on those databases a user with
 * any role could read and change another plugin's settings by changing the case of its
 * name: measured on OIE 4.7.0 with MySQL 8.4 (2026-11-01), where a user without View
 * Settings read Data Pruner's settings as "data pruner" and wiped them. A name that is
 * not exactly an installed extension's is refused here, so the usual checks only ever
 * see a name the database can't mistake for another.</p>
 *
 * <p>rbac's own settings are for the admin role only. rbac doesn't register these two
 * calls (they collided with Data Pruner, see {@link RbacServicePlugin#getExtensionPermissions}),
 * so without this a user with any role could read and change them.</p>
 */
final class PluginSettingsGuard {

    static final String READING_RBAC_NEEDS_ADMIN = "Reading rbac's settings needs the admin role.";
    static final String CHANGING_RBAC_NEEDS_ADMIN = "Changing rbac's settings needs the admin role.";

    private final Supplier<Set<String>> installedExtensionNames;

    /** Reads the installed plugin and connector names from the engine at each check. */
    PluginSettingsGuard() {
        this(PluginSettingsGuard::engineExtensionNames);
    }

    /** @param installedExtensionNames the exact names of every installed plugin and connector */
    PluginSettingsGuard(Supplier<Set<String>> installedExtensionNames) {
        this.installedExtensionNames = installedExtensionNames;
    }

    /**
     * @return why a caller without the admin role is refused this operation, or {@code null}
     *         when it isn't a plugin-settings call that this class refuses
     */
    String refusal(Operation operation) {
        if (!(operation instanceof ExtensionOperation extensionOperation)) {
            return null;
        }
        String extensionName = extensionOperation.getExtensionName();
        // getName() is "<extensionName>#<operation>".
        String operationName = extensionOperation.getName().substring(String.valueOf(extensionName).length() + 1);
        boolean reading = ExtensionServletInterface.OPERATION_PLUGIN_PROPERTIES_GET.equals(operationName);
        if (!reading && !ExtensionServletInterface.OPERATION_PLUGIN_PROPERTIES_SET.equals(operationName)) {
            return null;
        }
        if (RbacServletInterface.PLUGIN_NAME.equals(extensionName)) {
            return reading ? READING_RBAC_NEEDS_ADMIN : CHANGING_RBAC_NEEDS_ADMIN;
        }
        if (extensionName == null || !installedExtensionNames.get().contains(extensionName)) {
            return "There's no installed extension named '" + extensionName + "'.";
        }
        return null;
    }

    private static Set<String> engineExtensionNames() {
        ExtensionController extensions = ControllerFactory.getFactory().createExtensionController();
        Set<String> names = new HashSet<>(extensions.getPluginMetaData().keySet());
        names.addAll(extensions.getConnectorMetaData().keySet());
        return names;
    }
}
