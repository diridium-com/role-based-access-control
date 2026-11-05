// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Which permissions the role editor shows as ticked. The admin role's stored list holds only
 * the core permissions the seeder wrote, while its holders bypass every check and
 * {@code getMyPermissions} answers every core and extension permission for them. Showing the
 * stored list read as the admin role lacking the plugins' permissions (issue #28), so the
 * editor shows the whole catalog ticked for it. Saving still re-sends the stored list.
 */
final class RolePermissionDisplay {

    static final String ADMIN_LINE = "The admin role has every permission, including those of plugins installed later.";

    private RolePermissionDisplay() {
    }

    /**
     * @param role    the role being edited
     * @param catalog every permission the editor lists
     * @return the catalog for the admin role; otherwise the role's stored permissions
     */
    static Set<String> shown(Role role, Collection<String> catalog) {
        if (role.isAdmin()) {
            return new LinkedHashSet<>(catalog);
        }
        return role.getPermissions() != null ? new LinkedHashSet<>(role.getPermissions()) : new LinkedHashSet<>();
    }
}
