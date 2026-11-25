// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import java.io.Serializable;

/**
 * A permission a role holds that neither the engine nor any installed plugin registers. The Administrators call it an
 * orphaned permission. It grants nothing; it is left behind when a plugin renames a permission or is removed.
 */
public class UnregisteredGrant implements Serializable {

    private static final long serialVersionUID = 1L;

    private int roleId;
    private String roleName;
    private String permission;

    public UnregisteredGrant() {
    }

    public UnregisteredGrant(int roleId, String roleName, String permission) {
        this.roleId = roleId;
        this.roleName = roleName;
        this.permission = permission;
    }

    public int getRoleId() {
        return roleId;
    }

    public void setRoleId(int roleId) {
        this.roleId = roleId;
    }

    /** @return the role's name when the list was made; a removal request may leave it out */
    public String getRoleName() {
        return roleName;
    }

    public void setRoleName(String roleName) {
        this.roleName = roleName;
    }

    public String getPermission() {
        return permission;
    }

    public void setPermission(String permission) {
        this.permission = permission;
    }
}
