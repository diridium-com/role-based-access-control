// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import javax.swing.JCheckBox;

import org.junit.jupiter.api.Test;

/**
 * The role editor's warning tooltips on privileged permissions: Manage Extensions can disable RBAC, and a
 * Manage Roles holder can give their own account any role.
 */
class RoleEditorDialogWarningTest {

    private static String tooltipFor(String perm) {
        JCheckBox cb = new JCheckBox(perm);
        RoleEditorDialog.applyPermissionWarning(cb, perm);
        return cb.getToolTipText();
    }

    @Test
    void manageRolesSaysWhatItIsForAndWhatAHolderCanDo() {
        String tip = tooltipFor(RbacServletInterface.PERMISSION_MANAGE);
        assertTrue(tip.contains("delegating user management"), tip);
        assertTrue(tip.contains("own account any role, the admin role included"), tip);
        assertTrue(tip.contains("Grant it only to someone you would trust as an administrator."), tip);
    }

    @Test
    void manageExtensionsKeepsItsWarning() {
        assertTrue(tooltipFor("manageExtensions").contains("including disabling RBAC itself"));
    }

    @Test
    void otherPermissionsGetNoTooltip() {
        assertNull(tooltipFor("viewChannels"));
        assertNull(tooltipFor(RbacServletInterface.PERMISSION_VIEW));
    }
}
