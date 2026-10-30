// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.lang.reflect.Method;

import com.mirth.connect.client.core.api.MirthOperation;
import com.mirth.connect.client.core.api.Param;

import org.junit.jupiter.api.Test;

/**
 * Verifies that each @MirthOperation on RbacServletInterface maps to the
 * expected permission and auditable setting. The plugin's authorization
 * contract is encoded in these annotations; this test catches drift before
 * it ships.
 */
class RbacServletInterfacePermissionsTest {

    @Test
    void readOperations_requireViewRoles() throws Exception {
        assertPermission("getRoles", RbacServletInterface.PERMISSION_VIEW, false);
        assertPermission("getRole", RbacServletInterface.PERMISSION_VIEW, false);
        assertPermission("getUserRole", RbacServletInterface.PERMISSION_VIEW, false);
        assertPermission("getAvailablePermissions", RbacServletInterface.PERMISSION_VIEW, false);
        assertPermission("getMyPermissions", RbacServletInterface.PERMISSION_VIEW, false);
        assertPermission("getExtensionTaskPermissions", RbacServletInterface.PERMISSION_VIEW, false);
    }

    @Test
    void writeOperations_requireManageRoles() throws Exception {
        assertPermission("createRole", RbacServletInterface.PERMISSION_MANAGE, true);
        assertPermission("updateRole", RbacServletInterface.PERMISSION_MANAGE, true);
        assertPermission("deleteRole", RbacServletInterface.PERMISSION_MANAGE, true);
        assertPermission("assignUserRole", RbacServletInterface.PERMISSION_MANAGE, true);
        assertPermission("removeUserRole", RbacServletInterface.PERMISSION_MANAGE, true);
    }

    @Test
    void exportAndImport_requireTheirOwnPermissionsAndAreAudited() throws Exception {
        assertPermission("exportRoles", RbacServletInterface.PERMISSION_EXPORT, true);
        assertPermission("importRoles", RbacServletInterface.PERMISSION_IMPORT, true);
    }

    @Test
    void importRoles_keepsTheFileOutOfTheAudit() {
        for (Method method : RbacServletInterface.class.getDeclaredMethods()) {
            if (!method.getName().equals("importRoles")) {
                continue;
            }
            for (java.lang.reflect.Parameter parameter : method.getParameters()) {
                Param param = parameter.getAnnotation(Param.class);
                if (param != null && param.value().equals("file")) {
                    assertTrue(param.excludeFromAudit(), "the file's text must not be written to the audit log");
                    return;
                }
            }
        }
        fail("importRoles has no @Param(\"file\") parameter");
    }

    private void assertPermission(String methodName, String expectedPermission, boolean expectedAuditable) {
        for (Method method : RbacServletInterface.class.getDeclaredMethods()) {
            MirthOperation op = method.getAnnotation(MirthOperation.class);
            if (op != null && op.name().equals(methodName)) {
                assertEquals(expectedPermission, op.permission(),
                        methodName + " should require " + expectedPermission);
                assertEquals(expectedAuditable, op.auditable(),
                        methodName + " auditable should be " + expectedAuditable);
                return;
            }
        }
        fail("No @MirthOperation found with name '" + methodName + "'");
    }
}
