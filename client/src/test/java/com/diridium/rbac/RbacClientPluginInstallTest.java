// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;

import com.mirth.connect.client.ui.AuthorizationControllerFactory;
import com.mirth.connect.plugins.auth.client.SecureAuthorizationController;

import org.junit.jupiter.api.Test;

/**
 * Drift guard for the reflective controller install in
 * {@link RbacClientPlugin#installAuthorizationController()}.
 *
 * <p>That method sets our {@link SecureAuthorizationController} into a private
 * static field named {@code authorizationController} on the engine's
 * {@link AuthorizationControllerFactory}, because the factory's normal load
 * path can't see plugin classes. If a future engine renames or retypes that
 * field, the reflection fails silently at runtime and every UI button stays
 * enabled regardless of role. This test turns that silent breakage into a red
 * build at the next engine bump.</p>
 */
class RbacClientPluginInstallTest {

    @Test
    void factoryStillExposesTheInstallField() throws Exception {
        Field field = AuthorizationControllerFactory.class.getDeclaredField("authorizationController");
        assertTrue(Modifier.isStatic(field.getModifiers()),
                "the install field must be static (RbacClientPlugin sets it via field.set(null, ...))");
        assertTrue(field.getType().isAssignableFrom(SecureAuthorizationController.class),
                "SecureAuthorizationController must remain assignable into the factory field; "
                        + "field type is " + field.getType().getName());
    }
}
