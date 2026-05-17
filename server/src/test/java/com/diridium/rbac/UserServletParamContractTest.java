// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.lang.reflect.Parameter;

import com.mirth.connect.client.core.api.Param;
import com.mirth.connect.client.core.api.servlets.UserServletInterface;

import org.junit.jupiter.api.Test;

/**
 * Pins the engine contract RBAC depends on: the last-admin-delete guard and the
 * self-edit carve-out in {@link RbacAuthorizationController} read the target user
 * id from {@code parameterMap.get("userId")}, where {@code "userId"} is the
 * {@code @Param} name the engine assigns to that argument. The controller tests
 * stage {@code Map.of("userId", ...)} as a mirror literal, so a future engine
 * rename of the param would slip past them. This reflection check fails loudly
 * if the engine ever renames it.
 */
class UserServletParamContractTest {

    @Test
    void removeUser_userIdParamIsNamedUserId() {
        assertHasUserIdParam("removeUser");
    }

    @Test
    void updateUser_userIdParamIsNamedUserId() {
        assertHasUserIdParam("updateUser");
    }

    @Test
    void updateUserPassword_userIdParamIsNamedUserId() {
        assertHasUserIdParam("updateUserPassword");
    }

    private static void assertHasUserIdParam(String methodName) {
        boolean found = false;
        for (Method method : UserServletInterface.class.getMethods()) {
            if (!method.getName().equals(methodName)) {
                continue;
            }
            for (Parameter parameter : method.getParameters()) {
                Param param = firstParamAnnotation(parameter);
                if (param != null && "userId".equals(param.value())) {
                    found = true;
                }
            }
        }
        assertTrue(found, "UserServletInterface." + methodName
                + " must have an @Param(\"userId\") parameter (RBAC keys on that name)");
    }

    private static Param firstParamAnnotation(Parameter parameter) {
        for (Annotation annotation : parameter.getAnnotations()) {
            if (annotation instanceof Param p) {
                return p;
            }
        }
        return null;
    }
}
