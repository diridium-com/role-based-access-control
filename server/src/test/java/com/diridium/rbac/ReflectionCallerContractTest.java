// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;

import org.junit.jupiter.api.Test;

/**
 * Pins the rbac methods that other plugins call by reflection, with no
 * compile-time dependency on rbac. A rename or signature change here does not
 * break rbac's own build, so without this test it would only show up as
 * outside callers silently losing role assignment.
 *
 * <p>Known callers:
 * <ul>
 *   <li>gibson9583/oie-oidc-auth 1.0.3, {@code RbacRoleAssigner}: assigns a
 *       role at sign-in from the identity provider's groups.</li>
 *   <li>diridium-com/oie-ldap-plugin (not public yet): the same calls from
 *       LDAP groups.</li>
 * </ul>
 *
 * <p>The lookups mirror the callers' own: classes by name string (so a class
 * rename fails here), methods through {@link Class#getMethod} (so they must
 * stay public), with exact parameter and return types. If one of these has to
 * change, coordinate with the callers first, then update this test. Issue #56
 * tracks a supported API to replace these calls.
 */
class ReflectionCallerContractTest {

    private static final String REPOSITORY = "com.diridium.rbac.RbacRepository";
    private static final String AUTH_CONTROLLER = "com.diridium.rbac.RbacAuthorizationController";

    private static Class<?> load(String name) {
        return assertDoesNotThrow(() -> Class.forName(name, false, ReflectionCallerContractTest.class.getClassLoader()),
                name + " must keep this exact name: outside plugins look it up by string");
    }

    private static Method method(Class<?> type, String name, Class<?> returnType, Class<?>... params) {
        Method m = assertDoesNotThrow(() -> type.getMethod(name, params),
                type.getSimpleName() + "." + name + " must stay public with these parameter types");
        assertEquals(returnType, m.getReturnType(), type.getSimpleName() + "." + name + " return type");
        return m;
    }

    @Test
    void repositoryKeepsItsName() {
        assertEquals(REPOSITORY, RbacRepository.class.getName());
        load(REPOSITORY);
    }

    @Test
    void getInstanceIsStaticAndThrowsBeforeInit() throws Exception {
        Method getInstance = method(load(REPOSITORY), "getInstance", RbacRepository.class);
        assertTrue(Modifier.isStatic(getInstance.getModifiers()), "getInstance must stay static");

        // Callers treat a throw here as "rbac not started yet" and leave the role alone.
        RbacRepository.close();
        InvocationTargetException thrown = assertThrows(InvocationTargetException.class,
                () -> getInstance.invoke(null));
        assertEquals(IllegalStateException.class, thrown.getCause().getClass());
    }

    @Test
    void roleLookupMethods() {
        Class<?> repo = load(REPOSITORY);
        method(repo, "findRoleIdByName", Integer.class, String.class);
        method(repo, "getUserRoleId", Integer.class, int.class);
        method(repo, "getAdminRoleId", Integer.class);
        method(repo, "countUsersByRoleId", int.class, int.class);
    }

    @Test
    void assignUserRole() {
        method(load(REPOSITORY), "assignUserRole", void.class, int.class, int.class);
    }

    @Test
    void authorizationControllerKeepsPerUserInvalidateCache() {
        // Callers find this on whatever ControllerFactory.createAuthorizationController()
        // returns, so it must stay a public instance method taking a boxed Integer.
        Class<?> controller = load(AUTH_CONTROLLER);
        assertEquals(AUTH_CONTROLLER, RbacAuthorizationController.class.getName());
        Method m = method(controller, "invalidateCache", void.class, Integer.class);
        assertFalse(Modifier.isStatic(m.getModifiers()), "invalidateCache(Integer) must stay an instance method");
    }
}
