// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.mirth.connect.plugins.auth.client;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import com.diridium.rbac.RbacServletInterface;
import com.diridium.rbac.RoleEditorDialog;
import com.mirth.connect.client.core.Permissions;

import org.junit.jupiter.api.Test;

/**
 * Drift guard for the hand-maintained task-to-permission maps in
 * {@link SecureAuthorizationController#buildPermissionMaps()}.
 *
 * <p>The server-side operation-to-permission map is derived from the
 * engine's {@code @MirthOperation} annotations at runtime, but the
 * client-side task map is written by hand and has repeatedly drifted from
 * engine truth. This test catches one class of drift mechanically: a mapped
 * permission string that does not exist in the engine's
 * {@link Permissions} constants (typo, renamed permission, or a permission
 * removed by an engine upgrade). A user could never be granted such a
 * permission, so the task would be hidden for everyone — including admins
 * if the bypass ever regressed.</p>
 *
 * <p>What this test cannot catch: a mapping to a <em>real but wrong</em>
 * permission (e.g. a filtered bulk operation mapped to the single-message
 * permission). Those need the per-entry assertions in
 * {@link SecureAuthorizationControllerTest} and a manual cross-check of the
 * engine's {@code @MirthOperation} annotations whenever the map changes.</p>
 */
class PermissionMapDriftTest {

    @Test
    void taskPermissionMap_onlyUsesRealEnginePermissions() throws Exception {
        assertMapValuesAreKnownPermissions("taskPermissionMap");
    }

    @Test
    void groupTaskPermissionMap_onlyUsesRealPermissions() throws Exception {
        assertMapValuesAreKnownPermissions("groupTaskPermissionMap");
    }

    @Test
    void roleEditorPermissionLists_onlyUseRealEnginePermissions() throws Exception {
        // Same drift class as the controller maps: RoleEditorDialog's grouped
        // checklist (PERMISSION_GROUPS) and its Read-Only / Base presets are
        // hand-typed permission strings. A typo or an engine-renamed permission
        // here silently drops a checkbox or quietly breaks a preset.
        Set<String> known = knownPermissions();
        Set<String> offenders = new TreeSet<>();
        for (String permission : collectRoleEditorPermissions()) {
            if (!known.contains(permission)) {
                offenders.add(permission);
            }
        }
        assertTrue(offenders.isEmpty(), "RoleEditorDialog permission lists reference strings that do not "
                + "exist in the engine's Permissions constants: " + offenders);
    }

    @Test
    void permissionMaps_areNonEmpty() throws Exception {
        // Guards against a refactor accidentally emptying the maps, which
        // would silently turn every task into "unknown -> allow".
        assertFalse(readMap("taskPermissionMap").isEmpty());
        assertFalse(readMap("groupTaskPermissionMap").isEmpty());
    }

    private void assertMapValuesAreKnownPermissions(String fieldName) throws Exception {
        Set<String> known = knownPermissions();
        Set<String> offenders = new TreeSet<>();
        for (Map.Entry<String, String> entry : readMap(fieldName).entrySet()) {
            if (!known.contains(entry.getValue())) {
                offenders.add(entry.getKey() + " -> " + entry.getValue());
            }
        }
        assertTrue(offenders.isEmpty(), fieldName + " contains permission strings that do not "
                + "exist in the engine's Permissions constants (or the RBAC plugin's own): " + offenders);
    }

    /**
     * @return every engine core permission value plus the RBAC plugin's two
     *         extension permissions
     */
    private static Set<String> knownPermissions() throws Exception {
        Set<String> values = new HashSet<>();
        for (Field field : Permissions.class.getDeclaredFields()) {
            if (Modifier.isStatic(field.getModifiers()) && field.getType() == String.class) {
                values.add((String) field.get(null));
            }
        }
        values.add(RbacServletInterface.PERMISSION_VIEW);
        values.add(RbacServletInterface.PERMISSION_MANAGE);
        return values;
    }

    /**
     * Flattens every permission string declared in {@link RoleEditorDialog}'s
     * static lists: the grouped checklist plus the Base and Read-Only presets.
     */
    private static Set<String> collectRoleEditorPermissions() throws Exception {
        Set<String> all = new TreeSet<>();

        Field groups = RoleEditorDialog.class.getDeclaredField("PERMISSION_GROUPS");
        groups.setAccessible(true);
        Map<?, ?> groupMap = (Map<?, ?>) groups.get(null);
        for (Object value : groupMap.values()) {
            for (Object permission : (Collection<?>) value) {
                all.add((String) permission);
            }
        }

        for (String fieldName : new String[] {"BASE_PERMISSIONS", "READ_ONLY_PERMISSIONS"}) {
            Field field = RoleEditorDialog.class.getDeclaredField(fieldName);
            field.setAccessible(true);
            for (Object permission : (Collection<?>) field.get(null)) {
                all.add((String) permission);
            }
        }
        return all;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, String> readMap(String fieldName) throws Exception {
        SecureAuthorizationController controller = new SecureAuthorizationController();
        Field field = SecureAuthorizationController.class.getDeclaredField(fieldName);
        field.setAccessible(true);
        return (Map<String, String>) field.get(controller);
    }
}
