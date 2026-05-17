// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.LinkedHashSet;
import java.util.Set;

import com.mirth.connect.client.core.Permissions;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utilities for working with OIE core permissions.
 *
 * <p>The engine declares each permission as a {@code public static final String}
 * field on {@link Permissions}. Several places in the plugin need the full set
 * (seeding the admin role, exposing the catalog over REST, building the
 * operation→permission map). This class is the single place that reflects
 * over {@link Permissions} to produce that set; without it, the same loop
 * was duplicated in three callers.</p>
 */
final class PermissionUtil {

    private static final Logger log = LoggerFactory.getLogger(PermissionUtil.class);

    private PermissionUtil() {
    }

    /**
     * Reflects over {@link Permissions} and returns every core permission
     * constant declared there.
     *
     * @return every core permission constant declared on {@link Permissions},
     *         in field declaration order. Never {@code null}. Returns an
     *         empty set if reflection fails (logged at error level rather
     *         than rethrown so a partial run-up of the plugin can still
     *         proceed).
     */
    static Set<String> getAllCorePermissions() {
        Set<String> permissions = new LinkedHashSet<>();
        try {
            // Assumes every static String constant on Permissions is a permission
            // identifier — true for all current entries. If the engine ever adds
            // a non-permission String constant here, filter it out explicitly.
            for (Field field : Permissions.class.getDeclaredFields()) {
                if (field.getType() == String.class && Modifier.isStatic(field.getModifiers())) {
                    permissions.add((String) field.get(null));
                }
            }
        } catch (IllegalAccessException e) {
            log.error("Failed to read Permissions constants", e);
        }
        return permissions;
    }
}
