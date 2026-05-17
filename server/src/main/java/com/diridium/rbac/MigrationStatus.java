// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

/**
 * Second-layer failure indicator for the RBAC migrator.
 *
 * <p>The engine's {@code DefaultMigrationController} catches plugin
 * {@code MigrationException}s and only logs them, so a half-applied
 * migration would otherwise let the plugin start in a broken state.
 * {@link RbacServicePlugin#start()} re-reads the schema version after the
 * migrator runs and calls {@link #markFailed(String)} if it does not match
 * {@link RbacMigrator#LATEST_VERSION}.</p>
 *
 * <p>{@link RbacServlet} consults {@link #isOk()} at the top of every
 * mutating method and throws a clear {@code "plugin disabled"} error rather
 * than letting the request hit potentially-broken persistence.</p>
 *
 * <p>The auth controller deliberately does not consult this flag — denying
 * every authorization decision would render the entire engine unusable,
 * not just the RBAC UI. Instead, a failed migration causes auth lookups to
 * fail naturally (no role found → deny), which is the right fail-closed
 * behaviour for users while the RBAC servlet surfaces the clear error to
 * the admin who can fix it.</p>
 */
final class MigrationStatus {

    private static volatile boolean ok = true;
    private static volatile String error = null;

    private MigrationStatus() {
    }

    /**
     * @return {@code true} if the migrator reached
     *         {@link RbacMigrator#LATEST_VERSION} successfully; {@code false}
     *         after {@link #markFailed(String)}
     */
    static boolean isOk() {
        return ok;
    }

    /**
     * @return the most recent failure reason, or {@code null} if status is ok
     */
    static String getError() {
        return error;
    }

    /**
     * Records a migration failure with a human-readable reason.
     *
     * @param reason short explanation; surfaced to admins via REST errors
     */
    static void markFailed(String reason) {
        error = reason;
        ok = false;
    }

    /**
     * Clears any prior failure. Used in tests and on a successful restart.
     */
    static void markOk() {
        ok = true;
        error = null;
    }
}
