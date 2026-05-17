// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import com.mirth.connect.model.util.MigrationException;
import com.mirth.connect.server.controllers.ConfigurationController;
import com.mirth.connect.server.migration.Migrator;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static com.diridium.rbac.RbacServletInterface.PLUGIN_NAME;

/**
 * Versioned migrator for RBAC schema.
 *
 * <p>OIE's {@link Migrator} base class does not track per-plugin schema
 * versions, so we store our own under the {@link ConfigurationController}
 * key/value store. Each {@code migrate()} run reads the current version,
 * applies every {@code applyVN} step beyond it, and persists the new
 * version. Failure to reach {@link #LATEST_VERSION} is detected by
 * {@link RbacServicePlugin#start()} which marks {@link MigrationStatus}.</p>
 *
 * <h3>Versions</h3>
 * <ul>
 *   <li><b>1</b> — Initial schema: {@code rbac_role}, {@code rbac_role_permission},
 *       {@code rbac_user_role}, {@code rbac_role_channel}.</li>
 *   <li><b>2</b> — Adds {@code is_admin BOOLEAN/NUMBER(1)/BIT} column to
 *       {@code rbac_role}.</li>
 * </ul>
 *
 * <h3>Backfill</h3>
 *
 * <p>Plugin versions before this migrator did not record a schema version.
 * When {@code schema_version} is null, {@link #backfillSchemaVersion} detects
 * the actual state of the database via {@link DatabaseMetaData} and sets the
 * version accordingly so the version loop only runs the steps that haven't
 * been applied. Identifier case (PostgreSQL lowercases unquoted names;
 * Derby/Oracle/SQL Server uppercase) is handled by querying both cases.</p>
 */
public class RbacMigrator extends Migrator {

    /** Bump when adding a new {@code applyVN} step. */
    static final int LATEST_VERSION = 2;

    /** CONFIGURATION property key holding the applied schema version. Shared with
     *  {@code RbacServicePlugin}'s second-layer check so both agree on the key. */
    static final String VERSION_PROPERTY = "schema_version";
    private static final Logger log = LoggerFactory.getLogger(RbacMigrator.class);

    /**
     * {@inheritDoc}
     *
     * <p>Always detects the schema state from {@link DatabaseMetaData} and
     * aligns the stored {@code schema_version} property before running the
     * version loop. Detecting on every call (rather than only when the
     * property is null) makes us robust to operational quirks: pre-versioning
     * installs and manual edits to {@code CONFIGURATION}. (Note the
     * uninstall-then-reinstall case is NOT one of these: on uninstall the engine
     * drops the plugin's tables AND, on the next startup, clears its CONFIGURATION
     * properties — including {@code schema_version} — so that path already starts
     * clean.)</p>
     */
    @Override
    public void migrate() throws MigrationException {
        int current = detectAndAlignSchemaVersion();
        if (current < 1) {
            applyV1();
        }
        if (current < 2) {
            applyV2();
        }
        writeSchemaVersion(LATEST_VERSION);
        log.info("RBAC schema at version {}", LATEST_VERSION);
    }

    /**
     * Detects the actual schema version from {@link DatabaseMetaData} (table
     * + column existence) and writes it to the {@code schema_version}
     * property if it differs from what's stored.
     *
     * @return the detected current version (0 = fresh install, 1 = has
     *         tables but no is_admin column, 2 = has both)
     */
    private int detectAndAlignSchemaVersion() throws MigrationException {
        int detected = detectFromState();
        Integer stored = readSchemaVersionOrNull();
        if (stored == null) {
            log.info("RBAC schema state detected as version {} (no stored version)", detected);
            writeSchemaVersion(detected);
        } else if (stored != detected) {
            log.warn("RBAC schema stored version ({}) does not match actual state ({}); realigning",
                    stored, detected);
            writeSchemaVersion(detected);
        }
        return detected;
    }

    private int detectFromState() throws MigrationException {
        try {
            if (!tableExists("rbac_role")) {
                return 0;
            }
            // rbac_role exists, so v1 was at least started. Verify the other three base
            // tables actually landed: a partial applyV1 failure would otherwise be reported
            // as a healthy v1/v2 schema (detectAndAlign writes that version and start()
            // marks migration OK), and every later query against the missing tables would
            // fail at runtime with no migration signal. Fail loud instead — re-running
            // applyV1 is not a safe repair because the engine's Migrator does not ignore
            // errors, so the CREATE for the already-present rbac_role would throw.
            List<String> missing = new ArrayList<>();
            for (String child : new String[]{"rbac_role_permission", "rbac_user_role", "rbac_role_channel"}) {
                if (!tableExists(child)) {
                    missing.add(child);
                }
            }
            if (!missing.isEmpty()) {
                throw new MigrationException("RBAC schema is partially applied: rbac_role exists but "
                        + "child table(s) " + missing + " are missing; manual repair required");
            }
            if (!columnExists("rbac_role", "is_admin")) {
                return 1;
            }
            return 2;
        } catch (MigrationException e) {
            throw e; // already descriptive — do not double-wrap
        } catch (Exception e) {
            throw new MigrationException("Failed to detect RBAC schema state", e);
        }
    }

    /** Creates the four base tables. */
    private void applyV1() throws MigrationException {
        log.info("Applying RBAC schema v1 (create tables)");
        executeScript("/" + getDatabaseType() + "-rbac-tables.sql");
    }

    /** Adds the {@code is_admin} column to {@code rbac_role}. */
    private void applyV2() throws MigrationException {
        log.info("Applying RBAC schema v2 (add is_admin column)");
        String sql = switch (getDatabaseType()) {
            case "oracle" -> "ALTER TABLE rbac_role ADD is_admin NUMBER(1) DEFAULT 0 NOT NULL";
            case "sqlserver" -> "ALTER TABLE rbac_role ADD is_admin BIT NOT NULL DEFAULT 0";
            default -> "ALTER TABLE rbac_role ADD COLUMN is_admin BOOLEAN NOT NULL DEFAULT FALSE";
        };
        try {
            executeStatement(sql);
        } catch (Exception e) {
            throw new MigrationException("Failed to add is_admin column", e);
        }
    }

    // ========== Schema version persistence ==========

    /**
     * @return the stored schema_version as an integer, or {@code null} when
     *         the property is unset or unparseable
     */
    private Integer readSchemaVersionOrNull() {
        String raw = ConfigurationController.getInstance().getProperty(PLUGIN_NAME, VERSION_PROPERTY);
        if (raw == null) {
            return null;
        }
        try {
            return Integer.parseInt(raw);
        } catch (NumberFormatException e) {
            log.warn("RBAC schema_version property '{}' is not an integer; treating as unset", raw);
            return null;
        }
    }

    private void writeSchemaVersion(int version) throws MigrationException {
        try {
            ConfigurationController.getInstance().saveProperty(PLUGIN_NAME, VERSION_PROPERTY, String.valueOf(version));
        } catch (Exception e) {
            throw new MigrationException("Failed to persist schema_version=" + version, e);
        }
    }

    // ========== DatabaseMetaData helpers ==========

    /**
     * Checks for a table by name across the conventional identifier cases
     * different JDBC drivers normalise to.
     */
    private boolean tableExists(String tableName) throws Exception {
        Connection conn = getConnection();
        DatabaseMetaData meta = conn.getMetaData();
        for (String candidate : namingCandidates(tableName)) {
            try (ResultSet rs = meta.getTables(null, null, candidate, new String[]{"TABLE"})) {
                if (rs.next()) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Checks for a column on a table across the conventional identifier cases
     * different JDBC drivers normalise to.
     */
    private boolean columnExists(String tableName, String columnName) throws Exception {
        Connection conn = getConnection();
        DatabaseMetaData meta = conn.getMetaData();
        for (String tableCandidate : namingCandidates(tableName)) {
            for (String columnCandidate : namingCandidates(columnName)) {
                try (ResultSet rs = meta.getColumns(null, null, tableCandidate, columnCandidate)) {
                    if (rs.next()) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private static List<String> namingCandidates(String name) {
        List<String> out = new ArrayList<>(3);
        out.add(name);
        out.add(name.toUpperCase(Locale.ROOT));
        out.add(name.toLowerCase(Locale.ROOT));
        return out;
    }

    // ========== Engine contract ==========

    /**
     * {@inheritDoc}
     * <p>RBAC has no serialized data — its data is normalized across four
     * tables, not stored as blobs.</p>
     */
    @Override
    public void migrateSerializedData() throws MigrationException {
        // No serialized data migration needed
    }

    /**
     * {@inheritDoc}
     * @return DROP TABLE statements in FK-safe order: child tables first
     *         ({@code rbac_role_permission}, {@code rbac_role_channel},
     *         {@code rbac_user_role}), then {@code rbac_role}. On uninstall the
     *         engine records the plugin name in {@code extension_uninstall.properties}
     *         and, on the next startup, {@code removePropertiesForUninstalledExtensions()}
     *         DELETES every CONFIGURATION property under the plugin's group name — which
     *         includes our {@code schema_version} (persisted under {@code PLUGIN_NAME}).
     *         So an uninstall+restart already yields a clean slate; it is the ONLY
     *         property the plugin writes. {@link #detectAndAlignSchemaVersion()} still
     *         earns its keep for the other cases — pre-versioning installs and manual
     *         CONFIGURATION edits — where the stored version cannot be trusted.
     */
    @Override
    public List<String> getUninstallStatements() {
        List<String> statements = new ArrayList<>();
        statements.add("DROP TABLE rbac_role_permission");
        statements.add("DROP TABLE rbac_role_channel");
        statements.add("DROP TABLE rbac_user_role");
        statements.add("DROP TABLE rbac_role");
        return statements;
    }
}
