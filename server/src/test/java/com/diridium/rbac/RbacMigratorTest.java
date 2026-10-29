// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.mirth.connect.model.util.MigrationException;
import com.mirth.connect.server.controllers.ConfigurationController;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

/**
 * Tests the version-detection and backfill logic of {@link RbacMigrator}.
 *
 * <p>DDL execution is captured (not run) by overriding the {@code Migrator}
 * base class's protected {@code executeScript}/{@code executeStatement}
 * hooks; schema state is simulated through a mocked
 * {@link DatabaseMetaData}. The stored {@code schema_version} property is
 * served by a static-mocked {@link ConfigurationController}.</p>
 */
class RbacMigratorTest {

    private static final String PLUGIN_NAME = RbacServletInterface.PLUGIN_NAME;
    private static final String VERSION_PROP = "schema_version";

    private TestableMigrator migrator;
    private DatabaseMetaData meta;
    private ConfigurationController configController;
    private MockedStatic<ConfigurationController> mockedConfig;

    /** Records DDL instead of executing it. */
    private static class TestableMigrator extends RbacMigrator {
        final List<String> scripts = new ArrayList<>();
        final List<String> statements = new ArrayList<>();
        SQLException statementFailure;
        // SQL Server's catalog for the v3 checks ("table.column" keys); the statements update it.
        Map<String, String> catalogTypes;
        Map<String, String> catalogUniques;

        @Override
        protected void executeScript(String path) {
            scripts.add(path);
        }

        @Override
        protected int executeStatement(String sql) throws SQLException {
            if (statementFailure != null) {
                throw statementFailure;
            }
            statements.add(sql);
            if (catalogTypes != null) {
                applyToCatalog(sql);
            }
            return 0;
        }

        private void applyToCatalog(String sql) {
            Matcher m = Pattern.compile("ALTER TABLE (\\w+) DROP CONSTRAINT \\[(.+)]").matcher(sql);
            if (m.matches()) {
                catalogUniques.values().removeIf(index -> index.equals(m.group(2)));
            }
            Matcher alter = Pattern.compile("ALTER TABLE (\\w+) ALTER COLUMN (\\w+) NVARCHAR.*").matcher(sql);
            if (alter.matches()) {
                catalogTypes.put(alter.group(1) + "." + alter.group(2), "nvarchar");
            }
            Matcher add = Pattern.compile("ALTER TABLE (\\w+) ADD CONSTRAINT (\\w+) UNIQUE \\((.+)\\)").matcher(sql);
            if (add.matches()) {
                for (String column : add.group(3).split(",\\s*")) {
                    catalogUniques.put(add.group(1) + "." + column, add.group(2));
                }
            }
        }
    }

    @BeforeEach
    void setUp() throws Exception {
        migrator = new TestableMigrator();
        migrator.setDatabaseType("derby");

        Connection conn = mock(Connection.class);
        meta = mock(DatabaseMetaData.class);
        when(conn.getMetaData()).thenReturn(meta);
        migrator.setConnection(conn);

        // Default: nothing exists (fresh install)
        when(meta.getTables(any(), any(), anyString(), any()))
                .thenAnswer(inv -> resultSetWithNext(false));
        when(meta.getColumns(any(), any(), anyString(), anyString()))
                .thenAnswer(inv -> resultSetWithNext(false));
        when(meta.getIndexInfo(any(), any(), anyString(), anyBoolean(), anyBoolean()))
                .thenAnswer(inv -> resultSetWithNext(false));

        configController = mock(ConfigurationController.class);
        mockedConfig = Mockito.mockStatic(ConfigurationController.class);
        mockedConfig.when(ConfigurationController::getInstance).thenReturn(configController);
    }

    @AfterEach
    void tearDown() {
        mockedConfig.close();
    }

    // ========== Fresh install ==========

    @Test
    void freshInstall_appliesV1AndV2_andWritesVersion3() throws Exception {
        migrator.migrate();

        assertEquals(List.of("/derby-rbac-tables.sql"), migrator.scripts);
        assertEquals(1, migrator.statements.size());
        assertTrue(migrator.statements.get(0).contains("ADD COLUMN is_admin"));
        verify(configController).saveProperty(PLUGIN_NAME, VERSION_PROP, "3");
    }

    // ========== Partial states ==========

    @Test
    void v1State_tablesExistWithoutIsAdmin_appliesOnlyV2() throws Exception {
        givenBaseTablesExist();

        migrator.migrate();

        assertTrue(migrator.scripts.isEmpty(), "v1 script must not rerun");
        assertEquals(1, migrator.statements.size());
        assertTrue(migrator.statements.get(0).contains("is_admin"));
        verify(configController).saveProperty(PLUGIN_NAME, VERSION_PROP, "3");
    }

    @Test
    void v2State_fullyMigrated_runsNoDdl() throws Exception {
        givenBaseTablesExist();
        givenColumnExists("rbac_role", "is_admin");

        migrator.migrate();

        assertTrue(migrator.scripts.isEmpty());
        assertTrue(migrator.statements.isEmpty());
        // v3 has nothing to do outside SQL Server, so a v2 schema there is the latest.
        // Written once when aligning the unset stored version, once at the end
        verify(configController, atLeastOnce()).saveProperty(PLUGIN_NAME, VERSION_PROP, "3");
    }

    // ========== Backfill / realignment ==========

    @Test
    void uninstallReinstall_staleStoredVersion_isRealignedFromDbState() throws Exception {
        // The engine drops the plugin's tables on uninstall but leaves
        // CONFIGURATION properties behind: stored says 2, actual state is 0.
        when(configController.getProperty(PLUGIN_NAME, VERSION_PROP)).thenReturn("2");

        migrator.migrate();

        assertEquals(List.of("/derby-rbac-tables.sql"), migrator.scripts);
        assertEquals(1, migrator.statements.size());
        verify(configController).saveProperty(PLUGIN_NAME, VERSION_PROP, "0");
        verify(configController).saveProperty(PLUGIN_NAME, VERSION_PROP, "3");
    }

    @Test
    void v2StoredOutsideSqlServer_isAlreadyLatest_withoutRealigning() throws Exception {
        // An earlier release stored 2. Outside SQL Server v3 changes nothing, so this is the latest schema:
        // no realignment (and no WARN), no DDL, and the run records 3.
        when(configController.getProperty(PLUGIN_NAME, VERSION_PROP)).thenReturn("2");
        givenBaseTablesExist();
        givenColumnExists("rbac_role", "is_admin");

        migrator.migrate();

        assertTrue(migrator.scripts.isEmpty());
        assertTrue(migrator.statements.isEmpty());
        verify(configController, never()).saveProperty(PLUGIN_NAME, VERSION_PROP, "2");
        verify(configController).saveProperty(PLUGIN_NAME, VERSION_PROP, "3");
    }

    @Test
    void v3StoredOnSqlServer_withVarcharColumns_isRealignedAndConverted() throws Exception {
        // On SQL Server v2 and v3 differ, so a stored 3 over VARCHAR columns is a real mismatch.
        when(configController.getProperty(PLUGIN_NAME, VERSION_PROP)).thenReturn("3");
        givenSqlServerCatalog(
                Map.of("rbac_role.name", "varchar", "rbac_role.description", "varchar",
                        "rbac_role_permission.permission", "varchar"),
                Map.of("rbac_role.name", "UQ__rbac_rol__72E12F1B",
                        "rbac_role_permission.role_id", "uq_role_perm", "rbac_role_permission.permission", "uq_role_perm"));

        migrator.migrate();

        verify(configController).saveProperty(PLUGIN_NAME, VERSION_PROP, "2");
        assertEquals(7, migrator.statements.size(), migrator.statements.toString());
        verify(configController).saveProperty(PLUGIN_NAME, VERSION_PROP, "3");
    }

    @Test
    void storedVersionNotAnInteger_isTreatedAsUnset() throws Exception {
        when(configController.getProperty(PLUGIN_NAME, VERSION_PROP)).thenReturn("banana");
        givenBaseTablesExist();
        givenColumnExists("rbac_role", "is_admin");

        migrator.migrate();

        assertTrue(migrator.scripts.isEmpty());
        assertTrue(migrator.statements.isEmpty());
        verify(configController, atLeastOnce()).saveProperty(PLUGIN_NAME, VERSION_PROP, "3");
    }

    @Test
    void uppercaseIdentifiers_derbyStyle_areDetected() throws Exception {
        // Derby/Oracle normalise unquoted identifiers to uppercase; metadata
        // only answers for the uppercase candidates.
        givenBaseTablesExistUpper();
        givenColumnExists("RBAC_ROLE", "IS_ADMIN");

        migrator.migrate();

        assertTrue(migrator.scripts.isEmpty());
        assertTrue(migrator.statements.isEmpty());
    }

    // ========== Per-database V2 syntax ==========

    @Test
    void v2Syntax_oracle_usesNumberOne() throws Exception {
        migrator.setDatabaseType("oracle");
        givenBaseTablesExist();

        migrator.migrate();

        assertEquals(1, migrator.statements.size());
        assertTrue(migrator.statements.get(0).contains("NUMBER(1)"));
    }

    @Test
    void v2Syntax_sqlServer_usesBit() throws Exception {
        migrator.setDatabaseType("sqlserver");
        givenBaseTablesExist();

        migrator.migrate();

        // v3's NVARCHAR statements follow; the v3 tests below cover them.
        assertTrue(migrator.statements.get(0).contains("BIT"));
    }

    // ========== V3: SQL Server NVARCHAR ==========

    @Test
    void v3_sqlServerVarcharColumns_areConverted_andConstraintsComeBack() throws Exception {
        givenSqlServerCatalog(
                Map.of("rbac_role.name", "varchar", "rbac_role.description", "varchar",
                        "rbac_role_permission.permission", "varchar"),
                Map.of("rbac_role.name", "UQ__rbac_rol__72E12F1B",
                        "rbac_role_permission.role_id", "uq_role_perm", "rbac_role_permission.permission", "uq_role_perm"));

        migrator.migrate();

        assertEquals(List.of(
                "ALTER TABLE rbac_role DROP CONSTRAINT [UQ__rbac_rol__72E12F1B]",
                "ALTER TABLE rbac_role ALTER COLUMN name NVARCHAR(255) NOT NULL",
                "ALTER TABLE rbac_role ADD CONSTRAINT uq_rbac_role_name UNIQUE (name)",
                "ALTER TABLE rbac_role ALTER COLUMN description NVARCHAR(1024) NULL",
                "ALTER TABLE rbac_role_permission DROP CONSTRAINT [uq_role_perm]",
                "ALTER TABLE rbac_role_permission ALTER COLUMN permission NVARCHAR(255) NOT NULL",
                "ALTER TABLE rbac_role_permission ADD CONSTRAINT uq_role_perm UNIQUE (role_id, permission)"),
                migrator.statements);
        verify(configController).saveProperty(PLUGIN_NAME, VERSION_PROP, "2");
        verify(configController).saveProperty(PLUGIN_NAME, VERSION_PROP, "3");
    }

    @Test
    void v3_sqlServerAlreadyNvarchar_runsNoDdl() throws Exception {
        givenSqlServerCatalog(
                Map.of("rbac_role.name", "nvarchar", "rbac_role.description", "nvarchar",
                        "rbac_role_permission.permission", "nvarchar"),
                Map.of("rbac_role.name", "uq_rbac_role_name",
                        "rbac_role_permission.role_id", "uq_role_perm", "rbac_role_permission.permission", "uq_role_perm"));

        migrator.migrate();

        assertTrue(migrator.statements.isEmpty(), migrator.statements.toString());
        verify(configController, atLeastOnce()).saveProperty(PLUGIN_NAME, VERSION_PROP, "3");
    }

    @Test
    void v3_sqlServerStoppedHalfway_finishesOnTheNextRun() throws Exception {
        // The last run altered rbac_role.name and stopped before adding its constraint back.
        givenSqlServerCatalog(
                Map.of("rbac_role.name", "nvarchar", "rbac_role.description", "varchar",
                        "rbac_role_permission.permission", "nvarchar"),
                Map.of("rbac_role_permission.role_id", "uq_role_perm", "rbac_role_permission.permission", "uq_role_perm"));

        migrator.migrate();

        assertEquals(List.of(
                "ALTER TABLE rbac_role ADD CONSTRAINT uq_rbac_role_name UNIQUE (name)",
                "ALTER TABLE rbac_role ALTER COLUMN description NVARCHAR(1024) NULL"),
                migrator.statements);
        verify(configController).saveProperty(PLUGIN_NAME, VERSION_PROP, "3");
    }

    @Test
    void v3StatementFailure_wrapsInMigrationException() throws Exception {
        givenSqlServerCatalog(Map.of("rbac_role.name", "varchar"), Map.of());
        migrator.statementFailure = new SQLException("disk on fire");

        MigrationException e = assertThrows(MigrationException.class, () -> migrator.migrate());
        assertTrue(e.getMessage().contains("NVARCHAR"), e.getMessage());
    }

    // ========== Failure handling ==========

    @Test
    void v2StatementFailure_wrapsInMigrationException() throws Exception {
        givenBaseTablesExist();
        migrator.statementFailure = new SQLException("disk on fire");

        MigrationException e = assertThrows(MigrationException.class, () -> migrator.migrate());
        assertTrue(e.getMessage().contains("is_admin"));
    }

    @Test
    void partialSchema_roleTableWithoutChildTables_throwsMigrationException() throws Exception {
        // rbac_role landed but a child table did not (partial applyV1 failure). The
        // migrator must fail loudly rather than report a healthy schema.
        givenTableExists("rbac_role");
        givenTableExists("rbac_user_role");
        // rbac_role_permission and rbac_role_channel intentionally absent

        MigrationException e = assertThrows(MigrationException.class, () -> migrator.migrate());
        assertTrue(e.getMessage().contains("partially applied"));
        assertTrue(e.getMessage().contains("rbac_role_permission"));
    }

    @Test
    void metadataFailure_wrapsInMigrationException() throws Exception {
        when(meta.getTables(any(), any(), anyString(), any())).thenThrow(new SQLException("gone"));

        assertThrows(MigrationException.class, () -> migrator.migrate());
    }

    // ========== Engine contract ==========

    @Test
    void uninstallStatements_dropChildTablesBeforeParent_withoutIfExists() {
        List<String> statements = migrator.getUninstallStatements();

        assertEquals(4, statements.size());
        // Derby has no DROP TABLE IF EXISTS; the engine runs these with ignoreErrors
        statements.forEach(s -> assertTrue(s.startsWith("DROP TABLE rbac_"), s));
        assertEquals("DROP TABLE rbac_role", statements.get(3),
                "parent table must be dropped last (FK-safe order)");
    }

    @Test
    void migrateSerializedData_isANoOp() throws Exception {
        migrator.migrateSerializedData();
        assertTrue(migrator.scripts.isEmpty());
        assertTrue(migrator.statements.isEmpty());
    }

    // ========== Helpers ==========

    private void givenTableExists(String name) throws SQLException {
        when(meta.getTables(any(), any(), eq(name), any()))
                .thenAnswer(inv -> resultSetWithNext(true));
    }

    /** All four base tables present (a complete v1 schema), lowercase identifiers. */
    private void givenBaseTablesExist() throws SQLException {
        givenTableExists("rbac_role");
        givenTableExists("rbac_role_permission");
        givenTableExists("rbac_user_role");
        givenTableExists("rbac_role_channel");
    }

    /** All four base tables present, uppercase identifiers (Derby/Oracle style). */
    private void givenBaseTablesExistUpper() throws SQLException {
        givenTableExists("RBAC_ROLE");
        givenTableExists("RBAC_ROLE_PERMISSION");
        givenTableExists("RBAC_USER_ROLE");
        givenTableExists("RBAC_ROLE_CHANNEL");
    }

    private void givenColumnExists(String table, String column) throws SQLException {
        when(meta.getColumns(any(), any(), eq(table), eq(column)))
                .thenAnswer(inv -> resultSetWithNext(true));
    }

    private static ResultSet resultSetWithNext(boolean hasRow) throws SQLException {
        ResultSet rs = mock(ResultSet.class);
        when(rs.next()).thenReturn(hasRow);
        return rs;
    }

    /**
     * A SQL Server schema at v2 (tables and is_admin present) whose text column types and unique
     * constraints come from the given maps ("table.column" keys), which the migrator's statements update.
     */
    private void givenSqlServerCatalog(Map<String, String> types, Map<String, String> uniques) throws SQLException {
        migrator.setDatabaseType("sqlserver");
        givenBaseTablesExist();
        migrator.catalogTypes = new HashMap<>(types);
        migrator.catalogTypes.put("rbac_role.is_admin", "bit");
        migrator.catalogUniques = new HashMap<>(uniques);
        when(meta.getColumns(any(), any(), anyString(), anyString())).thenAnswer(inv -> {
            String type = migrator.catalogTypes.get(inv.getArgument(2) + "." + inv.getArgument(3));
            if (type == null) {
                return resultSetWithNext(false);
            }
            ResultSet rs = resultSetWithNext(true);
            when(rs.getString("TYPE_NAME")).thenReturn(type);
            return rs;
        });
        when(meta.getIndexInfo(any(), any(), anyString(), anyBoolean(), anyBoolean())).thenAnswer(inv -> {
            String prefix = inv.getArgument(2) + ".";
            List<String[]> rows = new ArrayList<>();
            migrator.catalogUniques.forEach((key, index) -> {
                if (key.startsWith(prefix)) {
                    rows.add(new String[] { index, key.substring(prefix.length()) });
                }
            });
            Iterator<String[]> it = rows.iterator();
            String[][] current = new String[1][];
            ResultSet rs = mock(ResultSet.class);
            when(rs.next()).thenAnswer(n -> {
                current[0] = it.hasNext() ? it.next() : null;
                return current[0] != null;
            });
            when(rs.getString("INDEX_NAME")).thenAnswer(n -> current[0][0]);
            when(rs.getString("COLUMN_NAME")).thenAnswer(n -> current[0][1]);
            return rs;
        });
    }
}
