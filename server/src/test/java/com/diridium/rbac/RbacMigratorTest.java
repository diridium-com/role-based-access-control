// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

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
            return 0;
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
    void freshInstall_appliesV1AndV2_andWritesVersion2() throws Exception {
        migrator.migrate();

        assertEquals(List.of("/derby-rbac-tables.sql"), migrator.scripts);
        assertEquals(1, migrator.statements.size());
        assertTrue(migrator.statements.get(0).contains("ADD COLUMN is_admin"));
        verify(configController).saveProperty(PLUGIN_NAME, VERSION_PROP, "2");
    }

    // ========== Partial states ==========

    @Test
    void v1State_tablesExistWithoutIsAdmin_appliesOnlyV2() throws Exception {
        givenBaseTablesExist();

        migrator.migrate();

        assertTrue(migrator.scripts.isEmpty(), "v1 script must not rerun");
        assertEquals(1, migrator.statements.size());
        assertTrue(migrator.statements.get(0).contains("is_admin"));
        verify(configController).saveProperty(PLUGIN_NAME, VERSION_PROP, "2");
    }

    @Test
    void v2State_fullyMigrated_runsNoDdl() throws Exception {
        givenBaseTablesExist();
        givenColumnExists("rbac_role", "is_admin");

        migrator.migrate();

        assertTrue(migrator.scripts.isEmpty());
        assertTrue(migrator.statements.isEmpty());
        // Written once when aligning the unset stored version, once at the end
        verify(configController, atLeastOnce()).saveProperty(PLUGIN_NAME, VERSION_PROP, "2");
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
        verify(configController).saveProperty(PLUGIN_NAME, VERSION_PROP, "2");
    }

    @Test
    void storedVersionNotAnInteger_isTreatedAsUnset() throws Exception {
        when(configController.getProperty(PLUGIN_NAME, VERSION_PROP)).thenReturn("banana");
        givenBaseTablesExist();
        givenColumnExists("rbac_role", "is_admin");

        migrator.migrate();

        assertTrue(migrator.scripts.isEmpty());
        assertTrue(migrator.statements.isEmpty());
        verify(configController, atLeastOnce()).saveProperty(PLUGIN_NAME, VERSION_PROP, "2");
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

        assertEquals(1, migrator.statements.size());
        assertTrue(migrator.statements.get(0).contains("BIT"));
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
}
