// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.List;

import org.apache.ibatis.session.SqlSessionManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import com.mirth.connect.server.util.SqlConfig;

/**
 * Verifies that a failed admin-role seed during {@link RbacRepository#init}
 * surfaces through {@link MigrationStatus} rather than being swallowed at WARN.
 *
 * <p>The seeding logic itself is exercised by {@link AdminRoleSeederTest}; this
 * test only pins the repository's failure-surfacing wiring: a broken bootstrap
 * must flip the plugin into the "disabled, check logs and restart" state so the
 * servlet returns a clear error instead of leaving the operator with
 * unexplained 403s.</p>
 */
class RbacRepositorySeedTest {

    private MockedStatic<SqlConfig> mockedSqlConfig;

    @BeforeEach
    void setUp() {
        // The repository is a static singleton; ensure a clean slate so init() actually runs.
        RbacRepository.close();
        MigrationStatus.markOk();
    }

    @AfterEach
    void tearDown() {
        if (mockedSqlConfig != null) {
            mockedSqlConfig.close();
        }
        RbacRepository.close();
        MigrationStatus.markOk();
    }

    @Test
    void seedFailure_marksMigrationStatusFailed() {
        // openSession blows up — simulates the seed transaction failing to even start.
        SqlConfig sqlConfig = mock(SqlConfig.class);
        SqlSessionManager manager = mock(SqlSessionManager.class);
        when(sqlConfig.getSqlSessionManager()).thenReturn(manager);
        when(manager.openSession(false)).thenThrow(new RuntimeException("db unreachable"));

        mockedSqlConfig = Mockito.mockStatic(SqlConfig.class);
        mockedSqlConfig.when(SqlConfig::getInstance).thenReturn(sqlConfig);

        RbacRepository.init(List.of(1));

        assertFalse(MigrationStatus.isOk(),
                "a failed seed must mark the plugin disabled, not report healthy");
        assertTrue(MigrationStatus.getError().contains("admin role seeding failed"),
                "the surfaced error should name the seed failure; was: " + MigrationStatus.getError());
    }
}
