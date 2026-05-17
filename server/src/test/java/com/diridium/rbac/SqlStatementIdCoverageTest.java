// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

/**
 * Cross-checks every MyBatis statement id the repository and seeder invoke
 * against the ids actually declared in {@code sqlmap.xml}. The repository/seeder
 * unit tests mock {@code SqlSession}, so a typo'd statement id passes the suite
 * and only blows up at runtime with "Mapped Statement not found". This test
 * closes that gap.
 *
 * <p>{@code sqlmap.xml} lives in the {@code package} module (not on the server
 * test classpath), so it is read from the filesystem relative to the module
 * basedir.</p>
 */
class SqlStatementIdCoverageTest {

    /** Every statement id referenced via RbacRepository.stmt(...) or the seeder. */
    private static final List<String> STATEMENT_IDS_IN_USE = List.of(
            "getAllRoles", "getRoleById", "insertRole", "updateRole", "deleteRole",
            "getRoleIdByName", "getAdminRoleId", "setRoleIsAdmin", "countUsersByRoleId",
            "getUserRoleId", "deleteUserRole", "insertUserRole", "deleteOrphanUserRoles",
            "getPermissionsForRole", "deletePermissionsForRole", "insertPermission",
            "getChannelIdsForRole", "deleteChannelIdsForRole", "insertChannelId");

    @Test
    void everyReferencedStatementIdIsDeclaredInSqlmap() throws IOException {
        Set<String> declared = declaredStatementIds();
        for (String id : STATEMENT_IDS_IN_USE) {
            assertTrue(declared.contains(id),
                    "sqlmap.xml is missing statement id '" + id + "'; declared ids: " + declared);
        }
    }

    private static Set<String> declaredStatementIds() throws IOException {
        String xml = Files.readString(locateSqlmap());
        Set<String> ids = new LinkedHashSet<>();
        Matcher m = Pattern.compile("id=\"([a-zA-Z0-9_]+)\"").matcher(xml);
        while (m.find()) {
            ids.add(m.group(1));
        }
        return ids;
    }

    /** Resolves sqlmap.xml whether tests run from the server module dir or the reactor root. */
    private static Path locateSqlmap() {
        Path base = Paths.get(System.getProperty("user.dir"));
        Path fromModule = base.resolve("../package/resources/sqlmap.xml").normalize();
        if (Files.exists(fromModule)) {
            return fromModule;
        }
        Path fromRoot = base.resolve("package/resources/sqlmap.xml").normalize();
        if (Files.exists(fromRoot)) {
            return fromRoot;
        }
        throw new IllegalStateException("Could not locate sqlmap.xml from " + base);
    }
}
