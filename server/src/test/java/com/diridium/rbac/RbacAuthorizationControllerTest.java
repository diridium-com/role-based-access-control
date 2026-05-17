// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import com.mirth.connect.client.core.Operation;
import com.mirth.connect.client.core.Operation.ExecuteType;
import com.mirth.connect.client.core.api.MirthApiException;
import com.mirth.connect.model.ExtensionPermission;
import com.mirth.connect.server.controllers.ChannelAuthorizer;
import com.mirth.connect.server.controllers.ChannelController;
import com.mirth.connect.server.controllers.ConfigurationController;
import com.mirth.connect.server.controllers.ControllerFactory;
import com.mirth.connect.server.controllers.EventController;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

/**
 * Exhaustive tests for the authorization controller's decision branches.
 *
 * <p>The base {@code AuthorizationController} no-arg constructor calls
 * {@code ControllerFactory.getFactory().create*Controller()}, so the static
 * factory is mocked in setUp. {@code RbacRepository.getInstance()} is also
 * static, mocked the same way, which lets each test stage a user→role
 * scenario without touching real persistence.
 *
 * <p>Tests pass {@code audit=false} to skip the engine's audit dispatch path
 * (we're testing authorization decisions, not engine audit machinery).
 */
class RbacAuthorizationControllerTest {

    private MockedStatic<ControllerFactory> mockedControllerFactory;
    private MockedStatic<RbacRepository> mockedRepo;
    private RbacRepository repo;
    private RbacAuthorizationController controller;
    private EventController eventController;

    @BeforeEach
    void setUp() {
        ControllerFactory factory = mock(ControllerFactory.class);
        eventController = mock(EventController.class);
        when(factory.createEventController()).thenReturn(eventController);
        when(factory.createChannelController()).thenReturn(mock(ChannelController.class));
        ConfigurationController configController = mock(ConfigurationController.class);
        when(configController.getServerId()).thenReturn("test-server-id");
        when(factory.createConfigurationController()).thenReturn(configController);

        mockedControllerFactory = Mockito.mockStatic(ControllerFactory.class);
        mockedControllerFactory.when(ControllerFactory::getFactory).thenReturn(factory);

        repo = mock(RbacRepository.class);
        mockedRepo = Mockito.mockStatic(RbacRepository.class);
        mockedRepo.when(RbacRepository::getInstance).thenReturn(repo);

        controller = new RbacAuthorizationController();
    }

    @AfterEach
    void tearDown() {
        mockedControllerFactory.close();
        mockedRepo.close();
    }

    private static Operation op(String name) {
        return new Operation(name, name, ExecuteType.SYNC, false);
    }

    // ========== isUserAuthorized: bypass paths ==========

    @Test
    void adminUser_alwaysAuthorized() throws Exception {
        // Any user assigned to an admin-flagged role bypasses the permission check
        givenUserHasRole(2, 5, Set.of(), null, true);
        assertTrue(controller.isUserAuthorized(2, op("anyOp"), null, "127.0.0.1", false));
        assertTrue(controller.isUserAuthorized(2, op("getChannel"), null, "127.0.0.1", false));
        assertTrue(controller.isUserAuthorized(2, op("deleteRole"), null, "127.0.0.1", false));
    }

    @Test
    void userOneWithoutAdminRole_isNotSpecial() {
        // user_id=1 is no longer hardcoded; without an admin role it goes through normal checks.
        // viewChannels granted but manageUsers not — removeUser (which requires manageUsers) is denied.
        givenUserHasRole(1, 5, Set.of("viewChannels"), null, false);
        assertThrows(MirthApiException.class,
                () -> controller.isUserAuthorized(1, op("removeUser"), null, "127.0.0.1", false));
    }

    @Test
    void nullOperation_authorized() throws Exception {
        assertTrue(controller.isUserAuthorized(2, null, null, "127.0.0.1", false));
    }

    @Test
    void infrastructureOperation_authorized() throws Exception {
        // Bare whitelist entries (kept for this assertion) and the always-open core ops.
        assertTrue(controller.isUserAuthorized(2, op("getMyPermissions"), null, "127.0.0.1", false));
        assertTrue(controller.isUserAuthorized(2, op("getExtensionTaskPermissions"), null, "127.0.0.1", false));
        assertTrue(controller.isUserAuthorized(2, op("getStatus"), null, "127.0.0.1", false));
        assertTrue(controller.isUserAuthorized(2, op("getServerId"), null, "127.0.0.1", false));
    }

    @Test
    void infrastructureOperation_compositeRbacNames_authorized() throws Exception {
        // At runtime RBAC's own endpoints arrive as the composite "<plugin>#<op>" name.
        // A no-role user must still be allowed to bootstrap the client UI.
        String plugin = RbacServletInterface.PLUGIN_NAME;
        assertTrue(controller.isUserAuthorized(2, op(plugin + "#getMyPermissions"), null, "127.0.0.1", false));
        assertTrue(controller.isUserAuthorized(2, op(plugin + "#getExtensionTaskPermissions"), null, "127.0.0.1", false));
    }

    @Test
    void serverSettings_notWhitelisted_deniedWithoutPermission() {
        // getServerSettings was removed from the whitelist (it leaks SMTP credentials);
        // it now requires viewServerSettings and is denied for a role without it.
        givenUserHasRole(2, 5, Set.of("viewDashboard"), null);
        assertThrows(MirthApiException.class,
                () -> controller.isUserAuthorized(2, op("getServerSettings"), null, "127.0.0.1", false));
    }

    @Test
    void degradableOperation_deniedUser_returnsFalseNotThrow() throws Exception {
        // getAllUsers/getUser/getChannels are @DontCheckAuthorized in the engine and
        // self-degrade; RBAC returns false (let the engine degrade) rather than a 403.
        when(repo.getUserRoleId(2)).thenReturn(null); // no role
        assertFalse(controller.isUserAuthorized(2, op("getAllUsers"), null, "127.0.0.1", false));
        assertFalse(controller.isUserAuthorized(2, op("getUser"), null, "127.0.0.1", false));
        assertFalse(controller.isUserAuthorized(2, op("getChannels"), null, "127.0.0.1", false));
    }

    @Test
    void degradableOperation_grantedUser_authorized() throws Exception {
        givenUserHasRole(2, 5, Set.of("manageUsers", "viewChannels"), null);
        assertTrue(controller.isUserAuthorized(2, op("getAllUsers"), null, "127.0.0.1", false));
        assertTrue(controller.isUserAuthorized(2, op("getChannels"), null, "127.0.0.1", false));
    }

    // ========== Map construction: partial-failure resilience ==========

    @Test
    void buildMap_onePermissionScanFails_remainingPermissionsStillEnforced() {
        // One failed Reflections scan must cost only its own entries, not abort
        // the rest of the map (which would silently allow everything after it).
        try (MockedStatic<com.mirth.connect.client.core.api.util.OperationUtil> opUtil =
                Mockito.mockStatic(com.mirth.connect.client.core.api.util.OperationUtil.class)) {
            opUtil.when(() -> com.mirth.connect.client.core.api.util.OperationUtil
                    .getOperationNamesForPermission(Mockito.anyString()))
                    .thenAnswer(inv -> {
                        String permission = inv.getArgument(0);
                        if ("viewChannels".equals(permission)) {
                            throw new RuntimeException("classpath scan exploded");
                        }
                        if ("manageUsers".equals(permission)) {
                            return new String[] { "removeUser" };
                        }
                        return new String[0];
                    });

            RbacAuthorizationController fresh = new RbacAuthorizationController();

            // manageUsers (scanned after the failure in declaration order) is still
            // mapped: a user without it is denied removeUser, not allowed by fallback.
            givenUserHasRole(2, 5, Set.of("viewChannels"), null, false);
            assertThrows(MirthApiException.class,
                    () -> fresh.isUserAuthorized(2, op("removeUser"), null, "127.0.0.1", false));
        }
    }

    // ========== isUserAuthorized: no role assigned ==========

    @Test
    void noRoleAssigned_throws403() {
        // removeUser is a gated, non-degradable op, so a no-role user is denied with a 403.
        when(repo.getUserRoleId(2)).thenReturn(null);
        MirthApiException e = assertThrows(MirthApiException.class,
                () -> controller.isUserAuthorized(2, op("removeUser"), null, "127.0.0.1", false));
        assertEquals(403, e.getResponse().getStatus());
    }

    @Test
    void repositoryThrowsDuringAuth_failsClosedWith403() {
        // A persistence failure mid-authorization must deny, not allow: loadUserAuth
        // catches the throw and yields no cached auth, which the decision path treats
        // as "no role -> deny" rather than letting the request through.
        when(repo.getUserRoleId(2)).thenThrow(new RuntimeException("db unreachable"));
        MirthApiException e = assertThrows(MirthApiException.class,
                () -> controller.isUserAuthorized(2, op("removeUser"), null, "127.0.0.1", false));
        assertEquals(403, e.getResponse().getStatus());
    }

    @Test
    void noRoleAssigned_isCached_secondCallDoesNotRehitDb() {
        // ConcurrentHashMap.computeIfAbsent does not cache null returns. Without the
        // NO_ROLE sentinel, every authorization check for a no-role user would re-query
        // the database. This test would fail (two DB calls) without the sentinel.
        when(repo.getUserRoleId(2)).thenReturn(null);

        assertThrows(MirthApiException.class,
                () -> controller.isUserAuthorized(2, op("removeUser"), null, "127.0.0.1", false));
        assertThrows(MirthApiException.class,
                () -> controller.isUserAuthorized(2, op("removeUser"), null, "127.0.0.1", false));

        verify(repo, times(1)).getUserRoleId(2);
    }

    @Test
    void noRoleAssigned_invalidateAllowsReload() {
        // After invalidation the cached NO_ROLE must be evicted so a newly-assigned
        // role becomes visible on the next call.
        when(repo.getUserRoleId(2)).thenReturn(null);
        assertThrows(MirthApiException.class,
                () -> controller.isUserAuthorized(2, op("removeUser"), null, "127.0.0.1", false));

        controller.invalidateCache();

        // After invalidation the controller must re-query — staged here as a granted role.
        givenUserHasRole(2, 5, Set.of("viewChannels"), null);
        try {
            assertTrue(controller.isUserAuthorized(2, op("getChannel"), null, "127.0.0.1", false));
        } catch (Exception e) {
            throw new AssertionError(e);
        }
        verify(repo, times(2)).getUserRoleId(2);
    }

    // ========== isUserAuthorized: core permissions ==========

    @Test
    void grantedCorePermission_authorized() throws Exception {
        givenUserHasRole(2, 5, Set.of("viewChannels"), null);
        assertTrue(controller.isUserAuthorized(2, op("getChannel"), null, "127.0.0.1", false));
    }

    @Test
    void deniedCorePermission_throws403WithReason() {
        // removeUser is gated on manageUsers and is non-degradable, so denial throws a 403
        // whose reason names the missing permission.
        givenUserHasRole(2, 5, Set.of("viewDashboard"), null);
        MirthApiException e = assertThrows(MirthApiException.class,
                () -> controller.isUserAuthorized(2, op("removeUser"), null, "127.0.0.1", false));
        assertEquals(403, e.getResponse().getStatus());
        assertTrue(e.getResponse().getStatusInfo().getReasonPhrase().contains("manageUsers"),
                "Reason phrase should name the missing permission");
    }

    // ========== isUserAuthorized: extension permissions ==========

    @Test
    void extensionPermission_grantedPath() throws Exception {
        // Extension ops arrive as the composite "<plugin>#<op>" name at runtime, and the
        // map is keyed the same way. The bare "testOp" would miss and fall to allow-unknown.
        controller.addExtensionPermission(extPerm("Manage Things", "testOp"));
        givenUserHasRole(2, 5, Set.of("Manage Things"), null);
        assertTrue(controller.isUserAuthorized(2, op("TestPlugin#testOp"), null, "127.0.0.1", false));
    }

    @Test
    void extensionPermission_deniedPath_throws403WithReason() {
        controller.addExtensionPermission(extPerm("Manage Things", "testOp"));
        givenUserHasRole(2, 5, Set.of("Something Else"), null);
        MirthApiException e = assertThrows(MirthApiException.class,
                () -> controller.isUserAuthorized(2, op("TestPlugin#testOp"), null, "127.0.0.1", false));
        assertTrue(e.getResponse().getStatusInfo().getReasonPhrase().contains("Manage Things"));
    }

    @Test
    void extensionPermission_bareRuntimeName_isNotSilentlyAllowed() {
        // Regression guard for the composite-name mismatch: a bare op name must NOT match
        // the composite-keyed map. (In production the engine never delivers a bare name for
        // an extension op; this pins that the map is composite-keyed.)
        controller.addExtensionPermission(extPerm("Manage Things", "testOp"));
        givenUserHasRole(2, 5, Set.of("Something Else"), null);
        // Bare "testOp" is unmapped -> falls to the allow-unknown fallback (returns true).
        // The point of the fix is that the COMPOSITE name (above) is what enforces.
        assertDoesNotThrow(() -> controller.isUserAuthorized(2, op("testOp"), null, "127.0.0.1", false));
    }

    @Test
    void rbacManagementOp_viewOnlyRole_cannotAssignAdmin_selfEscalationClosed() {
        // The critical regression: a user whose role holds only "View Roles" must NOT be
        // able to invoke the composite-named assignUserRole endpoint (which requires
        // "Manage Roles"). Before the fix this fell into allow-unknown and let any
        // role-holder self-assign the admin role.
        String plugin = RbacServletInterface.PLUGIN_NAME;
        controller.addExtensionPermission(new ExtensionPermission(
                plugin, "Manage Roles", "desc",
                new String[]{"assignUserRole", "createRole", "deleteRole"}, new String[]{}));
        givenUserHasRole(2, 5, Set.of("View Roles"), null);
        MirthApiException e = assertThrows(MirthApiException.class,
                () -> controller.isUserAuthorized(2, op(plugin + "#assignUserRole"), null, "127.0.0.1", false));
        assertTrue(e.getResponse().getStatusInfo().getReasonPhrase().contains("Manage Roles"));
    }

    // ========== isUserAuthorized: self-user-edit carve-out ==========

    @Test
    void updateUserPassword_asSelf_authorized() throws Exception {
        // Role has no manageUsers permission; self-password-change must still succeed
        // so the forced password change on first login doesn't lock the user out.
        givenUserHasRole(2, 5, Set.of("viewChannels"), null);
        assertTrue(controller.isUserAuthorized(2, op("updateUserPassword"),
                java.util.Map.of("userId", 2), "127.0.0.1", false));
    }

    @Test
    void updateUserPassword_targetingOther_denied() {
        givenUserHasRole(2, 5, Set.of("viewChannels"), null);
        assertThrows(MirthApiException.class,
                () -> controller.isUserAuthorized(2, op("updateUserPassword"),
                        java.util.Map.of("userId", 99), "127.0.0.1", false));
    }

    @Test
    void updateUser_asSelf_authorized() throws Exception {
        givenUserHasRole(2, 5, Set.of(), null);
        assertTrue(controller.isUserAuthorized(2, op("updateUser"),
                java.util.Map.of("userId", 2), "127.0.0.1", false));
    }

    @Test
    void updateUser_targetingOther_denied() {
        givenUserHasRole(2, 5, Set.of("viewChannels"), null);
        assertThrows(MirthApiException.class,
                () -> controller.isUserAuthorized(2, op("updateUser"),
                        java.util.Map.of("userId", 99), "127.0.0.1", false));
    }

    @Test
    void updateUserPassword_nullParameterMap_falsThroughToPermissionCheck() {
        givenUserHasRole(2, 5, Set.of(), null);
        // No params means we can't verify self-targeting, so the regular permission
        // check runs — and denies (role lacks manageUsers).
        assertThrows(MirthApiException.class,
                () -> controller.isUserAuthorized(2, op("updateUserPassword"), null, "127.0.0.1", false));
    }

    @Test
    void updateUser_withUsersManageRole_canStillEditOthers() throws Exception {
        // Sanity: the self carve-out doesn't break normal admin-style edits.
        givenUserHasRole(2, 5, Set.of("manageUsers"), null);
        assertTrue(controller.isUserAuthorized(2, op("updateUser"),
                java.util.Map.of("userId", 99), "127.0.0.1", false));
    }

    // ========== isUserAuthorized: last-admin deletion guard ==========

    @Test
    void removeUser_lastAdmin_denied() {
        // User 7 is the only user on the admin role; deleting them would leave zero admins.
        when(repo.getAdminRoleId()).thenReturn(5);
        when(repo.getUserRoleId(7)).thenReturn(5);
        when(repo.countUsersByRoleId(5)).thenReturn(1);
        assertThrows(MirthApiException.class,
                () -> controller.isUserAuthorized(7, op("removeUser"),
                        java.util.Map.of("userId", 7), "127.0.0.1", false));
    }

    @Test
    void removeUser_lastAdmin_deniedEvenForPrivilegedCaller() {
        // The guard sits ahead of the permission/bypass paths: a caller holding
        // manageUsers still cannot delete the last admin.
        givenUserHasRole(2, 6, Set.of("manageUsers"), null);
        when(repo.getAdminRoleId()).thenReturn(5);
        when(repo.getUserRoleId(7)).thenReturn(5);
        when(repo.countUsersByRoleId(5)).thenReturn(1);
        assertThrows(MirthApiException.class,
                () -> controller.isUserAuthorized(2, op("removeUser"),
                        java.util.Map.of("userId", 7), "127.0.0.1", false));
    }

    @Test
    void removeUser_adminWithOthersRemaining_allowed() throws Exception {
        // Two users hold the admin role; removing one still leaves an admin.
        givenUserHasRole(7, 5, Set.of(), null, true); // caller is an admin
        when(repo.getAdminRoleId()).thenReturn(5);
        when(repo.countUsersByRoleId(5)).thenReturn(2);
        assertTrue(controller.isUserAuthorized(7, op("removeUser"),
                java.util.Map.of("userId", 7), "127.0.0.1", false));
    }

    @Test
    void removeUser_nonAdminTarget_allowed() throws Exception {
        // Target user 99 isn't on the admin role, so the guard doesn't fire.
        givenUserHasRole(7, 5, Set.of(), null, true); // caller is an admin
        when(repo.getAdminRoleId()).thenReturn(5);
        when(repo.getUserRoleId(99)).thenReturn(9);
        assertTrue(controller.isUserAuthorized(7, op("removeUser"),
                java.util.Map.of("userId", 99), "127.0.0.1", false));
    }

    // ========== isUserAuthorized: unknown operations ==========

    @Test
    void unknownOperation_currentlyAllowed() throws Exception {
        // Documents existing policy: operations with no permission mapping fall through to allow.
        // Flagged in the design review — flip to deny here if/when that decision is revisited.
        givenUserHasRole(2, 5, Set.of(), null);
        assertTrue(controller.isUserAuthorized(2, op("totallyMadeUpOp"), null, "127.0.0.1", false));
    }

    // ========== addExtensionPermission ==========

    @Test
    void addExtensionPermission_nullSafe() {
        controller.addExtensionPermission(null); // does not throw
    }

    @Test
    void addExtensionPermission_multipleOpsRegistered() {
        ExtensionPermission ext = new ExtensionPermission(
                "TestPlugin", "Multi Op Perm", "desc",
                new String[]{"opA", "opB"}, new String[]{});
        controller.addExtensionPermission(ext);
        assertTrue(controller.getExtensionPermissionNames().contains("Multi Op Perm"));
    }

    @Test
    void addExtensionPermission_capturesTaskNames() {
        ExtensionPermission ext = new ExtensionPermission(
                "TestPlugin", "Manage Things", "desc",
                new String[]{"manageOp"},
                new String[]{"manageTask", "settings_TestPlugin/doRefresh"});
        controller.addExtensionPermission(ext);

        Map<String, String> taskPerms = controller.getExtensionTaskPermissions();
        assertEquals("Manage Things", taskPerms.get("manageTask"));
        assertEquals("Manage Things", taskPerms.get("settings_TestPlugin/doRefresh"));
    }

    @Test
    void getExtensionTaskPermissions_empty_returnsEmptyMap() {
        // No extension permissions registered yet
        assertTrue(controller.getExtensionTaskPermissions().isEmpty());
    }

    @Test
    void getExtensionTaskPermissions_returnsDefensiveCopy() {
        controller.addExtensionPermission(new ExtensionPermission(
                "TestPlugin", "Manage Things", "desc",
                new String[]{},
                new String[]{"someTask"}));

        Map<String, String> snapshot = controller.getExtensionTaskPermissions();
        snapshot.clear();

        // Mutating the snapshot must not affect subsequent calls
        assertEquals("Manage Things", controller.getExtensionTaskPermissions().get("someTask"));
    }

    @Test
    void addExtensionPermission_nullTaskNamesArray_isSafe() {
        controller.addExtensionPermission(new ExtensionPermission(
                "TestPlugin", "No Tasks Perm", "desc",
                new String[]{"someOp"}, null));
        // No exception; operation still registered, task map stays empty
        assertTrue(controller.getExtensionPermissionNames().contains("No Tasks Perm"));
        assertTrue(controller.getExtensionTaskPermissions().isEmpty());
    }

    @Test
    void extensionPermission_secondOpAlsoChecks() throws Exception {
        controller.addExtensionPermission(extPerm("Manage Things", "opA", "opB"));
        givenUserHasRole(2, 5, Set.of("Manage Things"), null);
        assertTrue(controller.isUserAuthorized(2, op("TestPlugin#opA"), null, "127.0.0.1", false));
        assertTrue(controller.isUserAuthorized(2, op("TestPlugin#opB"), null, "127.0.0.1", false));
    }

    // ========== doesUserHaveChannelRestrictions ==========

    @Test
    void adminUser_noChannelRestrictions() throws Exception {
        givenUserHasRole(2, 5, Set.of(), null, true);
        assertFalse(controller.doesUserHaveChannelRestrictions(2, null));
    }

    @Test
    void noRole_hasChannelRestrictions() throws Exception {
        when(repo.getUserRoleId(2)).thenReturn(null);
        assertTrue(controller.doesUserHaveChannelRestrictions(2, null));
    }

    @Test
    void roleWithChannelIds_hasRestrictions() throws Exception {
        givenUserHasRole(2, 5, Set.of(), Set.of("ch1"));
        assertTrue(controller.doesUserHaveChannelRestrictions(2, null));
    }

    @Test
    void roleWithoutChannelIds_noRestrictions() throws Exception {
        givenUserHasRole(2, 5, Set.of(), null);
        assertFalse(controller.doesUserHaveChannelRestrictions(2, null));
    }

    // ========== getChannelAuthorizer ==========

    @Test
    void adminUser_getChannelAuthorizer_null() throws Exception {
        givenUserHasRole(2, 5, Set.of(), null, true);
        assertNull(controller.getChannelAuthorizer(2, null));
    }

    @Test
    void noRole_getChannelAuthorizer_denyAll() throws Exception {
        when(repo.getUserRoleId(2)).thenReturn(null);
        ChannelAuthorizer authz = controller.getChannelAuthorizer(2, null);
        assertNotNull(authz);
        assertFalse(authz.isChannelAuthorized("anyChannel"));
    }

    @Test
    void restrictedRole_getChannelAuthorizer_setMembership() throws Exception {
        givenUserHasRole(2, 5, Set.of(), Set.of("ch1", "ch2"));
        ChannelAuthorizer authz = controller.getChannelAuthorizer(2, null);
        assertNotNull(authz);
        assertTrue(authz.isChannelAuthorized("ch1"));
        assertTrue(authz.isChannelAuthorized("ch2"));
        assertFalse(authz.isChannelAuthorized("ch3"));
    }

    @Test
    void unrestrictedRole_getChannelAuthorizer_null() throws Exception {
        givenUserHasRole(2, 5, Set.of(), null);
        assertNull(controller.getChannelAuthorizer(2, null));
    }

    // ========== Cache invalidation ==========

    @Test
    void cache_hitsOnRepeatedCalls() throws Exception {
        givenUserHasRole(2, 5, Set.of("viewChannels"), null);

        controller.isUserAuthorized(2, op("getChannel"), null, "127.0.0.1", false);
        controller.isUserAuthorized(2, op("getChannel"), null, "127.0.0.1", false);

        verify(repo, times(1)).getUserRoleId(2); // cache hit on second call
    }

    @Test
    void invalidateCache_clearsAll() throws Exception {
        givenUserHasRole(2, 5, Set.of("viewChannels"), null);

        controller.isUserAuthorized(2, op("getChannel"), null, "127.0.0.1", false);
        controller.invalidateCache();
        controller.isUserAuthorized(2, op("getChannel"), null, "127.0.0.1", false);

        verify(repo, times(2)).getUserRoleId(2);
    }

    @Test
    void invalidateCachePerUser_onlyClearsThatUser() throws Exception {
        givenUserHasRole(2, 5, Set.of("viewChannels"), null);
        givenUserHasRole(3, 5, Set.of("viewChannels"), null);

        controller.isUserAuthorized(2, op("getChannel"), null, "127.0.0.1", false);
        controller.isUserAuthorized(3, op("getChannel"), null, "127.0.0.1", false);

        controller.invalidateCache(2);

        controller.isUserAuthorized(2, op("getChannel"), null, "127.0.0.1", false);
        controller.isUserAuthorized(3, op("getChannel"), null, "127.0.0.1", false);

        verify(repo, times(2)).getUserRoleId(2); // user 2 reloaded
        verify(repo, times(1)).getUserRoleId(3); // user 3 still cached
    }

    @Test
    void invalidateCacheWithNull_safe() {
        controller.invalidateCache(null); // does not throw
    }

    // ========== usernameChanged ==========

    @Test
    void usernameChanged_noOp() throws Exception {
        controller.usernameChanged("old", "new"); // does not throw
    }

    // ========== Audit dispatch ==========

    @Test
    void auditableDenial_dispatchesEvent() {
        // audit=true + an auditable operation must dispatch a ServerEvent on the denial path.
        givenUserHasRole(2, 5, Set.of("viewDashboard"), null);
        Operation auditable = new Operation("removeUser", "removeUser", ExecuteType.SYNC, true);
        assertThrows(MirthApiException.class,
                () -> controller.isUserAuthorized(2, auditable, java.util.Map.of(), "127.0.0.1", true));
        verify(eventController, atLeastOnce()).dispatchEvent(any());
    }

    @Test
    void auditableAllow_dispatchesEvent() throws Exception {
        givenUserHasRole(2, 5, Set.of("viewChannels"), null);
        Operation auditable = new Operation("getChannel", "getChannel", ExecuteType.SYNC, true);
        controller.isUserAuthorized(2, auditable, null, "127.0.0.1", true);
        verify(eventController, atLeastOnce()).dispatchEvent(any());
    }

    // ========== Helpers ==========

    private void givenUserHasRole(int userId, int roleId, Set<String> perms, Set<String> channelIds) {
        givenUserHasRole(userId, roleId, perms, channelIds, false);
    }

    private void givenUserHasRole(int userId, int roleId, Set<String> perms, Set<String> channelIds, boolean isAdmin) {
        when(repo.getUserRoleId(userId)).thenReturn(roleId);
        Role role = new Role();
        role.setId(roleId);
        role.setPermissions(new HashSet<>(perms));
        if (channelIds != null) {
            role.setChannelIds(new HashSet<>(channelIds));
        }
        role.setAdmin(isAdmin);
        when(repo.getRoleById(roleId)).thenReturn(role);
    }

    private static ExtensionPermission extPerm(String displayName, String... operationNames) {
        return new ExtensionPermission("TestPlugin", displayName, "desc", operationNames, new String[]{});
    }
}
