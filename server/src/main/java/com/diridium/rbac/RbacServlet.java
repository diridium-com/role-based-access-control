// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.SecurityContext;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.mirth.connect.client.core.ClientException;
import com.mirth.connect.client.core.api.MirthApiException;
import com.mirth.connect.server.api.MirthServlet;
import com.mirth.connect.server.controllers.AuthorizationController;
import com.mirth.connect.server.controllers.ConfigurationController;
import com.mirth.connect.server.controllers.ControllerFactory;
import com.mirth.connect.server.controllers.DefaultAuthorizationController;

public class RbacServlet extends MirthServlet implements RbacServletInterface {

    private static final Logger log = LoggerFactory.getLogger(RbacServlet.class);

    private final RbacRepository repo;
    private final RoleService roleService;

    /**
     * The engine instantiates one of these per REST request. Resolves
     * collaborators from engine singletons / factories, then assembles a
     * {@link RoleService} for the actual business logic.
     *
     * <p>If {@link MigrationStatus#isOk()} is {@code false} the repository
     * was never initialised by {@code RbacServicePlugin.start} — we skip
     * resolving the collaborators and leave the fields {@code null}. Every
     * public method calls {@link #requireMigrationOk()} first and throws
     * a clear error before any field is used.</p>
     *
     * @param request the inbound HTTP request (engine-supplied)
     * @param sc      the security context for the authenticated caller
     *                (engine-supplied)
     */
    public RbacServlet(@Context HttpServletRequest request, @Context SecurityContext sc) {
        super(request, sc, PLUGIN_NAME);
        if (!MigrationStatus.isOk()) {
            this.repo = null;
            this.roleService = null;
            return;
        }
        this.repo = RbacRepository.getInstance();
        RbacAuditLog auditLog = new RbacAuditLog(
                ControllerFactory.getFactory().createEventController(),
                ConfigurationController.getInstance().getServerId());
        // The guard's retention floor is the CORE permission set, not core+extension.
        // The admin role is only ever seeded with core permissions (AdminRoleSeeder), so
        // requiring the extension perms too made every admin-role edit — even a description
        // change — fail validation. Safe because admin ACCESS is by the is_admin flag, not
        // by stored perms (isUserAuthorized bypasses on the flag; getMyPermissions returns
        // the full catalog for any admin-role holder regardless of what is stored).
        AdminRoleGuard adminGuard = new AdminRoleGuard(repo, PermissionUtil::getAllCorePermissions);
        this.roleService = new RoleService(repo, adminGuard, auditLog, this::invalidateCache);
    }

    /**
     * Throws a {@link ClientException} if the plugin's migration did not
     * reach {@link RbacMigrator#LATEST_VERSION}. Called by every public
     * REST method so a broken install surfaces a clear admin-visible error
     * instead of a {@code NullPointerException} or persistence failure.
     */
    private void requireMigrationOk() throws ClientException {
        if (!MigrationStatus.isOk()) {
            throw new ClientException("RBAC plugin disabled: schema migration failed ("
                    + MigrationStatus.getError() + "). Check server logs and restart.");
        }
    }

    private RbacAuthorizationController getRbacController() {
        AuthorizationController controller = DefaultAuthorizationController.create();
        if (controller instanceof RbacAuthorizationController) {
            return (RbacAuthorizationController) controller;
        }
        return null;
    }

    // ========== Role CRUD ==========

    /**
     * {@inheritDoc}
     * <p>Delegates to {@link RbacRepository#getAllRoles()}.</p>
     */
    @Override
    public List<Role> getRoles() throws ClientException {
        requireMigrationOk();
        try {
            return repo.getAllRoles();
        } catch (MirthApiException e) {
            throw e;
        } catch (Exception e) {
            log.error("Failed to get roles", e);
            throw new MirthApiException(e);
        }
    }

    /**
     * {@inheritDoc}
     * <p>Delegates to {@link RoleService#get(int)}.</p>
     */
    @Override
    public Role getRole(int roleId) throws ClientException {
        requireMigrationOk();
        try {
            return roleService.get(roleId);
        } catch (MirthApiException e) {
            throw e;
        } catch (Exception e) {
            log.error("Failed to get role {}", roleId, e);
            throw new MirthApiException(e);
        }
    }

    /**
     * {@inheritDoc}
     * <p>Delegates to {@link RoleService#create(Role)}.</p>
     */
    @Override
    public Role createRole(Role role) throws ClientException {
        requireMigrationOk();
        try {
            return roleService.create(role);
        } catch (MirthApiException e) {
            throw e;
        } catch (Exception e) {
            log.error("Failed to create role {}", role != null ? role.getName() : null, e);
            throw new MirthApiException(e);
        }
    }

    /**
     * {@inheritDoc}
     * <p>Delegates to {@link RoleService#update(int, Role)}.</p>
     */
    @Override
    public void updateRole(int roleId, Role role) throws ClientException {
        requireMigrationOk();
        try {
            roleService.update(roleId, role);
        } catch (MirthApiException e) {
            throw e;
        } catch (Exception e) {
            log.error("Failed to update role {}", roleId, e);
            throw new MirthApiException(e);
        }
    }

    /**
     * {@inheritDoc}
     * <p>Delegates to {@link RoleService#delete(int)}.</p>
     */
    @Override
    public void deleteRole(int roleId) throws ClientException {
        requireMigrationOk();
        try {
            roleService.delete(roleId);
        } catch (MirthApiException e) {
            throw e;
        } catch (Exception e) {
            log.error("Failed to delete role {}", roleId, e);
            throw new MirthApiException(e);
        }
    }

    // ========== User-Role Assignment ==========

    /**
     * {@inheritDoc}
     * <p>Delegates to {@link RoleService#getUserRole(int)}.</p>
     */
    @Override
    public Role getUserRole(int userId) throws ClientException {
        requireMigrationOk();
        try {
            return roleService.getUserRole(userId);
        } catch (MirthApiException e) {
            throw e;
        } catch (Exception e) {
            log.error("Failed to get role for user {}", userId, e);
            throw new MirthApiException(e);
        }
    }

    /**
     * {@inheritDoc}
     * <p>Delegates to {@link RoleService#assignUserRole(int, int)}.</p>
     */
    @Override
    public void assignUserRole(int userId, int roleId) throws ClientException {
        requireMigrationOk();
        try {
            roleService.assignUserRole(userId, roleId);
        } catch (MirthApiException e) {
            throw e;
        } catch (Exception e) {
            log.error("Failed to assign role {} to user {}", roleId, userId, e);
            throw new MirthApiException(e);
        }
    }

    /**
     * {@inheritDoc}
     * <p>Delegates to {@link RoleService#removeUserRole(int)}.</p>
     */
    @Override
    public void removeUserRole(int userId) throws ClientException {
        requireMigrationOk();
        try {
            roleService.removeUserRole(userId);
        } catch (MirthApiException e) {
            throw e;
        } catch (Exception e) {
            log.error("Failed to remove role from user {}", userId, e);
            throw new MirthApiException(e);
        }
    }

    // ========== Current User Permissions ==========

    /**
     * {@inheritDoc}
     * <p>Admin holders get the full permission catalog (core + extension)
     * so the UI shows everything. Non-admins get exactly their role's
     * granted set; users with no role get an empty set.</p>
     */
    @Override
    public Set<String> getMyPermissions() throws ClientException {
        requireMigrationOk();
        try {
            return roleService.effectivePermissions(getCurrentUserId(), this::getAllPermissions);
        } catch (MirthApiException e) {
            throw e;
        } catch (Exception e) {
            log.error("Failed to get permissions for current user", e);
            throw new MirthApiException(e);
        }
    }

    // ========== Permission Discovery ==========

    /**
     * {@inheritDoc}
     * <p>Returns the union of core permissions and registered extension
     * permissions, so the role editor UI can grant either category.</p>
     */
    @Override
    public Set<String> getAvailablePermissions() throws ClientException {
        requireMigrationOk();
        return getAllPermissions();
    }

    /**
     * {@inheritDoc}
     * <p>Pulls the live map from the auth controller; returns an empty map
     * if the RBAC controller is not currently registered (a state that
     * should not occur in production).</p>
     */
    @Override
    public Map<String, String> getExtensionTaskPermissions() throws ClientException {
        requireMigrationOk();
        try {
            RbacAuthorizationController rbac = getRbacController();
            return rbac != null ? rbac.getExtensionTaskPermissions() : new LinkedHashMap<>();
        } catch (MirthApiException e) {
            throw e;
        } catch (Exception e) {
            log.error("Failed to get extension task permissions", e);
            throw new MirthApiException(e);
        }
    }

    // ========== Helpers ==========

    private Set<String> getAllPermissions() {
        Set<String> all = new LinkedHashSet<>(PermissionUtil.getAllCorePermissions());
        RbacAuthorizationController rbac = getRbacController();
        if (rbac != null) {
            all.addAll(rbac.getExtensionPermissionNames());
        }
        return all;
    }

    private void invalidateCache() {
        RbacAuthorizationController rbac = getRbacController();
        if (rbac != null) {
            rbac.invalidateCache();
        }
    }
}
