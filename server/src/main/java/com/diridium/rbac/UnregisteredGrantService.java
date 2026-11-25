// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Supplier;

import javax.ws.rs.core.Response;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.mirth.connect.client.core.api.MirthApiException;

/**
 * Lists and removes the permissions roles hold that neither the engine nor any installed plugin registers, for the
 * admin-only Orphaned Permissions dialog in both Administrators. The engine's own permissions are never listed or
 * removed. Nothing is listed while rbac can't tell which plugin permissions are registered: when it can't read the
 * engine's permissions, or before the engine has registered the plugins' permissions, which it does after every plugin
 * has started. Then every plugin grant would look orphaned.
 */
final class UnregisteredGrantService {

    private static final Logger log = LoggerFactory.getLogger(UnregisteredGrantService.class);

    static final String LIST_NEEDS_ADMIN = "Listing orphaned permissions needs the admin role.";
    static final String REMOVE_NEEDS_ADMIN = "Removing orphaned permissions needs the admin role.";
    static final String NOT_READY = "Orphaned permissions can't be listed right now. See mirth.log for the reason.";

    private final RbacRepository repo;
    private final RbacAuditLog auditLog;
    private final Runnable cacheInvalidator;
    private final Supplier<Set<String>> corePermissions;
    private final Supplier<Set<String>> pluginPermissions;
    private final Supplier<List<String>> disabledPlugins;

    /**
     * @param corePermissions   the engine's own permissions
     * @param pluginPermissions the permissions installed, enabled plugins register, rbac's own among them
     * @param disabledPlugins   the names of the installed plugins that are disabled
     */
    UnregisteredGrantService(RbacRepository repo, RbacAuditLog auditLog, Runnable cacheInvalidator,
            Supplier<Set<String>> corePermissions, Supplier<Set<String>> pluginPermissions,
            Supplier<List<String>> disabledPlugins) {
        this.repo = repo;
        this.auditLog = auditLog;
        this.cacheInvalidator = cacheInvalidator;
        this.corePermissions = corePermissions;
        this.pluginPermissions = pluginPermissions;
        this.disabledPlugins = disabledPlugins;
    }

    /** The orphaned permissions, by role name and then permission, and the disabled plugins. */
    UnregisteredGrants list(boolean callerIsAdmin) {
        requireAdmin(callerIsAdmin, LIST_NEEDS_ADMIN);
        UnregisteredGrants result = new UnregisteredGrants();
        result.setGrants(find());
        result.setDisabledPlugins(new ArrayList<>(disabledPlugins.get()));
        return result;
    }

    /**
     * Removes the requested grants that are still orphaned, in one transaction. A requested grant that a plugin now
     * registers, that the role no longer holds, or that is the engine's own is left alone.
     *
     * @return how many were removed
     */
    int remove(boolean callerIsAdmin, UnregisteredGrants requested) {
        requireAdmin(callerIsAdmin, REMOVE_NEEDS_ADMIN);
        Map<Integer, Set<String>> orphaned = new HashMap<>();
        Map<Integer, String> roleNames = new HashMap<>();
        for (UnregisteredGrant grant : find()) {
            orphaned.computeIfAbsent(grant.getRoleId(), id -> new HashSet<>()).add(grant.getPermission());
            roleNames.put(grant.getRoleId(), grant.getRoleName());
        }
        Map<Integer, Set<String>> removeByRole = new LinkedHashMap<>();
        if (requested != null && requested.getGrants() != null) {
            for (UnregisteredGrant grant : requested.getGrants()) {
                Set<String> held = orphaned.get(grant.getRoleId());
                if (held != null && held.contains(grant.getPermission())) {
                    removeByRole.computeIfAbsent(grant.getRoleId(), id -> new TreeSet<>()).add(grant.getPermission());
                }
            }
        }
        if (removeByRole.isEmpty()) {
            return 0;
        }
        Map<Integer, Set<String>> removed = repo.removePermissions(removeByRole);
        cacheInvalidator.run();
        int count = 0;
        for (Map.Entry<Integer, Set<String>> entry : removed.entrySet()) {
            auditLog.orphanedPermissionsRemoved(roleNames.get(entry.getKey()), entry.getValue());
            count += entry.getValue().size();
        }
        return count;
    }

    private List<UnregisteredGrant> find() {
        Set<String> core = corePermissions.get();
        Set<String> plugins = pluginPermissions.get();
        if (core.isEmpty()) {
            log.error("RBAC: orphaned permissions are not listed, because the engine's permissions could not be read");
            throw unavailable(NOT_READY);
        }
        if (!plugins.contains(RbacServletInterface.PERMISSION_VIEW)) {
            log.error("RBAC: orphaned permissions are not listed, because the plugins' permissions are not registered yet");
            throw unavailable(NOT_READY);
        }
        List<UnregisteredGrant> grants = new ArrayList<>();
        for (Role role : repo.getAllRoles()) {
            if (role.getPermissions() == null) {
                continue;
            }
            for (String permission : role.getPermissions()) {
                if (!core.contains(permission) && !plugins.contains(permission)) {
                    grants.add(new UnregisteredGrant(role.getId(), role.getName(), permission));
                }
            }
        }
        grants.sort(Comparator.comparing(UnregisteredGrant::getRoleName, String.CASE_INSENSITIVE_ORDER)
                .thenComparing(UnregisteredGrant::getRoleId).thenComparing(UnregisteredGrant::getPermission));
        return grants;
    }

    private static void requireAdmin(boolean callerIsAdmin, String reason) {
        if (!callerIsAdmin) {
            throw RbacAuthorizationController.forbidden(reason);
        }
    }

    /** A 503 with the reason in the status line, which the Swing client shows, and in the body, which the web reads. */
    private static MirthApiException unavailable(String reason) {
        return new MirthApiException(Response.status(new Response.StatusType() {
            @Override
            public int getStatusCode() {
                return 503;
            }

            @Override
            public Response.Status.Family getFamily() {
                return Response.Status.Family.SERVER_ERROR;
            }

            @Override
            public String getReasonPhrase() {
                return reason;
            }
        }).entity(reason).build());
    }
}
