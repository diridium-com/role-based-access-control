// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import static com.diridium.rbac.RbacServletInterface.PERMISSION_MANAGE;
import static com.diridium.rbac.RbacServletInterface.PERMISSION_VIEW;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Supplier;

import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import com.diridium.rbac.RoleImportRow.Action;
import com.diridium.rbac.RoleTransferFormat.ExportFile;
import com.diridium.rbac.RoleTransferFormat.ExportedRole;
import com.mirth.connect.client.core.api.MirthApiException;

/**
 * Role export and import: the second permission each needs, the preview-then-apply
 * exchange, and the audit event. Extracted from {@link RbacServlet} like
 * {@link RoleService}, so it can be tested without {@code MirthServlet}.
 *
 * <p>An operation declares one permission, so the engine checks Export Roles or
 * Import Roles and this class checks the other: export also needs View Roles, since
 * the file shows every role it holds, and import also needs Manage Roles, so it
 * can't write anything its caller couldn't write by hand.</p>
 *
 * <p>An apply re-plans the file and refuses it (409) unless the plan's token equals
 * the one from the preview, so it writes exactly what the user saw.</p>
 */
class RoleTransferService {

    private final RbacRepository repo;
    private final RbacAuditLog auditLog;
    private final Runnable cacheInvalidator;
    private final Supplier<Set<String>> catalog;
    private final Supplier<Map<String, String>> channelNamesById;
    private final Supplier<String> rbacVersion;
    private final Supplier<String> engineVersion;

    /**
     * @param catalog          every permission this engine offers
     * @param channelNamesById every channel on this engine, id to name
     * @param rbacVersion      this rbac's version, written into exports
     * @param engineVersion    this engine's version, written into exports
     */
    RoleTransferService(RbacRepository repo, RbacAuditLog auditLog, Runnable cacheInvalidator,
            Supplier<Set<String>> catalog, Supplier<Map<String, String>> channelNamesById,
            Supplier<String> rbacVersion, Supplier<String> engineVersion) {
        this.repo = repo;
        this.auditLog = auditLog;
        this.cacheInvalidator = cacheInvalidator;
        this.catalog = catalog;
        this.channelNamesById = channelNamesById;
        this.rbacVersion = rbacVersion;
        this.engineVersion = engineVersion;
    }

    /**
     * @param callerPermissions the caller's effective permissions
     * @param roleIds           the roles to export; empty for every role but the admin role
     * @return the export file's text
     * @throws MirthApiException 403 without View Roles; 400 for an unknown id, the
     *                           admin role's id, or nothing to export
     */
    String export(Set<String> callerPermissions, Set<Integer> roleIds) {
        requirePermission(callerPermissions, PERMISSION_VIEW);
        List<Role> roles = new ArrayList<>();
        if (roleIds == null || roleIds.isEmpty()) {
            for (Role role : repo.getAllRoles()) {
                if (!role.isAdmin()) {
                    roles.add(role);
                }
            }
            if (roles.isEmpty()) {
                throw badRequest("There are no roles to export. The admin role is never exported.");
            }
        } else {
            for (int roleId : new TreeSet<>(roleIds)) {
                Role role = repo.getRoleById(roleId);
                if (role == null) {
                    throw badRequest("There's no role with id " + roleId + ".");
                }
                if (role.isAdmin()) {
                    throw badRequest("The admin role is never exported.");
                }
                roles.add(role);
            }
        }

        Map<String, String> channelNames = channelNamesById.get();
        List<ExportedRole> exported = new ArrayList<>();
        for (Role role : roles) {
            List<RoleTransferFormat.Channel> channels = new ArrayList<>();
            for (String channelId : role.getChannelIds()) {
                // A restriction can name a channel since deleted here; it keeps its id, with no name.
                channels.add(new RoleTransferFormat.Channel(channelId, channelNames.getOrDefault(channelId, "")));
            }
            channels.sort(Comparator.comparing(RoleTransferFormat.Channel::name)
                    .thenComparing(RoleTransferFormat.Channel::id));
            exported.add(new ExportedRole(role.getName(), role.getDescription(),
                    new ArrayList<>(new TreeSet<>(role.getPermissions())), !role.getChannelIds().isEmpty(), channels));
        }
        try {
            return RoleTransferFormat.write(rbacVersion.get(), engineVersion.get(), exported);
        } catch (IllegalArgumentException e) {
            throw badRequest(e.getMessage());
        }
    }

    /**
     * Previews (dry run) or applies a role export file.
     *
     * @param callerPermissions the caller's effective permissions
     * @param pick              for an apply, the positions in the file of the roles to write
     * @param planToken         for an apply, the token from the preview
     * @return the preview; for an apply, the rows written
     * @throws MirthApiException 403 without Manage Roles; for an apply, 400 for a refused
     *                           file, a missing token, a bad pick, or two new roles the
     *                           database treats as one name, and 409 if the roles
     *                           changed since the preview
     */
    RoleImportResult importRoles(Set<String> callerPermissions, String file, boolean dryRun, boolean applyChannels,
            List<Integer> pick, String planToken) {
        requirePermission(callerPermissions, PERMISSION_MANAGE);
        RoleImportResult result = new RoleImportResult();
        result.setApplyChannels(applyChannels);

        ExportFile parsed;
        RoleImportPlanner.Plan plan;
        try {
            parsed = RoleTransferFormat.parse(file);
            plan = new RoleImportPlanner(repo::findRoleIdByName, repo::getRoleById, repo.getAdminRoleId(),
                    catalog.get(), channelNamesById.get()).plan(parsed, applyChannels);
        } catch (RoleTransferFormat.Refusal e) {
            if (!dryRun) {
                throw badRequest(e.getMessage());
            }
            result.setImportable(false);
            result.setRefusal(e.getMessage());
            return result;
        }
        result.setImportable(true);
        result.setFormatVersion(parsed.formatVersion());
        result.setSourceRbacVersion(parsed.rbacVersion());
        result.setSourceEngineVersion(parsed.engineVersion());
        result.setPlanToken(plan.token());
        if (dryRun) {
            result.setRows(plan.rows());
            return result;
        }

        if (planToken == null || planToken.isBlank()) {
            throw badRequest("Preview the import first, and send the preview's planToken with the apply.");
        }
        if (!plan.token().equals(planToken)) {
            throw conflict("The roles changed since the preview. Preview the import again.");
        }
        Set<Integer> picked = pick != null ? new TreeSet<>(pick) : new TreeSet<>();
        if (picked.isEmpty()) {
            throw badRequest("No roles were picked.");
        }
        List<RoleImportPlanner.PlannedRole> writes = new ArrayList<>();
        List<RoleImportRow> written = new ArrayList<>();
        for (int index : picked) {
            if (index < 0 || index >= plan.rows().size()) {
                throw badRequest("There's no role at position " + index + " in the file.");
            }
            RoleImportRow row = plan.rows().get(index);
            RoleImportPlanner.PlannedRole write = plan.writes().get(index);
            if (write == null) {
                throw badRequest("The role '" + row.getName() + "' can't be imported: "
                        + (row.getAction() == Action.SKIP ? row.getReason() : "it's the same as the role here."));
            }
            writes.add(write);
            written.add(row);
        }

        try {
            repo.importRoles(writes);
        } catch (RoleImportWriter.NameClash e) {
            throw e.changedSincePreview() ? conflict(e.getMessage()) : badRequest(e.getMessage());
        }
        cacheInvalidator.run();
        List<String> created = new ArrayList<>();
        List<String> overwritten = new ArrayList<>();
        for (RoleImportPlanner.PlannedRole write : writes) {
            (write.existingId() == null ? created : overwritten).add(write.role().getName());
        }
        auditLog.rolesImported(created, overwritten, applyChannels);
        result.setApplied(true);
        result.setRows(written);
        return result;
    }

    private static void requirePermission(Set<String> callerPermissions, String permission) {
        if (callerPermissions == null || !callerPermissions.contains(permission)) {
            throw RbacAuthorizationController.forbidden("Missing permission: " + permission);
        }
    }

    private static MirthApiException badRequest(String message) {
        return new MirthApiException(Response.status(Status.BAD_REQUEST).entity(message).build());
    }

    private static MirthApiException conflict(String message) {
        return new MirthApiException(Response.status(Status.CONFLICT).entity(message).build());
    }
}
