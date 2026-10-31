// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
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
 * Role export and import: who may, the preview-then-apply exchange, and the audit
 * event. Extracted from {@link RbacServlet} like {@link RoleService}, so it can be
 * tested without {@code MirthServlet}.
 *
 * <p>Both are for the admin role only. Importing a role is admin-level power already,
 * since Manage Roles lets its holder give themselves any role, and the admin role sees
 * every channel, so an export can name each one. The engine has already checked View
 * Roles (export) or Manage Roles (import), which keeps a role without them out
 * with the usual reason.</p>
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
     * @param callerIsAdmin whether the caller holds the admin role
     * @param roleIds       the roles to export; empty for every role but the admin role
     * @return the export file's text
     * @throws MirthApiException 403 without the admin role; 400 for an unknown id, the
     *                           admin role's id, or nothing to export
     */
    String export(boolean callerIsAdmin, Set<Integer> roleIds) {
        requireAdmin(callerIsAdmin, "Exporting roles needs the admin role.");
        List<Role> roles = new ArrayList<>();
        Set<Integer> ids = withoutNulls(roleIds);
        if (ids.isEmpty()) {
            for (Role role : repo.getAllRoles()) {
                if (!role.isAdmin()) {
                    roles.add(role);
                }
            }
            if (roles.isEmpty()) {
                throw badRequest("There are no roles to export. The admin role is never exported.");
            }
        } else {
            for (int roleId : ids) {
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
     * @param callerIsAdmin whether the caller holds the admin role
     * @param pick          for an apply, the positions in the file of the roles to write
     * @param planToken     for an apply, the token from the preview
     * @return the preview; for an apply, the rows written
     * @throws MirthApiException 403 without the admin role; for an apply, 400 for a refused
     *                           file, a missing token, a bad pick, or two new roles the
     *                           database holds as one name, and 409 if the roles
     *                           changed since the preview
     */
    RoleImportResult importRoles(boolean callerIsAdmin, String file, boolean dryRun, boolean applyChannels,
            List<Integer> pick, String planToken) {
        requireAdmin(callerIsAdmin, "Importing roles needs the admin role.");
        RoleImportResult result = new RoleImportResult();
        result.setApplyChannels(applyChannels);

        Map<String, String> channelNames = channelNamesById.get();
        ExportFile parsed;
        RoleImportPlanner.Plan plan;
        try {
            parsed = RoleTransferFormat.parse(file);
            plan = new RoleImportPlanner(repo::findRoleIdByName, repo::getRoleById, repo.getAdminRoleId(),
                    catalog.get(), channelNames).plan(parsed, applyChannels);
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
        result.setRows(apply(plan, withoutNulls(pick), planToken, channelNames, applyChannels));
        result.setApplied(true);
        return result;
    }

    /** Writes the picked rows of a plan, then clears the cache and audits. Returns the rows written. */
    private List<RoleImportRow> apply(RoleImportPlanner.Plan plan, Set<Integer> picked, String planToken,
            Map<String, String> channelNames, boolean applyChannels) {
        if (planToken == null || planToken.isBlank()) {
            throw badRequest("Preview the import first, and send the preview's planToken with the apply.");
        }
        if (!plan.token().equals(planToken)) {
            throw conflict("The roles changed since the preview. Preview the import again.");
        }
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
        auditLog.rolesImported(writes, channelNames, applyChannels);
        return written;
    }

    /** The values in order, without null elements, which name no role and no position. */
    private static Set<Integer> withoutNulls(Collection<Integer> values) {
        Set<Integer> kept = new TreeSet<>();
        if (values != null) {
            values.stream().filter(Objects::nonNull).forEach(kept::add);
        }
        return kept;
    }

    private static void requireAdmin(boolean callerIsAdmin, String reason) {
        if (!callerIsAdmin) {
            throw RbacAuthorizationController.forbidden(reason);
        }
    }

    private static MirthApiException badRequest(String message) {
        return new MirthApiException(Response.status(Status.BAD_REQUEST).entity(message).build());
    }

    private static MirthApiException conflict(String message) {
        return new MirthApiException(Response.status(Status.CONFLICT).entity(message).build());
    }
}
