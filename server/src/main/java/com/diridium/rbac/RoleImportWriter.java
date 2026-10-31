// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import static com.diridium.rbac.RbacRepository.stmt;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.ibatis.session.SqlSession;

/**
 * Writes an import's picked roles inside the caller's transaction. Commit and
 * rollback belong to {@link RbacRepository#importRoles}, so a failure on any role
 * leaves every role as it was.
 */
final class RoleImportWriter {

    /**
     * The database already has a role by a new role's name. The message is for the user.
     * {@code changedSincePreview} is {@code false} when the name belongs to a role this
     * import just created: two names in the file the database treats as one, such as
     * "Café" and "Cafe" under MySQL's default collation, which no preview can see.
     */
    static final class NameClash extends RuntimeException {
        private static final long serialVersionUID = 1L;

        private final boolean changedSincePreview;

        NameClash(String message, boolean changedSincePreview) {
            super(message);
            this.changedSincePreview = changedSincePreview;
        }

        boolean changedSincePreview() {
            return changedSincePreview;
        }
    }

    void write(SqlSession session, List<RoleImportPlanner.PlannedRole> writes) {
        Map<Integer, String> created = new HashMap<>();
        for (RoleImportPlanner.PlannedRole write : writes) {
            Role role = write.role();
            Map<String, Object> params = new HashMap<>();
            params.put("name", role.getName());
            params.put("description", role.getDescription());
            int roleId;
            if (write.existingId() == null) {
                // Asked inside the transaction, so it sees the roles this import already inserted.
                Integer taken = session.selectOne(stmt("getRoleIdByName"), role.getName());
                if (taken != null && created.containsKey(taken)) {
                    throw new NameClash("The roles '" + created.get(taken) + "' and '" + role.getName()
                            + "' in the file are the same role on this engine, whose database holds them as one"
                            + " name. Rename one of them in the file.", false);
                }
                if (taken != null) {
                    throw new NameClash("The roles changed since the preview. Preview the import again.", true);
                }
                params.put("isAdmin", false);
                // useGeneratedKeys writes the assigned id back into params["id"]
                session.insert(stmt("insertRole"), params);
                roleId = RbacRepository.insertedRoleId(session, params, role.getName());
                created.put(roleId, role.getName());
            } else {
                roleId = write.existingId();
                params.put("id", roleId);
                session.update(stmt("updateRole"), params);
            }
            RbacRepository.savePermissionsForRole(session, roleId, role.getPermissions());
            if (write.writeChannels()) {
                RbacRepository.saveChannelIdsForRole(session, roleId, role.getChannelIds());
            }
        }
    }
}
