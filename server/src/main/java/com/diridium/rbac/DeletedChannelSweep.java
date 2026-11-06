// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.mirth.connect.model.Channel;
import com.mirth.connect.server.controllers.ChannelController;

/**
 * Startup sweep of channel restrictions to channels the engine no longer has. While RBAC is
 * loaded, {@link RbacChannelPlugin} removes such rows inside the engine's channel delete; this
 * sweep covers channels deleted while it was not (the plugin disabled, or a release before 1.3.0).
 * It removes the rows and leaves the role restricted, so a role whose channels were all
 * deleted is restricted to no channel rather than widened to every channel, and logs one
 * line per role it trimmed.
 *
 * <p>Non-fatal, like the sweep of deleted users' assignments: if the engine's channel list
 * cannot be read, nothing is removed, because an unreadable list must not pass for an
 * empty one. An empty list while restriction rows exist is treated the same way: the engine's
 * channel cache answers from whatever it holds and only logs a failed database read, so an
 * empty list at startup can mean a read that failed, and deleting every restriction on it
 * would be irreversible. A list with some channels missing after a partial failure is not
 * caught; that case is accepted (design-notes.md, 2026-11-06).</p>
 */
final class DeletedChannelSweep {

    private static final Logger log = LoggerFactory.getLogger(DeletedChannelSweep.class);

    private DeletedChannelSweep() {
    }

    /** Runs the sweep against the engine's channel list. */
    static void run() {
        run(DeletedChannelSweep::engineChannelIds, RbacRepository::getAllRoleChannels,
                RbacRepository::deleteChannelIdForRole, DeletedChannelSweep::roleNames);
    }

    /**
     * @param channelIds the engine's channel ids; a thrown exception skips the sweep, and so does
     *                   an empty set while rows exist
     * @param rows       every (roleId, channelId) restriction row
     * @param delete     removes one row
     * @param names      role id to name, for the log
     * @return the number of rows removed
     */
    static int run(Supplier<Set<String>> channelIds, Supplier<List<Map<String, Object>>> rows,
            RowDeleter delete, Supplier<Map<Integer, String>> names) {
        Set<String> live;
        try {
            live = channelIds.get();
        } catch (Exception e) {
            log.warn("RBAC: sweep of restrictions to deleted channels skipped, the engine's channel list could not"
                    + " be read (non-fatal): {}", e.getMessage());
            return 0;
        }
        try {
            List<Map<String, Object>> restrictionRows = rows.get();
            if (live.isEmpty() && !restrictionRows.isEmpty()) {
                log.warn("RBAC: sweep of restrictions to deleted channels skipped, the engine reported no channels"
                        + " while {} restriction row(s) exist (non-fatal)", restrictionRows.size());
                return 0;
            }
            Map<Integer, Integer> removedByRole = new LinkedHashMap<>();
            Map<Integer, Integer> leftByRole = new LinkedHashMap<>();
            for (Map<String, Object> row : restrictionRows) {
                // The map's keys are the column labels as the driver returns them: ROLEID on Derby and
                // Oracle, roleid on PostgreSQL, roleId on MySQL and SQL Server.
                int roleId = ((Number) column(row, "roleId")).intValue();
                String channelId = String.valueOf(column(row, "channelId")).trim();
                if (live.contains(channelId)) {
                    leftByRole.merge(roleId, 1, Integer::sum);
                } else {
                    delete.delete(roleId, channelId);
                    removedByRole.merge(roleId, 1, Integer::sum);
                }
            }
            if (removedByRole.isEmpty()) {
                return 0;
            }
            Map<Integer, String> roleNames = names.get();
            int total = 0;
            for (Map.Entry<Integer, Integer> entry : removedByRole.entrySet()) {
                int count = entry.getValue();
                total += count;
                String name = roleNames.getOrDefault(entry.getKey(), "id " + entry.getKey());
                String what = count == 1 ? "1 reference to a deleted channel" : count + " references to deleted channels";
                log.info("RBAC maintenance: removed {} from role '{}'.{}", what, name,
                        leftByRole.containsKey(entry.getKey()) ? "" : " Role '" + name + "' now has no channels.");
            }
            return total;
        } catch (Exception e) {
            log.warn("RBAC: sweep of restrictions to deleted channels failed (non-fatal): {}", e.getMessage());
            return 0;
        }
    }

    interface RowDeleter {
        void delete(int roleId, String channelId);
    }

    private static Object column(Map<String, Object> row, String name) {
        for (Map.Entry<String, Object> entry : row.entrySet()) {
            if (name.equalsIgnoreCase(entry.getKey())) {
                return entry.getValue();
            }
        }
        throw new IllegalStateException("no column " + name + " in " + row.keySet());
    }

    private static Set<String> engineChannelIds() {
        Set<String> ids = new HashSet<>();
        for (Channel channel : ChannelController.getInstance().getChannels(null)) {
            ids.add(channel.getId());
        }
        return ids;
    }

    private static Map<Integer, String> roleNames() {
        Map<Integer, String> names = new LinkedHashMap<>();
        for (Role role : RbacRepository.getInstance().getAllRoles()) {
            names.put(role.getId(), role.getName());
        }
        return names;
    }
}
