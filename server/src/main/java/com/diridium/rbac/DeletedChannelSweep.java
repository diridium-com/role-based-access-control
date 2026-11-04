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
 * Startup sweep of channel restrictions to channels the engine no longer has. The engine
 * deletes a channel without telling RBAC, so the role's restriction row stays behind: the
 * role editors show it as a deleted channel, and an export carries it with no name. The
 * sweep removes such rows and leaves the role restricted, so a role whose channels were all
 * deleted is restricted to no channel rather than widened to every channel.
 *
 * <p>Non-fatal, like the sweep of deleted users' assignments: if the engine's channel list
 * cannot be read, nothing is removed, because an unreadable list must not pass for an
 * empty one.</p>
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
     * @param channelIds the engine's channel ids; a thrown exception skips the sweep
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
            Map<Integer, Integer> removedByRole = new LinkedHashMap<>();
            Map<Integer, Integer> leftByRole = new LinkedHashMap<>();
            for (Map<String, Object> row : rows.get()) {
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
                total += entry.getValue();
                String name = roleNames.getOrDefault(entry.getKey(), "id " + entry.getKey());
                log.info("RBAC: removed {} restriction(s) to deleted channels from role '{}'{}", entry.getValue(), name,
                        leftByRole.containsKey(entry.getKey()) ? "" : ", which is now restricted to no channels");
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
