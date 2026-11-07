// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import java.util.List;
import java.util.function.Function;
import java.util.function.IntFunction;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.mirth.connect.model.Channel;
import com.mirth.connect.model.ServerEventContext;
import com.mirth.connect.plugins.ChannelPlugin;
import com.mirth.connect.server.controllers.AuthorizationController;
import com.mirth.connect.server.controllers.DefaultAuthorizationController;

/**
 * Keeps rbac's channel restrictions in step with the engine's channels. The engine calls
 * {@link #remove} inside its own channel delete, so the restriction rows naming the channel
 * go at the same moment and never sit in the table as stale rows. A role left with no
 * channel stays restricted, to no channel, so nothing widens. The startup sweep
 * ({@link DeletedChannelSweep}) covers channels deleted while rbac was not loaded.
 *
 * <p>Registered through {@code plugin.xml}'s server classes; the engine picks up any server
 * plugin that implements {@link ChannelPlugin}.</p>
 */
public class RbacChannelPlugin implements ChannelPlugin {

    private static final Logger log = LoggerFactory.getLogger(RbacChannelPlugin.class);

    @Override
    public String getPluginPointName() {
        return RbacServletInterface.PLUGIN_NAME;
    }

    @Override
    public void start() {
    }

    @Override
    public void stop() {
    }

    @Override
    public void remove(Channel channel, ServerEventContext context) {
        channelRemoved(channel.getId(), channel.getName(), RbacRepository::getRoleIdsForChannel,
                RbacRepository::deleteChannelIdFromRoles, id -> RbacRepository.getInstance().getRoleById(id),
                RbacChannelPlugin::invalidateCache);
    }

    /**
     * Removes the restriction rows naming a channel and logs each role that held one.
     * Non-fatal: a failure is logged and the rows wait for the startup sweep.
     *
     * @param rolesFor   the ids of the roles restricted to the channel
     * @param delete     removes every row naming the channel, answering how many
     * @param roleById   the role after the delete, for the log (null when it is gone)
     * @param invalidate clears the authorization cache
     * @return the number of rows removed
     */
    static int channelRemoved(String channelId, String channelName, Function<String, List<Integer>> rolesFor,
            Function<String, Integer> delete, IntFunction<Role> roleById, Runnable invalidate) {
        List<Integer> roleIds;
        int removed;
        try {
            roleIds = rolesFor.apply(channelId);
            if (roleIds.isEmpty()) {
                return 0;
            }
            removed = delete.apply(channelId);
            invalidate.run();
        } catch (Exception e) {
            log.warn("RBAC maintenance: could not remove the restrictions to deleted channel '{}' (non-fatal, the"
                    + " startup sweep will): {}", channelName, e.getMessage());
            log.debug("RBAC maintenance: the failure", e);
            return 0;
        }
        // The rows are gone; a failed read of a role's name only changes the log line.
        for (int roleId : roleIds) {
            Role role = null;
            try {
                role = roleById.apply(roleId);
            } catch (Exception e) {
                log.debug("RBAC maintenance: could not read role {} for the log", roleId, e);
            }
            String name = role != null ? role.getName() : "id " + roleId;
            boolean none = role != null && (role.getChannelIds() == null || role.getChannelIds().isEmpty());
            log.info("RBAC maintenance: channel '{}' was deleted, removed its restriction from role '{}'.{}",
                    channelName, name, none ? " Role '" + name + "' now has no channels." : "");
        }
        return removed;
    }

    private static void invalidateCache() {
        AuthorizationController controller = DefaultAuthorizationController.create();
        if (controller instanceof RbacAuthorizationController) {
            ((RbacAuthorizationController) controller).invalidateCache();
        }
    }

    @Override
    public void save(Channel channel, ServerEventContext context) {
    }

    @Override
    public void deploy(Channel channel, ServerEventContext context) {
    }

    @Override
    public void deploy(ServerEventContext context) {
    }

    @Override
    public void undeploy(String channelId, ServerEventContext context) {
    }

    @Override
    public void undeploy(ServerEventContext context) {
    }
}
