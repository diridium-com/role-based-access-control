// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import java.util.HashSet;
import java.util.Set;

/**
 * What the role editor saves for a role's channels. The engine redacts the channel list by the
 * editing user's own channel restriction, so the editor can list fewer channels than the stored
 * role holds. Those unseen ids are kept, never dropped by an unrelated edit.
 */
final class RoleChannelSelection {

    static final String NO_CHANNELS_LINE = "This role sees no channels until some are ticked.";

    private RoleChannelSelection() {
    }

    /**
     * The channel ids to save with "Specific Channels" selected: the ticked ones plus every stored
     * id the editor's channel list does not contain. With "All Channels" the set is empty.
     */
    static Set<String> savedChannelIds(boolean specificSelected, Set<String> ticked, Set<String> storedIds,
            Set<String> listedIds) {
        Set<String> saved = new HashSet<>();
        if (!specificSelected) {
            return saved;
        }
        if (ticked != null) {
            saved.addAll(ticked);
        }
        if (storedIds != null) {
            for (String id : storedIds) {
                if (listedIds == null || !listedIds.contains(id)) {
                    saved.add(id);
                }
            }
        }
        return saved;
    }

    /**
     * The line under the editor's channel list, or null for none. With "Specific Channels" selected
     * and nothing ticked, it says the role sees no channels, or, when the save keeps stored ids the
     * list does not show, how many it keeps. The web editor shows the same lines.
     */
    static String channelsLine(boolean specificSelected, boolean anyTicked, Set<String> storedIds,
            Set<String> listedIds) {
        if (!specificSelected || anyTicked) {
            return null;
        }
        int unseen = savedChannelIds(true, null, storedIds, listedIds).size();
        if (unseen == 0) {
            return NO_CHANNELS_LINE;
        }
        return "This role keeps " + unseen + (unseen == 1 ? " channel" : " channels") + " this list does not show.";
    }

    /** The admin role keeps its stored flag; every other role is restricted when "Specific Channels" is selected. */
    static boolean savedRestricted(Role existing, boolean specificSelected) {
        return existing != null && existing.isAdmin() ? existing.isRestricted() : specificSelected;
    }
}
