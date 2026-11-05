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

    /** The admin role keeps its stored flag; every other role is restricted when "Specific Channels" is selected. */
    static boolean savedRestricted(Role existing, boolean specificSelected) {
        return existing != null && existing.isAdmin() ? existing.isRestricted() : specificSelected;
    }
}
