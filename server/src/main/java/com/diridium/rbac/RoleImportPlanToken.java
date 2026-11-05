// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collection;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/**
 * The plan token of a role import preview: SHA-256 over length-prefixed values, so no two
 * different plans hash the same input. An apply sends it back, and the server re-plans and
 * compares, so a role changed since the preview is caught.
 */
final class RoleImportPlanToken {
    private final MessageDigest digest;

    RoleImportPlanToken() {
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    RoleImportPlanToken add(Object value) {
        byte[] bytes = String.valueOf(value).getBytes(UTF_8);
        digest.update((bytes.length + ":").getBytes(UTF_8));
        digest.update(bytes);
        return this;
    }

    RoleImportPlanToken addAll(Collection<String> values) {
        Set<String> sorted = values != null ? new TreeSet<>(values) : new TreeSet<>();
        add(sorted.size());
        sorted.forEach(this::add);
        return this;
    }

    void addRole(Role role) {
        if (role == null) {
            add("no role");
            return;
        }
        add(role.getId()).add(role.getName()).add(nullToEmpty(role.getDescription())).add(role.isRestricted())
                .addAll(role.getPermissions()).addAll(role.getChannelIds());
    }

    void addRow(RoleImportRow row, Role planned) {
        add(row.getIndex()).add(row.getName()).add(row.getAction()).add(row.getReason()).add(row.getChannels())
                .add(row.getMatchedChannelCount()).addAll(row.getDroppedPermissions())
                .add(row.isNoChannelFound()).add(row.isExistsHere()).add(row.isRestrictedNow())
                .add(row.isRestrictedAfter()).add(row.getDescriptionNow())
                .add(row.getDescriptionAfter())
                .addAll(row.getPermissionsNow()).addAll(row.getPermissionsAfter());
        addChannels(row.getChannelsNow());
        addChannels(row.getChannelsAfter());
        addRole(planned);
    }

    void addChannels(List<RoleImportChannel> channels) {
        add(channels.size());
        for (RoleImportChannel c : channels) {
            add(c.getId()).add(c.getName()).add(c.getFileId()).add(c.getFileName()).add(c.getMatch()).add(c.isUsed());
        }
    }

    String hex() {
        return HexFormat.of().formatHex(digest.digest());
    }

    // Oracle stores an empty string as NULL, so the two read back the same.
    private static String nullToEmpty(String value) {
        return value != null ? value : "";
    }
}
