// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Function;
import java.util.function.IntFunction;

import com.diridium.rbac.RoleImportRow.Action;
import com.diridium.rbac.RoleImportRow.Channels;
import com.diridium.rbac.RoleTransferFormat.ExportFile;
import com.diridium.rbac.RoleTransferFormat.ExportedRole;
import com.diridium.rbac.RoleTransferFormat.Refusal;

/**
 * Works out what importing a role export file would do on this engine, without
 * writing anything.
 *
 * <p>The rules, per role in the file:</p>
 * <ul>
 *   <li>A role matching this engine's admin role is skipped: an import never changes it.</li>
 *   <li>Permissions this engine doesn't offer are left out and listed. rbac stores any
 *       permission name, and a stored grant for a disabled extension would take effect
 *       as soon as that extension is enabled.</li>
 *   <li>With channel restrictions applied, each channel is matched by id, then by a
 *       name only one channel here has. A restricted role none of whose channels is
 *       found is skipped: rbac stores "every channel" as an empty list, so writing it
 *       with no channels would let it see everything.</li>
 *   <li>Without them, an existing role keeps its own channel restrictions and a new role
 *       sees every channel. A new role has no users yet, so that grants nothing until
 *       someone assigns one.</li>
 * </ul>
 *
 * <p>Names are matched with the repository's own lookup, so a database that compares
 * names without regard to case or accents matches the same way it enforces uniqueness.
 * The plan's token is a hash of every row and of the current state of every role the
 * file names, so an apply can tell whether anything changed since the preview.</p>
 */
final class RoleImportPlanner {

    /**
     * One role to write. {@code existingId} is {@code null} for a new role. When
     * {@code writeChannels} is {@code false} the role's channel rows are left as they are.
     */
    record PlannedRole(int index, Integer existingId, Role role, boolean writeChannels) {
    }

    /** Every row in file order; the writable ones by position; the token. */
    record Plan(List<RoleImportRow> rows, Map<Integer, PlannedRole> writes, String token) {
    }

    private final Function<String, Integer> findRoleIdByName;
    private final IntFunction<Role> getRoleById;
    private final Integer adminRoleId;
    private final Set<String> catalog;
    private final Map<String, String> channelNamesById;

    /**
     * @param findRoleIdByName the repository's name lookup
     * @param getRoleById      the repository's role lookup
     * @param adminRoleId      this engine's admin role, or {@code null} if there is none
     * @param catalog          every permission this engine offers
     * @param channelNamesById every channel on this engine, whatever the caller can see
     */
    RoleImportPlanner(Function<String, Integer> findRoleIdByName, IntFunction<Role> getRoleById, Integer adminRoleId,
            Set<String> catalog, Map<String, String> channelNamesById) {
        this.findRoleIdByName = findRoleIdByName;
        this.getRoleById = getRoleById;
        this.adminRoleId = adminRoleId;
        this.catalog = catalog;
        this.channelNamesById = channelNamesById;
    }

    /**
     * @throws Refusal if two roles in the file are the same role in this engine's database
     */
    Plan plan(ExportFile file, boolean applyChannels) throws Refusal {
        Map<String, List<String>> channelIdsByName = new HashMap<>();
        channelNamesById.forEach((id, name) -> channelIdsByName.computeIfAbsent(name, n -> new ArrayList<>()).add(id));

        List<RoleImportRow> rows = new ArrayList<>();
        Map<Integer, PlannedRole> writes = new LinkedHashMap<>();
        Map<Integer, Integer> fileIndexByExistingId = new HashMap<>();
        Token token = new Token().add(applyChannels);

        List<ExportedRole> roles = file.roles();
        for (int index = 0; index < roles.size(); index++) {
            ExportedRole fileRole = roles.get(index);
            RoleImportRow row = new RoleImportRow();
            row.setIndex(index);
            row.setName(fileRole.name());
            rows.add(row);

            Integer existingId = findRoleIdByName.apply(fileRole.name());
            Role existing = existingId != null ? getRoleById.apply(existingId) : null;
            if (existing == null) {
                existingId = null;
            } else {
                Integer earlier = fileIndexByExistingId.put(existingId, index);
                if (earlier != null) {
                    throw new Refusal("The roles '" + roles.get(earlier).name() + "' and '" + fileRole.name()
                            + "' in the file are the same role on this engine, whose database matches names"
                            + " without regard to case or accents. Rename one of them in the file.");
                }
            }
            token.addRole(existing);

            if (existingId != null && existingId.equals(adminRoleId)) {
                row.setAction(Action.SKIP);
                row.setReason("This is the name of this engine's admin role, which an import never changes.");
                token.addRow(row, null);
                continue;
            }

            Set<String> permissions = new LinkedHashSet<>();
            for (String permission : fileRole.permissions()) {
                if (catalog.contains(permission)) {
                    permissions.add(permission);
                } else {
                    row.getDroppedPermissions().add(permission);
                }
            }

            Set<String> channelIds = new LinkedHashSet<>();
            boolean writeChannels = true;
            if (applyChannels) {
                row.setChannels(Channels.FROM_FILE);
                for (RoleTransferFormat.Channel channel : fileRole.channels()) {
                    String id = match(channel, channelIdsByName);
                    if (id != null) {
                        channelIds.add(id);
                    } else {
                        row.getUnmatchedChannels().add(channel.name().isEmpty()
                                ? channel.id() : channel.name() + " (" + channel.id() + ")");
                    }
                }
                row.setMatchedChannelCount(channelIds.size());
                if (fileRole.restricted() && channelIds.isEmpty()) {
                    row.setAction(Action.SKIP);
                    row.setReason("None of its " + fileRole.channels().size() + " channels exist on this engine,"
                            + " and a role with no channels sees every channel.");
                    token.addRow(row, null);
                    continue;
                }
            } else if (existing != null) {
                row.setChannels(Channels.KEPT);
                channelIds.addAll(existing.getChannelIds());
                writeChannels = false;
            } else {
                row.setChannels(Channels.EVERY_CHANNEL);
                if (fileRole.restricted()) {
                    row.setReason("Sees every channel here; where it was exported it was restricted to "
                            + fileRole.channels().size() + " channel(s). Set its channels before assigning users.");
                }
            }

            Role planned = new Role();
            planned.setName(existing != null ? existing.getName() : fileRole.name());
            planned.setDescription(fileRole.description());
            planned.setPermissions(permissions);
            planned.setChannelIds(channelIds);

            if (existing == null) {
                row.setAction(Action.CREATE);
            } else if (sameContent(existing, planned)) {
                row.setAction(Action.UNCHANGED);
            } else {
                row.setAction(Action.OVERWRITE);
            }
            if (row.getAction() != Action.UNCHANGED) {
                writes.put(index, new PlannedRole(index, existingId, planned, writeChannels));
            }
            token.addRow(row, planned);
        }
        return new Plan(rows, writes, token.hex());
    }

    /** The id of the channel here that a file channel names: by id, then by a name only one channel has. */
    private String match(RoleTransferFormat.Channel channel, Map<String, List<String>> channelIdsByName) {
        if (channelNamesById.containsKey(channel.id())) {
            return channel.id();
        }
        List<String> named = channelIdsByName.get(channel.name());
        return named != null && named.size() == 1 && !channel.name().isEmpty() ? named.get(0) : null;
    }

    private static boolean sameContent(Role existing, Role planned) {
        return Objects.equals(nullToEmpty(existing.getDescription()), nullToEmpty(planned.getDescription()))
                && Objects.equals(existing.getPermissions(), planned.getPermissions())
                && Objects.equals(existing.getChannelIds(), planned.getChannelIds());
    }

    // Oracle stores an empty string as NULL, so the two read back the same.
    private static String nullToEmpty(String value) {
        return value != null ? value : "";
    }

    /** SHA-256 over length-prefixed values, so no two different plans hash the same input. */
    private static final class Token {
        private final MessageDigest digest;

        Token() {
            try {
                digest = MessageDigest.getInstance("SHA-256");
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException(e);
            }
        }

        Token add(Object value) {
            byte[] bytes = String.valueOf(value).getBytes(UTF_8);
            digest.update((bytes.length + ":").getBytes(UTF_8));
            digest.update(bytes);
            return this;
        }

        Token addAll(Collection<String> values) {
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
            add(role.getId()).add(role.getName()).add(nullToEmpty(role.getDescription()))
                    .addAll(role.getPermissions()).addAll(role.getChannelIds());
        }

        void addRow(RoleImportRow row, Role planned) {
            add(row.getIndex()).add(row.getName()).add(row.getAction()).add(row.getReason()).add(row.getChannels())
                    .add(row.getMatchedChannelCount()).addAll(row.getDroppedPermissions())
                    .addAll(row.getUnmatchedChannels());
            addRole(planned);
        }

        String hex() {
            return HexFormat.of().formatHex(digest.digest());
        }
    }
}
