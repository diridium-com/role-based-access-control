// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
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
 *   <li>With channel restrictions applied, each channel is matched by id. A channel whose
 *       id isn't here but whose name only one channel here has is listed as a match by
 *       name, and used only when the import matches channels by name. A restricted role
 *       none of whose channels is found is offered with {@code noChannelFound} set and
 *       comes in restricted to no channel, ticked like any new role, with a note that an
 *       administrator has to set its channels.</li>
 *   <li>Without them, an existing role keeps its own channel restrictions and a new role is
 *       restricted to no channel until an administrator sets its channels.</li>
 *   <li>Every row describes the role here with the file role's name, if there is one
 *       (description, permissions, channels), and the role as the import would leave it,
 *       with what was found here for each of the file's channels. A change between every
 *       channel and some channels is a note as well, since every channel has no list.</li>
 * </ul>
 *
 * <p>Names are matched with the repository's own lookup, so a database that compares
 * names without regard to case or accents matches the same way it enforces uniqueness.
 * The plan's token is a hash of every row, of the matches by name and whether they are
 * used, and of the current state of every role the file names, so an apply can tell
 * whether anything changed since the preview.</p>
 */
final class RoleImportPlanner {

    /**
     * One role to write. {@code existingId} is {@code null} for a new role. When
     * {@code writeChannels} is {@code false} the role's channel rows are left as they are.
     */
    record PlannedRole(Integer existingId, Role role, boolean writeChannels) {
    }

    /** Every row in file order; the writable ones by position; the channels matched by name; the token. */
    record Plan(List<RoleImportRow> rows, Map<Integer, PlannedRole> writes, List<ChannelNameMatch> channelNameMatches,
            String token) {
    }

    private final Function<String, Integer> findRoleIdByName;
    private final IntFunction<Role> getRoleById;
    private final Integer adminRoleId;
    private final Set<String> catalog;
    private final Map<String, String> channelNamesById;
    private final Map<String, List<String>> channelIdsByName = new HashMap<>();

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
        channelNamesById.forEach((id, name) -> channelIdsByName.computeIfAbsent(name, n -> new ArrayList<>()).add(id));
    }

    /**
     * @param matchChannelsByName whether a channel whose id isn't here is matched by its name
     * @throws Refusal if two roles in the file are the same role in this engine's database
     */
    Plan plan(ExportFile file, boolean applyChannels, boolean matchChannelsByName) throws Refusal {
        List<RoleImportRow> rows = new ArrayList<>();
        Map<Integer, PlannedRole> writes = new LinkedHashMap<>();
        Map<Integer, Integer> fileIndexByExistingId = new HashMap<>();
        ChannelMatcher channels = applyChannels ? new ChannelMatcher(matchChannelsByName) : null;
        RoleImportPlanToken token = new RoleImportPlanToken().add(applyChannels).add(matchChannelsByName);

        List<ExportedRole> roles = file.roles();
        for (int index = 0; index < roles.size(); index++) {
            ExportedRole fileRole = roles.get(index);
            Integer existingId = findRoleIdByName.apply(fileRole.name());
            Role existing = existingId != null ? getRoleById.apply(existingId) : null;
            if (existing != null) {
                Integer earlier = fileIndexByExistingId.put(existingId, index);
                if (earlier != null) {
                    throw new Refusal("The roles '" + roles.get(earlier).name() + "' and '" + fileRole.name()
                            + "' in the file are the same role on this engine, whose database holds them as one"
                            + " name. Rename one of them in the file.");
                }
            }
            token.addRole(existing);

            RoleImportRow row = new RoleImportRow();
            row.setIndex(index);
            row.setName(fileRole.name());
            rows.add(row);
            PlannedRole planned = planRole(row, fileRole, existing, channels);
            if (planned != null && row.getAction() != Action.UNCHANGED) {
                writes.put(index, planned);
            }
            token.addRow(row, planned != null ? planned.role() : null);
        }
        List<ChannelNameMatch> nameMatches = channels != null ? channels.nameMatches() : new ArrayList<>();
        for (ChannelNameMatch match : nameMatches) {
            token.add(match.getFileChannelId()).add(match.getName()).add(match.getChannelId());
        }
        return new Plan(rows, writes, nameMatches, token.hex());
    }

    /**
     * Sets the row's action, and any note and changes, for one role in the file.
     *
     * @param existing the role here with the file role's name, or {@code null}
     * @param channels the file's channel matching, or {@code null} when the file's channel
     *                 restrictions aren't applied
     * @return the role as it would be written, or {@code null} for a skipped role
     */
    private PlannedRole planRole(RoleImportRow row, ExportedRole fileRole, Role existing, ChannelMatcher channels) {
        Integer existingId = existing != null ? existing.getId() : null;
        describeNow(row, existing);
        row.setDescriptionAfter(nullToEmpty(fileRole.description()));

        Set<String> permissions = new LinkedHashSet<>();
        for (String permission : fileRole.permissions()) {
            if (catalog.contains(permission)) {
                permissions.add(permission);
            } else {
                row.getDroppedPermissions().add(permission);
            }
        }
        row.setPermissionsAfter(sorted(permissions));

        boolean admin = existingId != null && existingId.equals(adminRoleId);
        Set<String> channelIds;
        boolean restricted;
        boolean writeChannels = true;
        if (channels != null) {
            row.setChannels(Channels.FROM_FILE);
            channelIds = matchChannels(row, fileRole, channels);
            restricted = fileRole.restricted();
            row.setNoChannelFound(restricted && !fileRole.channels().isEmpty() && channelIds.isEmpty());
        } else if (existing != null) {
            row.setChannels(Channels.KEPT);
            channelIds = new LinkedHashSet<>(existing.getChannelIds());
            restricted = existing.isRestricted();
            row.setChannelsAfter(new ArrayList<>(row.getChannelsNow()));
            writeChannels = false;
        } else {
            channelIds = new LinkedHashSet<>();
            restricted = true;
            row.setChannels(Channels.NO_CHANNEL);
        }
        row.setRestrictedAfter(restricted);
        if (admin) {
            row.setAction(Action.SKIP);
            row.setReason(notes(row, fileRole, existing, null, channels != null));
            return null;
        }

        Role planned = new Role();
        planned.setName(existing != null ? existing.getName() : fileRole.name());
        planned.setDescription(fileRole.description());
        planned.setPermissions(permissions);
        planned.setChannelIds(channelIds);
        planned.setRestricted(restricted);

        if (existing == null) {
            row.setAction(Action.CREATE);
        } else if (sameContent(existing, planned)) {
            row.setAction(Action.UNCHANGED);
        } else {
            row.setAction(Action.OVERWRITE);
        }
        row.setReason(notes(row, fileRole, existing, planned, channels != null));
        return new PlannedRole(existingId, planned, writeChannels);
    }

    /**
     * The row's notes, as the Administrators show them: the admin-name skip, an unchanged
     * role, what the import does to the role's channels, then which of the import's
     * channels and permissions this engine lacks. {@code null} when there is nothing to say.
     */
    private static String notes(RoleImportRow row, ExportedRole fileRole, Role existing, Role planned,
            boolean applied) {
        List<String> parts = new ArrayList<>();
        int inImport = fileRole.channels().size();
        int nowCount = existing != null ? existing.getChannelIds().size() : 0;
        if (row.getAction() == Action.SKIP) {
            parts.add("The admin role on this engine has this name. An import never changes the admin role.");
        } else if (row.getAction() == Action.UNCHANGED) {
            parts.add("Identical to the role on this engine.");
        } else if (!applied) {
            if (existing != null) {
                parts.add("This role keeps the channels currently set on this engine.");
            } else {
                parts.add((fileRole.restricted()
                        ? "The import restricts this role to " + channelsText(inImport) + ". " : "")
                        + "Restrictions are not applied, so this role is restricted to no channels on this engine"
                        + " until an administrator sets channels for this role.");
            }
        } else if (row.isNoChannelFound()) {
            String instead = existing != null && existing.isRestricted() && nowCount > 0
                    ? ", instead of the " + count(nowCount, "channel") + " currently set on this engine," : "";
            parts.add("The import restricts this role to " + count(inImport, "channel") + ". None of those channels"
                    + " exist on this engine. If imported, this role is restricted to no channels" + instead
                    + " until an administrator sets channels for this role.");
        } else if (existing != null && existing.isRestricted() && !planned.isRestricted()) {
            parts.add("On this engine this role is restricted to " + channelsText(nowCount) + ". The import"
                    + " removes the restriction, so after the import this role will see every channel.");
        } else if (existing != null && !existing.isRestricted() && planned.isRestricted()) {
            parts.add("On this engine this role sees every channel. The import restricts this role to "
                    + channelsText(planned.getChannelIds().size()) + ".");
        }
        if (applied && row.getAction() != Action.SKIP) {
            long unused = row.getChannelsAfter().stream().filter(c -> !c.isUsed()).count();
            long byName = row.getChannelsAfter().stream()
                    .filter(c -> c.getMatch() == RoleImportChannel.Match.BY_NAME && !c.isUsed()).count();
            if (unused > 0 && !row.isNoChannelFound()) {
                parts.add("Of the " + count(inImport, "channel") + " in the import, " + unused
                        + (unused == 1 ? " is" : " are") + " not on this engine.");
            }
            if (byName > 0) {
                parts.add(byName + " of those channels " + (byName == 1 ? "matches" : "match")
                        + " a channel on this engine by name.");
            }
        }
        int dropped = row.getDroppedPermissions().size();
        if (dropped == 1) {
            parts.add("1 permission in the import is not offered by this engine and is left out.");
        } else if (dropped > 1) {
            parts.add(dropped + " permissions in the import are not offered by this engine and are left out.");
        }
        return parts.isEmpty() ? null : String.join(" ", parts);
    }

    private static String count(int n, String noun) {
        return n + " " + (n == 1 ? noun : noun + "s");
    }

    /** "no channels", "1 channel", "2 channels". */
    private static String channelsText(int n) {
        return n == 0 ? "no channels" : count(n, "channel");
    }

    /** Puts on the row the role here with the file role's name: its description, permissions and channels. */
    private void describeNow(RoleImportRow row, Role existing) {
        if (existing == null) {
            return;
        }
        row.setExistsHere(true);
        row.setRestrictedNow(existing.isRestricted());
        row.setDescriptionNow(nullToEmpty(existing.getDescription()));
        row.setPermissionsNow(sorted(existing.getPermissions()));
        List<RoleImportChannel> now = new ArrayList<>();
        for (String id : existing.getChannelIds()) {
            RoleImportChannel channel = new RoleImportChannel();
            channel.setId(id);
            channel.setName(channelNamesById.get(id));
            channel.setMatch(channel.getName() != null ? RoleImportChannel.Match.BY_ID : RoleImportChannel.Match.NOT_FOUND);
            channel.setUsed(true);
            now.add(channel);
        }
        // By name; the channels deleted here (no name) last, by id.
        now.sort(Comparator.comparing((RoleImportChannel c) -> c.getName() == null)
                .thenComparing(c -> nullToEmpty(c.getName())).thenComparing(RoleImportChannel::getId));
        row.setChannelsNow(now);
    }

    /**
     * Describes each of the file role's channels on the row and returns the ids here of
     * the ones the role is restricted to after the import.
     */
    private Set<String> matchChannels(RoleImportRow row, ExportedRole fileRole, ChannelMatcher channels) {
        Set<String> channelIds = new LinkedHashSet<>();
        for (RoleTransferFormat.Channel channel : fileRole.channels()) {
            RoleImportChannel found = channels.describe(channel);
            row.getChannelsAfter().add(found);
            if (found.isUsed()) {
                channelIds.add(found.getId());
            }
        }
        row.setMatchedChannelCount(channelIds.size());
        return channelIds;
    }

    /** Matches one file's channels to this engine's, and keeps the matches by name. */
    private final class ChannelMatcher {
        private final boolean byName;
        private final Map<String, ChannelNameMatch> nameMatchesByFileId = new LinkedHashMap<>();

        ChannelMatcher(boolean byName) {
            this.byName = byName;
        }

        /**
         * What this engine has for a file channel: the channel with its id; the channel
         * with its name, when only one has it, used only when matching by name; or
         * nothing, in which case the entry keeps the file's id and name.
         */
        RoleImportChannel describe(RoleTransferFormat.Channel channel) {
            RoleImportChannel found = new RoleImportChannel();
            found.setFileId(channel.id());
            found.setFileName(channel.name());
            if (channelNamesById.containsKey(channel.id())) {
                found.setId(channel.id());
                found.setName(channelNamesById.get(channel.id()));
                found.setMatch(RoleImportChannel.Match.BY_ID);
                found.setUsed(true);
                return found;
            }
            List<String> named = channelIdsByName.get(channel.name());
            if (named == null || named.size() != 1 || channel.name().isEmpty()) {
                found.setId(channel.id());
                found.setName(channel.name().isEmpty() ? null : channel.name());
                found.setMatch(RoleImportChannel.Match.NOT_FOUND);
                found.setUsed(false);
                return found;
            }
            ChannelNameMatch match = nameMatchesByFileId.computeIfAbsent(channel.id(), id -> {
                ChannelNameMatch m = new ChannelNameMatch();
                m.setName(channel.name());
                m.setFileChannelId(id);
                m.setChannelId(named.get(0));
                return m;
            });
            found.setId(match.getChannelId());
            found.setName(channel.name());
            found.setMatch(RoleImportChannel.Match.BY_NAME);
            found.setUsed(byName);
            return found;
        }

        List<ChannelNameMatch> nameMatches() {
            return new ArrayList<>(nameMatchesByFileId.values());
        }
    }

    private static List<String> sorted(Set<String> values) {
        return new ArrayList<>(new TreeSet<>(values));
    }

    private static boolean sameContent(Role existing, Role planned) {
        return Objects.equals(nullToEmpty(existing.getDescription()), nullToEmpty(planned.getDescription()))
                && existing.isRestricted() == planned.isRestricted()
                && Objects.equals(existing.getPermissions(), planned.getPermissions())
                && Objects.equals(existing.getChannelIds(), planned.getChannelIds());
    }

    // Oracle stores an empty string as NULL, so the two read back the same.
    private static String nullToEmpty(String value) {
        return value != null ? value : "";
    }
}
