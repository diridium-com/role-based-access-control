// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 * What an import would do, or did, with one role from a role export file.
 * One row per role in the file, in file order; {@link #getIndex()} is the
 * role's position, which the apply call uses to say which rows were ticked.
 *
 * <p>The "now" fields describe the role here that has the file role's name, when
 * there is one ({@link #isExistsHere()}); the "after" fields describe the role as
 * the import would leave it, from the file's content. An unrestricted role sees every
 * channel and lists none; a restricted role sees only its list, and a restricted role
 * with an empty list sees no channel.</p>
 */
public class RoleImportRow implements Serializable {

    private static final long serialVersionUID = 1L;

    /** What happens to the role. Only CREATE and OVERWRITE rows can be picked. */
    public enum Action {
        CREATE, OVERWRITE, UNCHANGED, SKIP
    }

    /** Where the role's channel restrictions come from. */
    public enum Channels {
        /** The channels in the file that were found on this engine (or every channel, if the file says so). */
        FROM_FILE,
        /** Channel restrictions were not applied; the existing role keeps its own. */
        KEPT,
        /** Channel restrictions were not applied; the new role is restricted to no channel. */
        NO_CHANNEL
    }

    private int index;
    private String name;
    private Action action;
    private String reason;
    private List<String> droppedPermissions = new ArrayList<>();
    private int matchedChannelCount;
    private Channels channels;
    private boolean noChannelFound;
    private boolean existsHere;
    private boolean restrictedNow;
    private boolean restrictedAfter;
    private String descriptionNow;
    private String descriptionAfter;
    private List<String> permissionsNow = new ArrayList<>();
    private List<String> permissionsAfter = new ArrayList<>();
    private List<RoleImportChannel> channelsNow = new ArrayList<>();
    private List<RoleImportChannel> channelsAfter = new ArrayList<>();

    /** @return the role's position in the file, from 0 */
    public int getIndex() {
        return index;
    }

    public void setIndex(int index) {
        this.index = index;
    }

    /** @return the role's name as the file gives it */
    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Action getAction() {
        return action;
    }

    public void setAction(Action action) {
        this.action = action;
    }

    /**
     * @return the notes the Administrators show for the row: why a row is skipped, what an
     *         import does to the role's channels, which of the import's channels and
     *         permissions this engine lacks. {@code null} when there is nothing to say.
     */
    public String getReason() {
        return reason;
    }

    public void setReason(String reason) {
        this.reason = reason;
    }

    /** @return permissions in the file that this engine doesn't offer, so they are left out */
    public List<String> getDroppedPermissions() {
        return droppedPermissions;
    }

    public void setDroppedPermissions(List<String> droppedPermissions) {
        this.droppedPermissions = droppedPermissions;
    }

    /** @return how many of the file's channels were found on this engine */
    public int getMatchedChannelCount() {
        return matchedChannelCount;
    }

    public void setMatchedChannelCount(int matchedChannelCount) {
        this.matchedChannelCount = matchedChannelCount;
    }

    public Channels getChannels() {
        return channels;
    }

    public void setChannels(Channels channels) {
        this.channels = channels;
    }

    /**
     * @return whether the import restricts this role to channels none of which was found on this
     *         engine, so that importing the row as it stands restricts the role to no channel
     *         until an administrator sets its channels.
     */
    public boolean isNoChannelFound() {
        return noChannelFound;
    }

    public void setNoChannelFound(boolean noChannelFound) {
        this.noChannelFound = noChannelFound;
    }

    /** @return whether a role with the file role's name exists here; the "now" fields are empty when not */
    public boolean isExistsHere() {
        return existsHere;
    }

    public void setExistsHere(boolean existsHere) {
        this.existsHere = existsHere;
    }

    /** @return whether the role here is restricted to {@link #getChannelsNow()}; false means every channel */
    public boolean isRestrictedNow() {
        return restrictedNow;
    }

    public void setRestrictedNow(boolean restrictedNow) {
        this.restrictedNow = restrictedNow;
    }

    /**
     * @return whether the role is restricted after the import, to the used entries of
     *         {@link #getChannelsAfter()}; false means every channel. Meaningless on a SKIP row.
     */
    public boolean isRestrictedAfter() {
        return restrictedAfter;
    }

    public void setRestrictedAfter(boolean restrictedAfter) {
        this.restrictedAfter = restrictedAfter;
    }

    /** @return the description of the role here, empty when it has none; {@code null} when there is no role here */
    public String getDescriptionNow() {
        return descriptionNow;
    }

    public void setDescriptionNow(String descriptionNow) {
        this.descriptionNow = descriptionNow;
    }

    /** @return the description the file gives the role */
    public String getDescriptionAfter() {
        return descriptionAfter;
    }

    public void setDescriptionAfter(String descriptionAfter) {
        this.descriptionAfter = descriptionAfter;
    }

    /** @return the permissions of the role here, sorted; empty when there is no role here */
    public List<String> getPermissionsNow() {
        return permissionsNow;
    }

    public void setPermissionsNow(List<String> permissionsNow) {
        this.permissionsNow = permissionsNow;
    }

    /** @return the file's permissions this engine offers, sorted (the rest are in {@link #getDroppedPermissions()}) */
    public List<String> getPermissionsAfter() {
        return permissionsAfter;
    }

    public void setPermissionsAfter(List<String> permissionsAfter) {
        this.permissionsAfter = permissionsAfter;
    }

    /**
     * @return the channels the role here is restricted to, by name, the deleted ones last;
     *         empty when it sees every channel, sees no channel, or there is no role here
     */
    public List<RoleImportChannel> getChannelsNow() {
        return channelsNow;
    }

    public void setChannelsNow(List<RoleImportChannel> channelsNow) {
        this.channelsNow = channelsNow;
    }

    /**
     * @return with channel restrictions applied, the file's channels in file order, each
     *         with what was found for it here; without, the channels the role keeps
     *         ({@link Channels#KEPT}). Empty when the role sees every channel, or no channel,
     *         after the import.
     */
    public List<RoleImportChannel> getChannelsAfter() {
        return channelsAfter;
    }

    public void setChannelsAfter(List<RoleImportChannel> channelsAfter) {
        this.channelsAfter = channelsAfter;
    }
}
