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
        /** Channel restrictions were not applied; the new role sees every channel. */
        EVERY_CHANNEL
    }

    private int index;
    private String name;
    private Action action;
    private String reason;
    private List<String> droppedPermissions = new ArrayList<>();
    private List<String> unmatchedChannels = new ArrayList<>();
    private int matchedChannelCount;
    private Channels channels;

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

    /** @return why the row is skipped, or a note the user should read; {@code null} when there is none */
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

    /** @return channels in the file found neither by id nor by name, each as "name (id)" */
    public List<String> getUnmatchedChannels() {
        return unmatchedChannels;
    }

    public void setUnmatchedChannels(List<String> unmatchedChannels) {
        this.unmatchedChannels = unmatchedChannels;
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
}
