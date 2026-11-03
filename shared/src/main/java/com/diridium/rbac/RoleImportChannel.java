// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import java.io.Serializable;

/**
 * One channel in a role import preview: a channel the role is restricted to on this
 * engine now ({@link RoleImportRow#getChannelsNow()}), or a channel in the file and what
 * was found for it here ({@link RoleImportRow#getChannelsAfter()}).
 */
public class RoleImportChannel implements Serializable {

    private static final long serialVersionUID = 1L;

    /** How the channel was looked up on this engine. */
    public enum Match {
        /** A channel here has this id. In a "now" list: the channel still exists. */
        BY_ID,
        /** No channel here has the id, but exactly one has the file's name. */
        BY_NAME,
        /** Neither. In a "now" list: the channel was deleted here. */
        NOT_FOUND
    }

    private String id;
    private String name;
    private String fileName;
    private Match match;
    private boolean used;

    /** @return the channel's id here; for a channel not found here, its id in the file */
    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    /**
     * @return the channel's name here; for a channel not found here, its name in the file;
     *         {@code null} when there is neither (a channel deleted here, or a file channel
     *         with no name that wasn't found)
     */
    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    /** @return the channel's name in the file; {@code null} in a "now" list */
    public String getFileName() {
        return fileName;
    }

    public void setFileName(String fileName) {
        this.fileName = fileName;
    }

    public Match getMatch() {
        return match;
    }

    public void setMatch(Match match) {
        this.match = match;
    }

    /**
     * @return whether the role is restricted to this channel after the import: {@code false}
     *         for a channel not found here, and for a match by name while the import doesn't
     *         match channels by name. Always {@code true} in a "now" list.
     */
    public boolean isUsed() {
        return used;
    }

    public void setUsed(boolean used) {
        this.used = used;
    }
}
