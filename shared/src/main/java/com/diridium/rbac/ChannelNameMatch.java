// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import java.io.Serializable;

/**
 * A channel in a role export file whose id isn't on this engine, but whose name only one
 * channel here has. An import uses that channel, for every role in the file that names it,
 * only when it matches channels by name.
 */
public class ChannelNameMatch implements Serializable {

    private static final long serialVersionUID = 1L;

    private String name;
    private String fileChannelId;
    private String channelId;

    /** @return the channel's name, in the file and here */
    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    /** @return the channel's id in the file */
    public String getFileChannelId() {
        return fileChannelId;
    }

    public void setFileChannelId(String fileChannelId) {
        this.fileChannelId = fileChannelId;
    }

    /** @return the id of the channel here with that name */
    public String getChannelId() {
        return channelId;
    }

    public void setChannelId(String channelId) {
        this.channelId = channelId;
    }
}
