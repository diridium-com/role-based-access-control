// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 * The orphaned permissions roles hold, and the names of the installed plugins that are disabled: a disabled plugin
 * registers no permissions, so the grants it would register are listed too. A request to remove some sends only the
 * grants.
 */
public class UnregisteredGrants implements Serializable {

    private static final long serialVersionUID = 1L;

    private List<UnregisteredGrant> grants = new ArrayList<>();
    private List<String> disabledPlugins = new ArrayList<>();

    public List<UnregisteredGrant> getGrants() {
        return grants;
    }

    public void setGrants(List<UnregisteredGrant> grants) {
        this.grants = grants;
    }

    public List<String> getDisabledPlugins() {
        return disabledPlugins;
    }

    public void setDisabledPlugins(List<String> disabledPlugins) {
        this.disabledPlugins = disabledPlugins;
    }
}
