// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;

/**
 * A role definition used by the RBAC plugin.
 *
 * <p>A role bundles three things: a set of permissions (string identifiers
 * matching the engine's {@code Permissions} constants and any registered
 * extension permissions), an optional set of channel ids that act as a
 * whitelist (empty meaning unrestricted), and a name/description for the UI.</p>
 *
 * <p>One role per installation may be flagged as the admin role via
 * {@link #isAdmin()}. The admin flag is set once at seed time and not
 * exposed via the REST or UI surface — see {@code AdminRoleGuard} and
 * {@code RbacRepository.seedAdministratorPermissions} for the full lifecycle.</p>
 */
public class Role implements Serializable {

    private static final long serialVersionUID = 1L;

    private Integer id;
    private String name;
    private String description;
    private Set<String> permissions;
    private Set<String> channelIds;

    /**
     * Flagged true for the bootstrap admin role. Set once during seeding;
     * never editable via the REST API.
     */
    private boolean isAdmin;

    /**
     * Creates a new role with empty permission and channel-id sets and the
     * admin flag set to false.
     */
    public Role() {
        this.permissions = new HashSet<>();
        this.channelIds = new HashSet<>();
        this.isAdmin = false;
    }

    /**
     * @return the database-assigned id of this role, or {@code null} for a
     *         role that has not been persisted yet
     */
    public Integer getId() {
        return id;
    }

    /**
     * @param id the database-assigned id; typically set by the repository
     *           after insert
     */
    public void setId(Integer id) {
        this.id = id;
    }

    /**
     * @return the role's display name (must be unique across all roles)
     */
    public String getName() {
        return name;
    }

    /**
     * @param name the role's display name; must be unique across all roles,
     *             enforced by a UNIQUE constraint on {@code rbac_role.name}
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * @return free-text description shown in the admin UI; may be {@code null}
     */
    public String getDescription() {
        return description;
    }

    /**
     * @param description free-text description shown in the admin UI; may be
     *                    {@code null} or empty
     */
    public void setDescription(String description) {
        this.description = description;
    }

    /**
     * @return the set of permission identifiers granted to this role; never
     *         {@code null} for a default-constructed instance but may be set
     *         to {@code null} via {@link #setPermissions(Set)}
     */
    public Set<String> getPermissions() {
        return permissions;
    }

    /**
     * @param permissions the set of permission identifiers granted to this
     *                    role; {@code null} is permitted but discouraged
     */
    public void setPermissions(Set<String> permissions) {
        this.permissions = permissions;
    }

    /**
     * @return the set of channel ids this role is restricted to; an empty
     *         set means no restriction (all channels accessible). May be set
     *         to {@code null} via {@link #setChannelIds(Set)}.
     */
    public Set<String> getChannelIds() {
        return channelIds;
    }

    /**
     * @param channelIds the channel ids this role is restricted to; empty or
     *                   {@code null} means no restriction
     */
    public void setChannelIds(Set<String> channelIds) {
        this.channelIds = channelIds;
    }

    /**
     * @return {@code true} if this role is flagged as the admin role.
     *         Users assigned to an admin role bypass the per-permission check
     *         entirely.
     */
    public boolean isAdmin() {
        return isAdmin;
    }

    /**
     * @param isAdmin whether this role is flagged as the admin role.
     *                This flag is set by the seeder; the REST and UI
     *                surfaces never update it once a role exists.
     */
    public void setAdmin(boolean isAdmin) {
        this.isAdmin = isAdmin;
    }

    /**
     * Returns a defensive copy of this role.
     *
     * <p>The permission and channel-id sets are copied so mutating one role's
     * sets does not affect the other. Null sets are normalised to empty so
     * callers receive a clean object regardless of how the source was built.</p>
     *
     * @return a new {@code Role} instance with all fields copied; scalar
     *         fields shared by reference (they're immutable), collection
     *         fields are fresh {@code HashSet}s
     */
    public Role copy() {
        Role copy = new Role();
        copy.id = this.id;
        copy.name = this.name;
        copy.description = this.description;
        copy.permissions = this.permissions != null ? new HashSet<>(this.permissions) : new HashSet<>();
        copy.channelIds = this.channelIds != null ? new HashSet<>(this.channelIds) : new HashSet<>();
        copy.isAdmin = this.isAdmin;
        return copy;
    }
}
