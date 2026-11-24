// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Names, at startup, each role whose name, description or a permission holds a character XML can't carry. One such role
 * makes the role list fail for both Administrators (measured: HTTP 500) and stops role export, and the admin
 * can't see the list that would show it. The log line gives its id, which a REST delete needs; the README says
 * how. rbac doesn't change the role itself: removing the character could collide with another role's name.
 */
final class UnlistableRoles {

    private static final Logger log = LoggerFactory.getLogger(UnlistableRoles.class);

    private UnlistableRoles() {
    }

    /** Checks every role in the database. Non-fatal. */
    static void run() {
        try {
            logAll(RbacRepository.getInstance().getAllRoles());
        } catch (Exception e) {
            log.warn("RBAC: could not check role names at startup (non-fatal): {}", e.getMessage());
        }
    }

    static void logAll(List<Role> roles) {
        for (Role role : roles) {
            boolean unlistable = NameCharacters.breaksXml(role.getName())
                    || NameCharacters.breaksXml(role.getDescription())
                    || (role.getPermissions() != null
                    && role.getPermissions().stream().anyMatch(NameCharacters::breaksXml));
            if (unlistable) {
                log.warn("RBAC: role {} '{}' has a character that stops the Administrators from listing roles and"
                        + " blocks role export. Delete it; the README says how.",
                        role.getId(), NameCharacters.forLog(role.getName()));
            }
        }
    }
}
