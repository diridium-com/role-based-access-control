// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

import { mergeExtensionTaskPermissions, createController, RELOAD_BACKOFF_MS } from './task-permission-map.js';

const PERMISSION_VIEW = 'View Roles';
export const MAX_AUTOMATIC_RETRIES = 3;
const userKey = (user) => user == null ? null : String(user.id ?? user.username);

/** Install the permission snapshot and recover it atomically after a failed load. */
export async function registerAuthorization(platform, api, registerRoles) {
    const owner = userKey(platform.store.getState('user'));
    let active = owner !== null;
    let permissions = null;
    let isAdmin = false;
    let panelRegistered = false;
    let inFlight = null;
    let retryTimer = null;
    let automaticRetries = 0;

    function clearRetry() {
        if (retryTimer !== null) clearTimeout(retryTimer);
        retryTimer = null;
    }

    // A logout invalidates this registration permanently, even if the same user
    // signs in again before an old request finishes. Profile updates for the
    // same user do not invalidate the session.
    let unsubscribe;
    const isCurrent = () => active && userKey(platform.store.getState('user')) === owner;
    unsubscribe = platform.store.subscribe('user', (user) => {
        if (userKey(user) !== owner) {
            active = false;
            permissions = null;
            isAdmin = false;
            clearRetry();
            unsubscribe?.();
        }
    });

    function fetchPermissions(notify = false) {
        if (!isCurrent()) return Promise.resolve();
        if (inFlight) return inFlight;
        clearRetry();
        inFlight = (async () => {
            const [perms, taskPerms] = await Promise.all([
                api.getMyPermissions(),
                api.getExtensionTaskPermissions()
            ]);
            // Export and Import Roles are for the admin role only. Only a user
            // holding View Roles can be one (an admin holds every permission),
            // so nobody else is asked. A failure here means "not an admin": it
            // never fails the permission load.
            let admin = false;
            const userId = platform.store.getState('user')?.id;
            if (perms.has(PERMISSION_VIEW) && isCurrent() && userId != null) {
                try {
                    const role = await api.getUserRole(userId);
                    admin = !!role && role.isAdmin === true;
                } catch (e) {
                    console.warn('[rbac] could not read the current user\'s role - treating as not an admin:', e);
                }
            }
            // Neither the permissions nor extension mappings may cross a
            // session boundary or be applied from a partially successful load.
            if (!isCurrent()) return;
            mergeExtensionTaskPermissions(taskPerms);
            if (perms.has(PERMISSION_VIEW) && !panelRegistered) {
                registerRoles(platform, api);
                panelRegistered = true;
            }
            permissions = perms;
            isAdmin = admin;
            if (notify) {
                // Settings definitions, navigation and tasks must all observe
                // a Roles panel registered during recovery without a reload.
                platform.store.setState('webPlugins', [...(platform.store.getState('webPlugins') ?? [])]);
            }
        })().catch(error => {
            if (isCurrent() && automaticRetries < MAX_AUTOMATIC_RETRIES) {
                // Empty settings/navigation has no guaranteed future render to
                // trigger checkTask's lazy retry. Recover without user input.
                // Stop after a short outage window: indefinite background API
                // requests would keep the engine's idle session alive. Lazy
                // task checks can still retry, but never replenish this budget.
                retryTimer = setTimeout(() => {
                    retryTimer = null;
                    automaticRetries++;
                    fetchPermissions(true).catch(() => {});
                }, RELOAD_BACKOFF_MS);
            }
            throw error;
        }).finally(() => { inFlight = null; });
        return inFlight;
    }

    try {
        await fetchPermissions();
    } catch (e) {
        console.warn('[rbac] permission load failed — failing closed:', e);
    }

    if (!isCurrent()) {
        clearRetry();
        unsubscribe?.();
        return;
    }
    platform.setAuthorizationController(createController({
        getPermissions: () => isCurrent() ? permissions : null,
        getIsAdmin: () => isCurrent() && isAdmin,
        reload: () => fetchPermissions(true)
    }));
}
