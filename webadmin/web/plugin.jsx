// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

/*
 * Role-Based Access Control — web administrator entry.
 *
 * register() is awaited by the host's loadPlugins() (post-login), so the
 * authorization controller installs with the user's permissions already in
 * hand — no fail-closed flash on a healthy engine. On a fetch failure the
 * controller still installs and fails CLOSED (permissions = null denies every
 * task) while its throttled reload retries in the background; a successful
 * reload re-pokes the webPlugins store key so the nav and task panes
 * re-render against the recovered permission set.
 *
 * The Roles settings tab registers ONLY when the user's permissions include
 * "View Roles" (RbacServletInterface.PERMISSION_VIEW) — hidden-tab decision,
 * matching how Swing users without the permission never get a working panel.
 * A failed permission fetch also skips it (no tab is better than a dead one).
 */

import { makeApi } from './rbac-api.js';
import { mergeExtensionTaskPermissions, createController } from './task-permission-map.js';
import { registerRolesPanel } from './roles-panel.jsx';

// RbacServletInterface.PERMISSION_VIEW — gate for the Roles settings tab
// (same string GROUP_TASK_PERMISSIONS maps for .../doRefresh).
const PERMISSION_VIEW = 'View Roles';

export async function register(platform) {
    const api = makeApi(platform.api);

    // The user's loaded permission set; null = "could not be loaded", which the
    // controller treats as deny-everything (fail closed).
    let permissions = null;

    async function fetchPermissions() {
        const [perms, taskPerms] = await Promise.all([
            api.getMyPermissions(),
            api.getExtensionTaskPermissions()
        ]);
        // Other extensions' task→permission mappings merge putIfAbsent
        // (hardcoded entries win); repeat merges after the first are no-ops.
        mergeExtensionTaskPermissions(taskPerms);
        permissions = perms;
    }

    try {
        await fetchPermissions();
    } catch (e) {
        console.warn('[rbac] permission load failed — failing closed:', e);
    }

    platform.setAuthorizationController(createController({
        getPermissions: () => permissions,
        // Fired (throttled, fire-and-forget) by the fail-closed path. On success,
        // re-set webPlugins to itself: setState always notifies, forcing the nav
        // and any mounted task panes to re-run checkTask with real permissions.
        reload: async () => {
            await fetchPermissions();
            platform.store.setState('webPlugins', platform.store.getState('webPlugins'));
        }
    }));

    if (permissions !== null && permissions.has(PERMISSION_VIEW)) {
        registerRolesPanel(platform, api);
    }
}
