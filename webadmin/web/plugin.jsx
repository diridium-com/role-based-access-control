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
 * A failed permission fetch skips it until a successful retry grants View Roles.
 */

import { makeApi } from './rbac-api.js';
import { registerAuthorization } from './authorization-session.js';
import { registerRolesPanel } from './roles-panel.jsx';

export async function register(platform) {
    await registerAuthorization(platform, makeApi(platform.api), registerRolesPanel);
}
