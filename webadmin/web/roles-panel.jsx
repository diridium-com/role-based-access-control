// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

/*
 * "Role-Based Access Control" settings tab — the web port of RbacSettingsPanel.
 *
 * Roles table (ID/Name/Description, single-select, double-click = edit) over a
 * User-Role Assignments table (User ID/Username/Assigned Role, resolved with
 * the same N+1 getUserRole calls as Swing, "(none)" when unassigned). All
 * mutations are committed via REST the moment each dialog confirms — the tab
 * never participates in the settings view's Save/dirty tracking (it registers
 * no save()), and says so up front via the italic notice.
 *
 * Task pane = Refresh only (settings_Role-Based Access Control/doRefresh →
 * "View Roles"); the Add/Edit/Delete and Assign/Remove buttons are gated on
 * checkTask(…, 'doSave') → "Manage Roles" (the Config Map Add Row precedent).
 * When the users list is denied (listing users needs manageUsers, which a
 * View-Roles-only user lacks) the roles table still renders and the
 * assignments area degrades to a hint — same partial panel as Swing.
 */

import {
    IMMEDIATE_NOTICE, ROLE_COLUMNS, USER_COLUMNS, NONE_ROLE_LABEL,
    MSG_CATALOG_NOT_LOADED, MSG_SELECT_ROLE_EDIT, MSG_SELECT_ROLE_DELETE,
    MSG_SELECT_USER_ASSIGN, MSG_SELECT_USER_REMOVE, MSG_ADMIN_ROLE_CANNOT_DELETE,
    MSG_NO_ROLES, deleteRoleConfirmText, TITLE_CONFIRM_DELETE,
    removeRoleConfirmText, TITLE_CONFIRM_REMOVE, assignRolePromptText,
    TITLE_ASSIGN_ROLE, buildAssignmentPreview, ASSIGN_PREVIEW_HEADER,
    ASSIGN_PREVIEW_FOOTER, TITLE_CONFIRM_ASSIGNMENT
} from './rbac-core.js';
import { mapEntries } from './rbac-api.js';
import { makeRoleEditor } from './role-editor.jsx';

const RBAC_GROUP = 'settings_Role-Based Access Control';

export function registerRolesPanel(platform, api) {
    const React = platform.React;
    const ui = platform.ui;
    const RoleEditor = makeRoleEditor(platform);

    /* Role picker for Assign Role (Swing's showInputDialog with the role-name
       combo). Resolves the chosen role id, or null on cancel. */
    function pickRole(roles, username) {
        return new Promise((resolve) => {
            const sel = ui.select(
                roles.map((r) => ({ value: r.id, label: r.name })), roles[0].id);
            ui.modal({
                title: TITLE_ASSIGN_ROLE,
                body: ui.field(assignRolePromptText(username), sel),
                onClose: () => resolve(null),
                buttons: [
                    { label: 'Cancel', onClick: () => resolve(null) },
                    { label: 'OK', primary: true, onClick: () => resolve(sel.value) }
                ]
            });
        });
    }

    /* The assignment-impact preview (Swing's confirmAssignment): monospace body
       with the exact Swing text, OK/Cancel. */
    function confirmAssignment(username, currentRoleName, role, channelMap) {
        const preview = buildAssignmentPreview(username, currentRoleName, role, channelMap);
        return new Promise((resolve) => {
            ui.modal({
                title: TITLE_CONFIRM_ASSIGNMENT,
                body: ui.h('div',
                    ui.h('div', { style: 'margin-bottom: 8px' }, ASSIGN_PREVIEW_HEADER),
                    ui.h('pre', {
                        style: 'margin: 0; max-height: 260px; overflow: auto; font-size: 12px;'
                            + ' border: 1px solid var(--line, #8884); border-radius: 4px; padding: 8px 10px;'
                    }, preview),
                    ui.h('div', { style: 'margin-top: 8px; font-style: italic' }, ASSIGN_PREVIEW_FOOTER)),
                onClose: () => resolve(false),
                buttons: [
                    { label: 'Cancel', onClick: () => resolve(false) },
                    { label: 'OK', primary: true, onClick: () => resolve(true) }
                ]
            });
        });
    }

    function RolesPanel({ setTasks }) {
        const [roles, setRoles] = React.useState([]);
        const [users, setUsers] = React.useState([]);
        const [usersError, setUsersError] = React.useState(null); // users.list denied/failed
        const [userRoles, setUserRoles] = React.useState({});     // userId -> role name | null
        const [catalog, setCatalog] = React.useState(null);       // Set<string> | null (not loaded)
        const [extGroups, setExtGroups] = React.useState({});     // permission -> publishing plugin
        const [channels, setChannels] = React.useState([]);       // [{id, name}] live, wire order
        const [selectedRoleId, setSelectedRoleId] = React.useState(null);
        const [selectedUserId, setSelectedUserId] = React.useState(null);
        const [editor, setEditor] = React.useState(null);         // { role: Role|null } while open
        const [loading, setLoading] = React.useState(true);

        const loadingRef = React.useRef(false);
        const pendingRef = React.useRef(false);

        const load = React.useCallback(async () => {
            // Overlap guard (Swing's AtomicBoolean pair): drop concurrent
            // refreshes, but remember one requested mid-flight so a
            // post-mutation refresh is never silently lost.
            if (loadingRef.current) { pendingRef.current = true; return; }
            loadingRef.current = true;
            setLoading(true);
            try {
                const [rolesRes, permsRes, extGroupsRes, channelsRes, usersRes] = await Promise.allSettled([
                    api.getRoles(),
                    api.getAvailablePermissions(),
                    api.getExtensionPermissionGroups(),
                    platform.api.channels.idsAndNames(),
                    platform.api.users.list()
                ]);
                if (rolesRes.status === 'fulfilled') setRoles(rolesRes.value);
                else ui.toast(`Failed to load roles: ${rolesRes.reason && rolesRes.reason.message || rolesRes.reason}`, 'error');
                // Catalog failure leaves it null: Add/Edit stay guarded by
                // MSG_CATALOG_NOT_LOADED instead of opening an editor that
                // would wipe permissions.
                if (permsRes.status === 'fulfilled') setCatalog(permsRes.value);
                // Grouping is cosmetic — failure just leaves plugin permissions
                // under "Other".
                if (extGroupsRes.status === 'fulfilled') setExtGroups(extGroupsRes.value);
                if (channelsRes.status === 'fulfilled') {
                    setChannels(mapEntries(channelsRes.value).map(([id, name]) => ({ id, name })));
                }
                if (usersRes.status === 'fulfilled') {
                    // N+1 like Swing: resolve each user's assigned role;
                    // per-user failures tolerated (rendered as "(none)").
                    const list = usersRes.value;
                    const names = {};
                    await Promise.all(list.map(async (u) => {
                        try {
                            const role = await api.getUserRole(u.id);
                            names[u.id] = role ? role.name : null;
                        } catch {
                            names[u.id] = null;
                        }
                    }));
                    setUsers(list);
                    setUserRoles(names);
                    setUsersError(null);
                } else {
                    // Partial panel: keep the roles table working when the user
                    // list is denied (needs manageUsers) — Swing parity.
                    setUsers([]);
                    setUserRoles({});
                    setUsersError(String(usersRes.reason && usersRes.reason.message || usersRes.reason));
                }
            } finally {
                loadingRef.current = false;
                setLoading(false);
                if (pendingRef.current) { pendingRef.current = false; load(); }
            }
        }, []);

        React.useEffect(() => {
            load();
            // Refresh is the ONLY rail task — no Save participation (the panel
            // never calls setSave, so it can't trip the settings dirty tracking).
            setTasks('Role-Based Access Control Tasks', [
                ui.taskButton('Refresh', 'refresh', () => load(), { task: 'doRefresh', group: RBAC_GROUP })
            ]);
        }, [load, setTasks]);

        const canManage = platform.checkTask(RBAC_GROUP, 'doSave');
        const channelMap = React.useMemo(
            () => new Map(channels.map((c) => [c.id, c.name])), [channels]);
        const selectedRole = roles.find((r) => String(r.id) === String(selectedRoleId)) || null;
        const selectedUser = users.find((u) => String(u.id) === String(selectedUserId)) || null;

        const catalogNotLoaded = () => {
            if (!catalog || catalog.size === 0) {
                ui.toast(MSG_CATALOG_NOT_LOADED, 'warn');
                return true;
            }
            return false;
        };

        // Every mutation: commit, surface engine errors (incl. the server-side
        // AdminRoleGuard messages) as a toast, always reload.
        async function mutate(call) {
            try {
                await call();
            } catch (e) {
                ui.toast(String(e && e.message || e), 'error');
            } finally {
                load();
            }
        }

        function addRole() {
            if (catalogNotLoaded()) return;
            setEditor({ role: null });
        }

        function editRole(role) {
            const target = role || selectedRole;
            if (!target) { ui.toast(MSG_SELECT_ROLE_EDIT, 'warn'); return; }
            if (catalogNotLoaded()) return;
            setEditor({ role: target });
        }

        async function deleteRole() {
            if (!selectedRole) { ui.toast(MSG_SELECT_ROLE_DELETE, 'warn'); return; }
            // Identify the admin role by its flag, not its name (it can be
            // renamed). The server's AdminRoleGuard enforces this too; this is
            // the friendly client guard.
            if (selectedRole.isAdmin) { ui.toast(MSG_ADMIN_ROLE_CANNOT_DELETE, 'warn'); return; }
            const ok = await ui.confirmDialog(TITLE_CONFIRM_DELETE,
                deleteRoleConfirmText(selectedRole.name), { danger: true, okLabel: 'Delete' });
            if (!ok) return;
            await mutate(() => api.deleteRole(selectedRole.id));
        }

        async function assignRole() {
            if (!selectedUser) { ui.toast(MSG_SELECT_USER_ASSIGN, 'warn'); return; }
            if (roles.length === 0) { ui.toast(MSG_NO_ROLES, 'warn'); return; }
            const username = selectedUser.username;
            const roleId = await pickRole(roles, username);
            if (roleId === null) return;
            const role = roles.find((r) => String(r.id) === String(roleId));
            if (!role) return;
            const currentRoleName = userRoles[selectedUser.id] != null ? userRoles[selectedUser.id] : null;
            if (!await confirmAssignment(username, currentRoleName, role, channelMap)) return;
            await mutate(() => api.assignUserRole(selectedUser.id, role.id));
        }

        async function removeRole() {
            if (!selectedUser) { ui.toast(MSG_SELECT_USER_REMOVE, 'warn'); return; }
            // The admin floor (don't strip the last admin) is enforced
            // server-side by AdminRoleGuard; its message surfaces via mutate().
            const ok = await ui.confirmDialog(TITLE_CONFIRM_REMOVE,
                removeRoleConfirmText(selectedUser.username), { danger: true, okLabel: 'Remove' });
            if (!ok) return;
            await mutate(() => api.removeUserRole(selectedUser.id));
        }

        // The editor commits like Swing: the dialog closes the moment Apply
        // passes validation, then the mutation runs (errors toast, panel stays).
        async function applyEditor(built) {
            setEditor(null);
            await mutate(() => built.id != null
                ? api.updateRole(built.id, built)
                : api.createRole(built));
        }

        return (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                <div className="text-text-faint" style={{ fontStyle: 'italic', fontSize: 12 }}>
                    {IMMEDIATE_NOTICE}
                </div>

                <div className="panel">
                    <div className="panel-header">Roles
                        {canManage ? (
                            <div className="panel-tools" style={{ display: 'flex', gap: 8 }}>
                                <button className="btn" onClick={() => addRole()}>Add</button>
                                <button className="btn" onClick={() => editRole()}>Edit</button>
                                <button className="btn" onClick={() => deleteRole()}>Delete</button>
                            </div>
                        ) : null}
                    </div>
                    <div className="panel-body flush">
                        <table className="dt" style={{ width: '100%' }}>
                            <thead>
                                <tr>
                                    <th style={{ width: 60 }}>{ROLE_COLUMNS[0]}</th>
                                    <th>{ROLE_COLUMNS[1]}</th>
                                    <th>{ROLE_COLUMNS[2]}</th>
                                </tr>
                            </thead>
                            <tbody>
                                {roles.length === 0 ? (
                                    <tr><td colSpan={3} className="text-text-faint" style={{ padding: 12 }}>
                                        {loading ? 'Loading…' : 'No roles defined'}
                                    </td></tr>
                                ) : roles.map((role) => (
                                    <tr key={role.id}
                                        className={String(role.id) === String(selectedRoleId) ? 'selected' : ''}
                                        style={{ cursor: 'pointer' }}
                                        onClick={() => setSelectedRoleId(role.id)}
                                        onDoubleClick={() => { setSelectedRoleId(role.id); editRole(role); }}>
                                        <td>{role.id}</td>
                                        <td>{role.name}</td>
                                        <td>{role.description}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </div>

                <div className="panel">
                    <div className="panel-header">User-Role Assignments
                        {canManage && !usersError ? (
                            <div className="panel-tools" style={{ display: 'flex', gap: 8 }}>
                                <button className="btn" onClick={() => assignRole()}>Assign Role</button>
                                <button className="btn" onClick={() => removeRole()}>Remove Role</button>
                            </div>
                        ) : null}
                    </div>
                    <div className="panel-body flush">
                        {usersError ? (
                            <div className="text-text-faint" style={{ padding: 12 }}>
                                The user list could not be loaded (viewing assignments requires the
                                manageUsers permission): {usersError}
                            </div>
                        ) : (
                            <table className="dt" style={{ width: '100%' }}>
                                <thead>
                                    <tr>
                                        <th style={{ width: 80 }}>{USER_COLUMNS[0]}</th>
                                        <th>{USER_COLUMNS[1]}</th>
                                        <th>{USER_COLUMNS[2]}</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {users.length === 0 ? (
                                        <tr><td colSpan={3} className="text-text-faint" style={{ padding: 12 }}>
                                            {loading ? 'Loading…' : 'No users'}
                                        </td></tr>
                                    ) : users.map((user) => (
                                        <tr key={user.id}
                                            className={String(user.id) === String(selectedUserId) ? 'selected' : ''}
                                            style={{ cursor: 'pointer' }}
                                            onClick={() => setSelectedUserId(user.id)}>
                                            <td>{user.id}</td>
                                            <td>{user.username}</td>
                                            <td>{userRoles[user.id] != null ? userRoles[user.id] : NONE_ROLE_LABEL}</td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        )}
                    </div>
                </div>

                {editor ? (
                    <RoleEditor
                        role={editor.role}
                        catalog={catalog}
                        extGroups={extGroups}
                        channels={channels}
                        onApply={applyEditor}
                        onCancel={() => setEditor(null)} />
                ) : null}
            </div>
        );
    }

    platform.registerSettingsPanel({ label: 'Role-Based Access Control', component: RolesPanel });
}
