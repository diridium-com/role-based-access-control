// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

/*
 * The User-Role Assignments half of the Roles settings panel: the users table
 * (User ID/Username/Assigned Role, "(none)" when unassigned, "(unknown)" when
 * the lookup failed; see lookUpRoleNames in rbac-core.js), Assign Role with
 * its role picker and impact preview, and Remove Role. The panel loads the users
 * and their roles with everything else and hands them in; each change goes
 * through the panel's mutate(), which shows the engine's error and reloads.
 * When the users list is denied (listing users needs manageUsers, which a
 * View-Roles-only user lacks) the table degrades to a hint, as in Swing.
 */

import {
    USER_COLUMNS, UNKNOWN_ROLE_LABEL, MSG_SELECT_USER_ASSIGN, MSG_SELECT_USER_REMOVE, MSG_NO_ROLES,
    removeRoleConfirmText, TITLE_CONFIRM_REMOVE, assignRolePromptText, TITLE_ASSIGN_ROLE,
    buildAssignmentPreview, ASSIGN_PREVIEW_HEADER, ASSIGN_PREVIEW_FOOTER, TITLE_CONFIRM_ASSIGNMENT
} from './rbac-core.js';

export function makeUserAssignments(platform, api) {
    const React = platform.React;
    const ui = platform.ui;

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

    /* props: users, userRoles (userId -> the Assigned Role text), usersError (why the
       list did not load, or null), roles, channelMap (a Map of channel id to
       name), canManage (Assign and Remove shown), loading, mutate(call) */
    return function UserAssignments({ users, userRoles, usersError, roles, channelMap, canManage, loading, mutate }) {
        const [selectedUserId, setSelectedUserId] = React.useState(null);
        const selectedUser = users.find((u) => String(u.id) === String(selectedUserId)) || null;
        // A user missing from the lookup reads "(unknown)", as in Swing.
        const roleText = (userId) => (userRoles[userId] != null ? userRoles[userId] : UNKNOWN_ROLE_LABEL);

        async function assignRole() {
            if (!selectedUser) { ui.toast(MSG_SELECT_USER_ASSIGN, 'warn'); return; }
            if (roles.length === 0) { ui.toast(MSG_NO_ROLES, 'warn'); return; }
            const username = selectedUser.username;
            const roleId = await pickRole(roles, username);
            if (roleId === null) return;
            const role = roles.find((r) => String(r.id) === String(roleId));
            if (!role) return;
            // The preview's "Current role" is the table's text, "(none)" and "(unknown)" included (as Swing).
            const currentRoleName = roleText(selectedUser.id);
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

        return (
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
                                        <td>{roleText(user.id)}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    )}
                </div>
            </div>
        );
    };
}
