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
 * Task pane = Refresh (settings_Role-Based Access Control/doRefresh →
 * "View Roles") plus Export Roles and Import Roles, shown to the admin role
 * only (the controller answers doExportRoles/doImportRoles from the admin
 * flag; see role-transfer.jsx); the Add/Edit/Delete and Assign/Remove buttons are gated on
 * checkTask(…, 'doSave') → "Manage Roles" (the Config Map Add Row precedent).
 * The assignments table and its Assign and Remove are user-assignments.jsx;
 * this panel loads its data with everything else.
 * When the users list is denied (listing users needs manageUsers, which a
 * View-Roles-only user lacks) the roles table still renders and the
 * assignments area degrades to a hint — same partial panel as Swing.
 */

import {
    IMMEDIATE_NOTICE, ROLE_COLUMNS,
    MSG_CATALOG_NOT_LOADED, MSG_CHANNELS_NOT_LOADED, MSG_SELECT_ROLE_EDIT, MSG_SELECT_ROLE_DELETE,
    MSG_ADMIN_ROLE_CANNOT_DELETE, deleteRoleConfirmText, TITLE_CONFIRM_DELETE, lookUpRoleNames
} from './rbac-core.js';
import {
    TASK_EXPORT_ROLES, TASK_EXPORT_ROLES_TOOLTIP, TASK_IMPORT_ROLES, TASK_IMPORT_ROLES_TOOLTIP
} from './role-transfer-core.js';
import { mapEntries } from './rbac-api.js';
import { makeRoleEditor } from './role-editor.jsx';
import { makeRoleTransfer } from './role-transfer.jsx';
import { makeUserAssignments } from './user-assignments.jsx';

const RBAC_GROUP = 'settings_Role-Based Access Control';

export function registerRolesPanel(platform, api) {
    const React = platform.React;
    const ui = platform.ui;
    const RoleEditor = makeRoleEditor(platform);
    const { startExport, startImport, TransferDialogs } = makeRoleTransfer(platform, api);
    const UserAssignments = makeUserAssignments(platform, api);

    function RolesPanel({ setTasks }) {
        const [roles, setRoles] = React.useState([]);
        const [users, setUsers] = React.useState([]);
        const [usersError, setUsersError] = React.useState(null); // users.list denied/failed
        const [userRoles, setUserRoles] = React.useState({});     // userId -> role name, "(none)" or "(unknown)"
        const [catalog, setCatalog] = React.useState(null);       // Set<string> | null (not loaded)
        const [extGroups, setExtGroups] = React.useState({});     // permission -> publishing plugin
        const [channels, setChannels] = React.useState([]);       // [{id, name}] live, wire order
        const [channelsLoaded, setChannelsLoaded] = React.useState(false); // last fetch succeeded
        const [selectedRoleId, setSelectedRoleId] = React.useState(null);
        const [editor, setEditor] = React.useState(null);         // { role: Role|null } while open
        const [transfer, setTransfer] = React.useState(null);     // export/import dialog value while open
        const [loading, setLoading] = React.useState(true);

        const channelMapRef = React.useRef(null); // the export task reads the channel names, null when not loaded
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
                // A failed fetch keeps the old list. A stale or missing list would hide
                // live channels from the editor (the save keeps them, unseen), so
                // Add/Edit wait for a fresh one.
                if (channelsRes.status === 'fulfilled') {
                    setChannels(mapEntries(channelsRes.value).map(([id, name]) => ({ id, name })));
                    setChannelsLoaded(true);
                } else {
                    setChannelsLoaded(false);
                    ui.toast(`Failed to load channels: ${channelsRes.reason && channelsRes.reason.message || channelsRes.reason}`, 'error');
                }
                if (usersRes.status === 'fulfilled') {
                    // N+1 like Swing: resolve each user's assigned role;
                    // a failed lookup shows "(unknown)", no role "(none)".
                    const list = usersRes.value;
                    const names = await lookUpRoleNames(list, api.getUserRole);
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
            // No Save participation (the panel never calls setSave, so it can't
            // trip the settings dirty tracking). Export and Import Roles are
            // for the admin role only; the controller hides them from anyone else.
            setTasks('Role-Based Access Control Tasks', [
                ui.taskButton('Refresh', 'refresh', () => load(), { task: 'doRefresh', group: RBAC_GROUP }),
                ui.taskButton(TASK_EXPORT_ROLES, 'export', async () => setTransfer(await startExport(channelMapRef.current)),
                    { task: 'doExportRoles', group: RBAC_GROUP, title: TASK_EXPORT_ROLES_TOOLTIP }),
                ui.taskButton(TASK_IMPORT_ROLES, 'import', async () => setTransfer(await startImport()),
                    { task: 'doImportRoles', group: RBAC_GROUP, title: TASK_IMPORT_ROLES_TOOLTIP })
            ]);
        }, [load, setTasks]);

        const canManage = platform.checkTask(RBAC_GROUP, 'doSave');
        const channelMap = React.useMemo(
            () => new Map(channels.map((c) => [c.id, c.name])), [channels]);
        channelMapRef.current = channelsLoaded ? channelMap : null;
        const selectedRole = roles.find((r) => String(r.id) === String(selectedRoleId)) || null;

        const catalogNotLoaded = () => {
            if (!catalog || catalog.size === 0) {
                ui.toast(MSG_CATALOG_NOT_LOADED, 'warn');
                return true;
            }
            return false;
        };

        const channelListNotLoaded = () => {
            if (!channelsLoaded) {
                ui.toast(MSG_CHANNELS_NOT_LOADED, 'warn');
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
            if (catalogNotLoaded() || channelListNotLoaded()) return;
            setEditor({ role: null });
        }

        function editRole(role) {
            const target = role || selectedRole;
            if (!target) { ui.toast(MSG_SELECT_ROLE_EDIT, 'warn'); return; }
            if (catalogNotLoaded() || channelListNotLoaded()) return;
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

                <UserAssignments
                    users={users}
                    userRoles={userRoles}
                    usersError={usersError}
                    roles={roles}
                    channelMap={channelMap}
                    canManage={canManage}
                    loading={loading}
                    mutate={mutate} />

                {editor ? (
                    <RoleEditor
                        role={editor.role}
                        catalog={catalog}
                        extGroups={extGroups}
                        channels={channels}
                        onApply={applyEditor}
                        onCancel={() => setEditor(null)} />
                ) : null}

                <TransferDialogs
                    transfer={transfer}
                    onClose={() => setTransfer(null)}
                    onImported={() => { setTransfer(null); load(); }} />
            </div>
        );
    }

    platform.registerSettingsPanel({ label: 'Role-Based Access Control', component: RolesPanel });
}
