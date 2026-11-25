// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

/*
 * The admin-only Orphaned Permissions dialog: the permissions roles hold that neither the
 * engine nor any installed plugin registers, with Remove Selected and Remove All. The server
 * lists them, never the engine's own permissions, and checks each removal again. Swing twin:
 * OrphanedPermissionsDialog, with the same texts.
 */

import {
    TASK_ORPHANED_PERMISSIONS, ORPHANED_INTRO, ORPHANED_EMPTY, ORPHANED_COLUMNS,
    orphanedDisabledLine, orphanedConfirmation, toggleIn
} from './rbac-core.js';
import { sortByColumn } from './role-transfer-core.js';
import { makeTransferShell } from './role-transfer-shell.jsx';
import { makeDetailTables } from './role-detail-tables.jsx';

const keyOf = (grant) => `${grant.roleId}\n${grant.permission}`;

export function makeOrphanedPermissions(platform, api) {
    const React = platform.React;
    const ui = platform.ui;
    const Shell = makeTransferShell(React);
    const { useSort, SortHeader } = makeDetailTables(React);

    /* Resolves the list to open the dialog with, or null when it can't be read (the
       server's message was shown). */
    async function startOrphaned() {
        try {
            return await api.getUnregisteredGrants();
        } catch (e) {
            ui.toast(String(e && e.message || e), 'error');
            return null;
        }
    }

    /* props: initial (the list from startOrphaned), onClose(), onRemoved() */
    function OrphanedPermissionsDialog({ initial, onClose, onRemoved }) {
        const [list, setList] = React.useState(initial);
        const [ticked, setTicked] = React.useState(() => new Set());
        const [busy, setBusy] = React.useState(false);
        const [sort, toggleSort] = useSort();

        async function remove(grants) {
            if (grants.length === 0) return;
            const ok = await ui.confirmDialog(TASK_ORPHANED_PERMISSIONS, orphanedConfirmation(grants),
                { danger: true, okLabel: 'Remove' });
            if (!ok) return;
            setBusy(true);
            try {
                await api.removeUnregisteredGrants(grants);
                onRemoved();
                setList(await api.getUnregisteredGrants());
                setTicked(new Set());
            } catch (e) {
                ui.toast(String(e && e.message || e), 'error');
            }
            setBusy(false);
        }

        const picked = list.grants.filter((g) => ticked.has(keyOf(g)));
        const shown = sortByColumn(list.grants, [(g) => g.roleName, (g) => g.permission], sort);
        const disabledLine = orphanedDisabledLine(list.disabledPlugins);

        return (
            <Shell title={TASK_ORPHANED_PERMISSIONS} onCancel={onClose} footer={(
                <>
                    <button className="btn" disabled={busy || picked.length === 0}
                        onClick={() => remove(picked)}>Remove Selected</button>
                    <button className="btn" disabled={busy || list.grants.length === 0}
                        onClick={() => remove(list.grants)}>Remove All</button>
                    <button className="btn btn-primary" onClick={onClose}>Close</button>
                </>
            )}>
                <div style={{ marginBottom: 8 }}>{ORPHANED_INTRO}</div>
                {disabledLine ? <div className="rbac-xfer-callout">{disabledLine}</div> : null}
                {list.grants.length === 0 ? <div style={{ marginTop: 10 }}>{ORPHANED_EMPTY}</div> : (
                    <div className="rbac-xfer-roles">
                        <table className="dt rbac-xfer-table">
                            <SortHeader columns={ORPHANED_COLUMNS} sort={sort} onSort={toggleSort} />
                            <tbody>
                                {shown.map((grant) => (
                                    <tr key={keyOf(grant)}>
                                        <td>
                                            <label style={{ display: 'inline-flex', alignItems: 'center', gap: 6, cursor: 'pointer' }}>
                                                <input type="checkbox" aria-label={`${grant.roleName}: ${grant.permission}`}
                                                    checked={ticked.has(keyOf(grant))}
                                                    onChange={() => setTicked((set) => toggleIn(set, keyOf(grant)))} />
                                                {grant.roleName}
                                            </label>
                                        </td>
                                        <td>{grant.permission}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </Shell>
        );
    }

    return { startOrphaned, OrphanedPermissionsDialog };
}
