// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

/*
 * Export Roles: a table with a tick box per role (never the admin role), all
 * ticked, and an Export button that asks where to save and writes the server's text as is.
 */

import {
    TITLE_EXPORT_ROLES, EXPORT_PROMPT, EXPORT_CHANNELS_LINE, EXPORT_COLUMNS, EXPORT_FILE_NAME, exportedText,
    exportPermissionsLines, exportChannelsLines
} from './rbac-core.js';
import { makeTransferShell } from './role-transfer-shell.jsx';
import { makeListCell } from './role-table-cells.jsx';

export function makeRoleExportDialog(platform, api) {
    const React = platform.React;
    const ui = platform.ui;
    const Shell = makeTransferShell(React);
    const ListCell = makeListCell(React);

    /* props: roles (normalized, admin role already left out), channelMap (a Map of
       channel id to name, or null when the channel list isn't loaded), onClose() */
    return function RoleExportDialog({ roles, channelMap, onClose }) {
        const [ticked, setTicked] = React.useState(() => new Set(roles.map((r) => r.id)));
        const [busy, setBusy] = React.useState(false);

        const toggle = (id) => setTicked((set) => {
            const next = new Set(set);
            if (next.has(id)) next.delete(id); else next.add(id);
            return next;
        });

        // saveFile must open the browser's save dialog inside this click, so
        // nothing is awaited before it; the server's text is fetched after the
        // user has picked a file.
        async function doExport() {
            const ids = roles.filter((r) => ticked.has(r.id)).map((r) => r.id);
            let fetched = false;
            setBusy(true);
            try {
                await ui.saveFile(EXPORT_FILE_NAME, 'application/xml', async () => {
                    fetched = true;
                    return api.exportRoles(ids);
                });
                if (fetched) {
                    ui.toast(exportedText(ids.length), 'success');
                    onClose();
                    return;
                }
            } catch (e) {
                ui.toast(String(e && e.message || e), 'error');
            }
            setBusy(false); // cancelled or failed: stay open
        }

        return (
            <Shell title={TITLE_EXPORT_ROLES} onCancel={onClose} footer={(
                <>
                    <button className="btn" onClick={onClose}>Cancel</button>
                    <button className="btn btn-primary" disabled={busy || ticked.size === 0}
                        onClick={() => doExport()}>Export</button>
                </>
            )}>
                <div style={{ marginBottom: 8 }}>{EXPORT_PROMPT}</div>
                <div>{EXPORT_CHANNELS_LINE}</div>
                <table className="dt rbac-xfer-table">
                    <thead>
                        <tr>{EXPORT_COLUMNS.map((c, i) => <th key={i}>{c}</th>)}</tr>
                    </thead>
                    <tbody>
                        {roles.map((role) => (
                            <tr key={role.id}>
                                <td>
                                    <input type="checkbox" aria-label={role.name}
                                        checked={ticked.has(role.id)} onChange={() => toggle(role.id)} />
                                </td>
                                <td>{role.name}</td>
                                <td>{role.description}</td>
                                <ListCell lines={exportPermissionsLines(role)} />
                                <ListCell lines={exportChannelsLines(role, channelMap)} />
                            </tr>
                        ))}
                    </tbody>
                </table>
            </Shell>
        );
    };
}
