// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

/*
 * Export Roles: a tick box per role (never the admin role), all ticked, and an
 * Export button that asks where to save and writes the server's text as is.
 */

import { TITLE_EXPORT_ROLES, EXPORT_PROMPT, EXPORT_FILE_NAME, exportedText } from './rbac-core.js';
import { makeTransferShell } from './role-transfer-shell.jsx';

export function makeRoleExportDialog(platform, api) {
    const React = platform.React;
    const ui = platform.ui;
    const Shell = makeTransferShell(React);

    /* props: roles (normalized, admin role already left out), onClose() */
    return function RoleExportDialog({ roles, onClose }) {
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
                {roles.map((role) => (
                    <label key={role.id} className="rbac-check">
                        <input type="checkbox" checked={ticked.has(role.id)} onChange={() => toggle(role.id)} />
                        {role.name}
                    </label>
                ))}
            </Shell>
        );
    };
}
