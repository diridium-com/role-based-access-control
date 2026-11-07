// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

/*
 * Export Roles: a table with a tick box per role (never the admin role), all
 * ticked, a click on a row selects it and fills the permission and channel
 * tables below, and an Export button that asks where to save and writes the
 * server's text as is.
 */

import {
    TITLE_EXPORT_ROLES, EXPORT_PROMPT, EXPORT_CHANNELS_NOTE, EXPORT_CHANNELS_BOLD, EXPORT_COLUMNS,
    EXPORT_FILE_NAME, EXPORT_PERMISSION_COLUMNS, EXPORT_CHANNEL_COLUMNS, EXPORT_CHANNEL_ID_COLUMNS,
    EXPORT_EVERY_CHANNEL, EXPORT_NO_CHANNEL, exportedText, exportPermissionRows, exportChannelRows,
    exportPermissionsCount, exportChannelsCount, permissionsHeading, channelsHeading, sortByColumn, EXPORT_COUNT_COLUMNS
} from './role-transfer-core.js';
import { toggleIn } from './rbac-core.js';
import { makeTransferShell } from './role-transfer-shell.jsx';
import { makeDetailTables } from './role-detail-tables.jsx';

export function makeRoleExportDialog(platform, api) {
    const React = platform.React;
    const ui = platform.ui;
    const Shell = makeTransferShell(React);
    const { useSort, SortHeader, DetailTables } = makeDetailTables(React);

    /* props: roles (normalized, admin role already left out), channelMap (a Map of
       channel id to name, or null when the channel list isn't loaded), onClose() */
    return function RoleExportDialog({ roles, channelMap, onClose }) {
        const [ticked, setTicked] = React.useState(() => new Set(roles.map((r) => r.id)));
        const [busy, setBusy] = React.useState(false);
        const [selectedId, setSelectedId] = React.useState(roles[0].id);
        const [sort, toggleSort] = useSort();

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

        const selected = roles.find((r) => r.id === selectedId) || roles[0];
        const sortKeys = [
            (r) => (ticked.has(r.id) ? 1 : 0), (r) => r.name, (r) => r.description,
            exportPermissionsCount, exportChannelsCount
        ];
        const shownRoles = sortByColumn(roles, sortKeys, sort, EXPORT_COUNT_COLUMNS);

        return (
            <Shell title={TITLE_EXPORT_ROLES} onCancel={onClose} footer={(
                <>
                    <button className="btn" onClick={onClose}>Cancel</button>
                    <button className="btn btn-primary" disabled={busy || ticked.size === 0}
                        onClick={() => doExport()}>Export</button>
                </>
            )}>
                <div style={{ marginBottom: 8 }}>{EXPORT_PROMPT}</div>
                <div className="rbac-xfer-callout">
                    {EXPORT_CHANNELS_NOTE}<strong>{EXPORT_CHANNELS_BOLD}</strong>
                </div>
                <div className="rbac-xfer-roles">
                    <table className="dt rbac-xfer-table">
                        <SortHeader columns={EXPORT_COLUMNS} sort={sort} onSort={toggleSort} />
                        <tbody>
                            {shownRoles.map((role) => (
                                <tr key={role.id} onClick={() => setSelectedId(role.id)}
                                    className={'rbac-xfer-pick' + (role === selected ? ' rbac-xfer-selected' : '')}>
                                    <td>
                                        <input type="checkbox" aria-label={role.name}
                                            checked={ticked.has(role.id)}
                                            onClick={(e) => e.stopPropagation()}
                                            onChange={() => setTicked((set) => toggleIn(set, role.id))} />
                                    </td>
                                    <td>{role.name}</td>
                                    <td>{role.description}</td>
                                    <td>{exportPermissionsCount(role)}</td>
                                    <td>{exportChannelsCount(role)}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
                <DetailTables
                    permissions={{ heading: permissionsHeading(selected.name),
                        columns: EXPORT_PERMISSION_COLUMNS, rows: exportPermissionRows(selected) }}
                    channels={{ heading: channelsHeading(selected.name), columns: EXPORT_CHANNEL_COLUMNS,
                        rows: exportChannelRows(selected, channelMap), idColumns: EXPORT_CHANNEL_ID_COLUMNS,
                        empty: selected.restricted ? EXPORT_NO_CHANNEL : EXPORT_EVERY_CHANNEL }} />
            </Shell>
        );
    };
}
