// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

/*
 * Import Roles: the preview of a picked file. Two tick boxes (channel
 * restrictions, then matching channels by name) that preview the file again
 * whenever they change, a roles table with a tick box per New or Overwrite row
 * (a click on a row selects it), the selected role's permissions and channels
 * in two tables below it, and an Import button that applies the ticked rows
 * with the preview's plan token. Any failed apply shows the server's message
 * and previews again, so the tables show what the roles are now. The tables,
 * the "not applied" line and the name-match hint are the last successful
 * preview's; after a failed preview Import stays disabled until one succeeds.
 * While a preview or an apply runs, Cancel and Escape do nothing.
 */

import {
    TITLE_IMPORT_ROLES, IMPORT_APPLY_CHANNELS, IMPORT_MATCH_BY_NAME, IMPORT_COLUMNS,
    PERMISSION_COLUMNS, CHANNEL_COLUMNS, CHANNEL_ID_COLUMNS, PERMISSIONS_LEGEND, CHANNELS_LEGEND, CHANNELS_NOT_APPLIED,
    importRefusedText, importSourceText, importedText, actionLabel, canTick, notesText,
    mergeTicks, pickedIndexes, nameMatchHint, sortByColumn, IMPORT_COUNT_COLUMNS, permissionsCountText, channelsCountText,
    permissionsHeading, channelsHeading, permissionRows, channelRows, everyChannelText
} from './role-transfer-core.js';
import { toggleIn } from './rbac-core.js';
import { makeTransferShell } from './role-transfer-shell.jsx';
import { makeDetailTables } from './role-detail-tables.jsx';

const errorText = (e) => String(e && e.message || e);

export function makeRoleImportDialog(platform, api) {
    const React = platform.React;
    const ui = platform.ui;
    const Shell = makeTransferShell(React);
    const { useSort, SortHeader, DetailTables } = makeDetailTables(React);

    /* props: fileText (the picked file), initial (the first preview, importable),
       onClose(), onImported() (after a successful apply) */
    return function RoleImportDialog({ fileText, initial, onClose, onImported }) {
        const [result, setResult] = React.useState(initial);
        const [applyChannels, setApplyChannels] = React.useState(initial.applyChannels);
        const [matchByName, setMatchByName] = React.useState(initial.matchChannelsByName);
        const [ticks, setTicks] = React.useState(() => mergeTicks([], new Set(), initial.rows));
        const [busy, setBusy] = React.useState(false);
        const [previewFailed, setPreviewFailed] = React.useState(false);
        const [selectedIndex, setSelectedIndex] = React.useState(initial.rows.length ? initial.rows[0].index : -1);
        const [sort, toggleSort] = useSort();
        const latest = React.useRef(0);

        // Preview the file again with these settings. A refused file closes the
        // dialog; a failed call keeps what is shown, says why, and disables
        // Import until a preview succeeds.
        async function preview(nextApply, nextMatch) {
            const mine = ++latest.current;
            setBusy(true);
            try {
                const next = await api.importRoles(fileText, {
                    dryRun: true, applyChannels: nextApply, matchChannelsByName: nextMatch
                });
                if (mine !== latest.current) return;
                if (!next.importable) {
                    ui.toast(importRefusedText(next.refusal), 'error');
                    onClose();
                    return;
                }
                setTicks((before) => mergeTicks(result.rows, before, next.rows));
                setResult(next);
                setPreviewFailed(false);
            } catch (e) {
                if (mine === latest.current) {
                    setPreviewFailed(true);
                    ui.toast(errorText(e), 'error');
                }
            } finally {
                if (mine === latest.current) setBusy(false);
            }
        }

        function changeApplyChannels(on) {
            const nextMatch = on && matchByName;
            setApplyChannels(on);
            setMatchByName(nextMatch);
            preview(on, nextMatch);
        }

        function changeMatchByName(on) {
            setMatchByName(on);
            preview(applyChannels, on);
        }

        // Apply with the settings of the preview shown, which its plan token covers.
        async function apply() {
            const pick = pickedIndexes(result.rows, ticks);
            setBusy(true);
            try {
                await api.importRoles(fileText, {
                    dryRun: false, applyChannels: result.applyChannels, matchChannelsByName: result.matchChannelsByName,
                    pick, planToken: result.planToken
                });
            } catch (e) {
                ui.toast(errorText(e), 'error');
                await preview(result.applyChannels, result.matchChannelsByName);
                return;
            }
            ui.toast(importedText(pick.length), 'success');
            onImported();
        }

        // The selected role: kept across a preview while a row with its index exists.
        const selected = result.rows.find((r) => r.index === selectedIndex) || result.rows[0];
        const sortKeys = [
            (r) => (ticks.has(r.index) ? 1 : 0), (r) => r.name, (r) => actionLabel(r.action),
            (r) => r.descriptionNow, (r) => r.descriptionAfter, permissionsCountText, channelsCountText, notesText
        ];
        const shownRows = sortByColumn(result.rows, sortKeys, sort, IMPORT_COUNT_COLUMNS);

        const hint = nameMatchHint(result.channelNameMatches.length, result.applyChannels, result.matchChannelsByName);
        const nothingPicked = pickedIndexes(result.rows, ticks).length === 0;

        return (
            <Shell title={TITLE_IMPORT_ROLES} onCancel={onClose} closable={!busy} footer={(
                <>
                    <button className="btn" disabled={busy} onClick={onClose}>Cancel</button>
                    <button className="btn btn-primary" disabled={busy || nothingPicked || previewFailed}
                        onClick={() => apply()}>Import</button>
                </>
            )}>
                <div style={{ marginBottom: 8 }}>
                    {importSourceText(result.sourceRbacVersion, result.sourceEngineVersion)}
                </div>
                <label className="rbac-check">
                    <input type="checkbox" checked={applyChannels} disabled={busy}
                        onChange={(e) => changeApplyChannels(e.target.checked)} />
                    {IMPORT_APPLY_CHANNELS}
                </label>
                <label className="rbac-check rbac-xfer-indent">
                    <input type="checkbox" checked={matchByName} disabled={busy || !applyChannels}
                        onChange={(e) => changeMatchByName(e.target.checked)} />
                    {IMPORT_MATCH_BY_NAME}
                </label>
                {hint ? <div style={{ marginTop: 8 }}>{hint}</div> : null}
                <div className="rbac-xfer-roles">
                    <table className="dt rbac-xfer-table">
                        <SortHeader columns={IMPORT_COLUMNS} sort={sort} onSort={toggleSort} />
                        <tbody>
                            {shownRows.map((row) => (
                                <tr key={row.index} onClick={() => setSelectedIndex(row.index)}
                                    className={'rbac-xfer-pick' + (row === selected ? ' rbac-xfer-selected' : '')}>
                                    <td>
                                        <input type="checkbox" aria-label={'Import ' + row.name}
                                            checked={canTick(row) && ticks.has(row.index)}
                                            disabled={busy || !canTick(row)}
                                            onClick={(e) => e.stopPropagation()}
                                            onChange={() => setTicks((set) => toggleIn(set, row.index))} />
                                    </td>
                                    <td>{row.name}</td>
                                    <td>{actionLabel(row.action)}</td>
                                    <td>{row.descriptionNow}</td>
                                    <td>{row.descriptionAfter}</td>
                                    <td>{permissionsCountText(row)}</td>
                                    <td>{channelsCountText(row)}</td>
                                    <td className="rbac-xfer-notes">{notesText(row)}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
                {selected ? (
                    <DetailTables
                        permissions={{ heading: permissionsHeading(selected.name),
                            columns: PERMISSION_COLUMNS, rows: permissionRows(selected), legend: PERMISSIONS_LEGEND }}
                        channels={{ heading: channelsHeading(selected.name), columns: CHANNEL_COLUMNS,
                            rows: channelRows(selected), idColumns: CHANNEL_ID_COLUMNS,
                            legend: CHANNELS_LEGEND, notice: everyChannelText(selected),
                            notApplied: result.applyChannels ? null : CHANNELS_NOT_APPLIED }} />
                ) : null}
            </Shell>
        );
    };
}
