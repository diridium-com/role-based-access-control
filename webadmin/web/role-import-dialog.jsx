// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

/*
 * Import Roles: the preview of a picked file. Two tick boxes (channel
 * restrictions, then matching channels by name) that preview the file again
 * whenever they change, a table with a tick box per New or Overwrite row, and
 * an Import button that applies the ticked rows with the preview's plan token.
 * Any failed apply shows the server's message and previews again, so the table
 * shows what the roles are now.
 */

import {
    TITLE_IMPORT_ROLES, IMPORT_APPLY_CHANNELS, IMPORT_MATCH_BY_NAME, IMPORT_COLUMNS,
    importRefusedText, importSourceText, importedText, actionLabel, canTick, detailsText,
    mergeTicks, pickedIndexes, nameMatchSection
} from './rbac-core.js';
import { makeTransferShell } from './role-transfer-shell.jsx';

const errorText = (e) => String(e && e.message || e);

export function makeRoleImportDialog(platform, api) {
    const React = platform.React;
    const ui = platform.ui;
    const Shell = makeTransferShell(React);

    /* props: fileText (the picked file), initial (the first preview, importable),
       onClose(), onImported() (after a successful apply) */
    return function RoleImportDialog({ fileText, initial, onClose, onImported }) {
        const [result, setResult] = React.useState(initial);
        const [applyChannels, setApplyChannels] = React.useState(true);
        const [matchByName, setMatchByName] = React.useState(false);
        const [ticks, setTicks] = React.useState(() => mergeTicks([], new Set(), initial.rows));
        const [busy, setBusy] = React.useState(false);
        const latest = React.useRef(0);

        // Preview the file again with these settings. A refused file closes the
        // dialog; a failed call keeps what is shown and says why.
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
            } catch (e) {
                if (mine === latest.current) ui.toast(errorText(e), 'error');
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

        async function apply() {
            const pick = pickedIndexes(result.rows, ticks);
            setBusy(true);
            try {
                await api.importRoles(fileText, {
                    dryRun: false, applyChannels, matchChannelsByName: matchByName,
                    pick, planToken: result.planToken
                });
            } catch (e) {
                ui.toast(errorText(e), 'error');
                await preview(applyChannels, matchByName);
                return;
            }
            ui.toast(importedText(pick.length), 'success');
            onImported();
        }

        const toggleTick = (index) => setTicks((set) => {
            const next = new Set(set);
            if (next.has(index)) next.delete(index); else next.add(index);
            return next;
        });

        const matches = nameMatchSection(applyChannels, matchByName, result.channelNameMatches);
        const nothingPicked = pickedIndexes(result.rows, ticks).length === 0;

        return (
            <Shell title={TITLE_IMPORT_ROLES} onCancel={onClose} footer={(
                <>
                    <button className="btn" onClick={onClose}>Cancel</button>
                    <button className="btn btn-primary" disabled={busy || nothingPicked}
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
                {matches ? (
                    <div style={{ marginTop: 8 }}>
                        <div>{matches.heading}</div>
                        <div className="rbac-xfer-list">
                            {matches.names.map((name, i) => <div key={i}>{name}</div>)}
                        </div>
                        {matches.hint ? <div>{matches.hint}</div> : null}
                    </div>
                ) : null}
                <table className="dt rbac-xfer-table">
                    <thead>
                        <tr>{IMPORT_COLUMNS.map((c, i) => <th key={i} style={i === 0 ? { width: 30 } : null}>{c}</th>)}</tr>
                    </thead>
                    <tbody>
                        {result.rows.map((row) => (
                            <tr key={row.index}>
                                <td>
                                    <input type="checkbox" aria-label={'Import ' + row.name}
                                        checked={canTick(row) && ticks.has(row.index)}
                                        disabled={busy || !canTick(row)}
                                        onChange={() => toggleTick(row.index)} />
                                </td>
                                <td>{row.name}</td>
                                <td>{actionLabel(row.action)}</td>
                                <td>{detailsText(row)}</td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </Shell>
        );
    };
}
