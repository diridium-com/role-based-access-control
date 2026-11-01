// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

export function makeImportConflictDialog(platform) {
    const React = platform.React;

    function ImportConflictDialog({ roles, importedRoles, channelMap, onProceed, onCancel }) {
        const [rows, setRows] = React.useState(() => {
            return importedRoles.map((importedRole) => {
                const existing = roles.find((r) => r.name.toLowerCase() === importedRole.name.toLowerCase());
                let status = 'New';
                let action = 'Create';
                let details = `New role will be created with ${importedRole.permissions.size} permission(s).`;

                if (existing) {
                    if (existing.isAdmin) {
                        status = 'Admin (Locked)';
                        action = 'Skip';
                        details = 'Admin role cannot be overwritten.';
                    } else {
                        const dList = [];
                        const exDesc = existing.description || '';
                        const imDesc = importedRole.description || '';
                        if (exDesc !== imDesc) {
                            dList.push(`Description:\n  [-] ${exDesc}\n  [+] ${imDesc}`);
                        }

                        const exPerms = existing.permissions || new Set();
                        const imPerms = importedRole.permissions || new Set();
                        const addedPerms = [...imPerms].filter(p => !exPerms.has(p));
                        const removedPerms = [...exPerms].filter(p => !imPerms.has(p));

                        if (addedPerms.length > 0 || removedPerms.length > 0) {
                            let pText = 'Permissions:\n';
                            addedPerms.forEach(p => pText += `  [+] (Added) ${p}\n`);
                            removedPerms.forEach(p => pText += `  [-] (Removed) ${p}\n`);
                            dList.push(pText.trimEnd());
                        }

                        const exCh = existing.channelIds || new Set();
                        const imCh = importedRole.channelIds || new Set();
                        const addedCh = [...imCh].filter(c => !exCh.has(c));
                        const removedCh = [...exCh].filter(c => !imCh.has(c));

                        if (addedCh.length > 0 || removedCh.length > 0) {
                            let cText = 'Channel Restrictions:\n';
                            addedCh.forEach(c => cText += `  [+] (Added Channel) ${channelMap.get(c) || c}\n`);
                            removedCh.forEach(c => cText += `  [-] (Removed Channel) ${channelMap.get(c) || c}\n`);
                            dList.push(cText.trimEnd());
                        }

                        if (dList.length > 0) {
                            status = 'Conflict Detected';
                            action = 'Overwrite All';
                            details = dList.join('\n\n');
                        } else {
                            status = 'No Conflict';
                            action = 'Skip';
                            details = 'No differences found (role is identical).';
                        }
                    }
                }

                return {
                    importedRole,
                    existing,
                    import: status !== 'Admin (Locked)',
                    status,
                    action,
                    details
                };
            });
        });

        const [selectedIndex, setSelectedIndex] = React.useState(0);

        return (
            <div style={{
                position: 'fixed',
                top: 0,
                left: 0,
                width: '100vw',
                height: '100vh',
                backgroundColor: 'rgba(0, 0, 0, 0.6)',
                zIndex: 99999,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center'
            }}>
                <div className="panel rbac-editor" style={{ width: '800px', height: '620px', zIndex: 100000, boxShadow: '0 8px 24px rgba(0,0,0,0.3)' }}>
                    <div className="panel-header">Import Roles & Detailed Conflict Resolution</div>
                    <div className="panel-body" style={{ padding: 12, gap: 12 }}>
                        <div style={{ fontSize: 12, color: 'var(--text-dim, #888)' }}>
                            Review imported roles, detected differences, and choose resolution actions:
                        </div>
                        <div style={{ flex: 1, border: '1px solid var(--line, #8884)', borderRadius: 4, overflow: 'auto' }}>
                            <table className="dt" style={{ width: '100%', margin: 0 }}>
                                <thead>
                                    <tr>
                                        <th style={{ width: 60, textAlign: 'center' }}>Import</th>
                                        <th>Role Name</th>
                                        <th>Conflict Status</th>
                                        <th style={{ width: 200 }}>Action on Conflict</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {rows.map((row, idx) => (
                                        <tr key={idx}
                                            className={idx === selectedIndex ? 'selected' : ''}
                                            style={{ cursor: 'pointer' }}
                                            onClick={() => setSelectedIndex(idx)}>
                                            <td style={{ textAlign: 'center' }} onClick={(e) => e.stopPropagation()}>
                                                <input type="checkbox"
                                                    checked={row.import}
                                                    disabled={row.status === 'Admin (Locked)'}
                                                    onChange={(e) => {
                                                        const val = e.target.checked;
                                                        setRows(r => r.map((it, i) => i === idx ? { ...it, import: val } : it));
                                                    }} />
                                            </td>
                                            <td>{row.importedRole.name}</td>
                                            <td>
                                                <span style={{
                                                    fontWeight: 'bold',
                                                    color: row.status === 'Conflict Detected' ? '#d9534f' : row.status === 'No Conflict' ? '#5cb85c' : 'inherit'
                                                }}>
                                                    {row.status}
                                                </span>
                                            </td>
                                            <td onClick={(e) => e.stopPropagation()}>
                                                <select value={row.action}
                                                    disabled={row.status === 'Admin (Locked)'}
                                                    style={{ width: '100%', padding: '2px 4px' }}
                                                    onChange={(e) => {
                                                        const val = e.target.value;
                                                        setRows(r => r.map((it, i) => i === idx ? { ...it, action: val } : it));
                                                    }}>
                                                    <option value="Create">Create</option>
                                                    <option value="Overwrite All">Overwrite All</option>
                                                    <option value="Overwrite Permissions Only">Overwrite Permissions Only</option>
                                                    <option value="Skip">Skip</option>
                                                </select>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                        <div style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
                            <div style={{ fontSize: 11, fontWeight: 'bold', marginBottom: 4 }}>Detailed Changes Preview:</div>
                            <pre style={{
                                flex: 1, margin: 0, padding: 8, fontSize: 11, fontFamily: 'monospace',
                                background: 'var(--bg-alt, #f9f9f9)', border: '1px solid var(--line, #8884)',
                                borderRadius: 4, overflow: 'auto', whiteSpace: 'pre-wrap'
                            }}>
                                {rows[selectedIndex] ? rows[selectedIndex].details : 'Select a role above to view details.'}
                            </pre>
                        </div>
                    </div>
                    <div className="rbac-editor-foot">
                        <button className="btn" onClick={onCancel}>Cancel</button>
                        <button className="btn btn-primary" onClick={() => onProceed(rows)}>Proceed Import</button>
                    </div>
                </div>
            </div>
        );
    }

    return ImportConflictDialog;
}

export function makeExportRoleDialog(platform) {
    const React = platform.React;

    function ExportRoleDialog({ roles, onExport, onCancel }) {
        const [selectedIds, setSelectedIds] = React.useState(() => {
            return new Set(roles.map(r => r.id));
        });
        const [includeChannels, setIncludeChannels] = React.useState(true);

        const toggleAll = (checked) => {
            if (checked) {
                setSelectedIds(new Set(roles.map(r => r.id)));
            } else {
                setSelectedIds(new Set());
            }
        };

        const toggleOne = (id) => {
            const next = new Set(selectedIds);
            if (next.has(id)) {
                next.delete(id);
            } else {
                next.add(id);
            }
            setSelectedIds(next);
        };

        const allSelected = roles.length > 0 && selectedIds.size === roles.length;

        return (
            <div style={{
                position: 'fixed',
                top: 0,
                left: 0,
                width: '100vw',
                height: '100vh',
                backgroundColor: 'rgba(0, 0, 0, 0.6)',
                zIndex: 99999,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center'
            }}>
                <div className="panel rbac-editor" style={{ width: '600px', height: '530px', zIndex: 100000, boxShadow: '0 8px 24px rgba(0,0,0,0.3)' }}>
                    <div className="panel-header">Export Roles to XML</div>
                    <div className="panel-body" style={{ padding: 12, gap: 12, display: 'flex', flexDirection: 'column' }}>
                        <div style={{ flex: 1, border: '1px solid var(--line, #8884)', borderRadius: 4, overflow: 'auto' }}>
                            <table className="dt" style={{ width: '100%', margin: 0 }}>
                                <thead>
                                    <tr>
                                        <th style={{ width: 60, textAlign: 'center' }}>
                                            <input type="checkbox" checked={allSelected} onChange={(e) => toggleAll(e.target.checked)} />
                                        </th>
                                        <th style={{ width: 60 }}>ID</th>
                                        <th>Role Name</th>
                                        <th>Description</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {roles.map((role) => {
                                        const isChecked = selectedIds.has(role.id);
                                        return (
                                            <tr key={role.id} style={{ cursor: 'pointer' }} onClick={() => toggleOne(role.id)}>
                                                <td style={{ textAlign: 'center' }} onClick={(e) => e.stopPropagation()}>
                                                    <input type="checkbox" checked={isChecked} onChange={() => toggleOne(role.id)} />
                                                </td>
                                                <td>{role.id}</td>
                                                <td>{role.name}</td>
                                                <td>{role.description}</td>
                                            </tr>
                                        );
                                    })}
                                </tbody>
                            </table>
                        </div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, paddingTop: 4 }}>
                            <input
                                type="checkbox"
                                id="include-channels-checkbox"
                                checked={includeChannels}
                                onChange={(e) => setIncludeChannels(e.target.checked)}
                            />
                            <label htmlFor="include-channels-checkbox" style={{ cursor: 'pointer' }}>
                                Include channel restrictions in export
                            </label>
                        </div>
                    </div>
                    <div className="rbac-editor-foot">
                        <button className="btn" onClick={onCancel}>Cancel</button>
                        <button
                            className="btn btn-primary"
                            disabled={selectedIds.size === 0}
                            onClick={() => {
                                const rolesToExport = roles.filter(r => selectedIds.has(r.id));
                                onExport(rolesToExport, includeChannels);
                            }}>
                            Export Selected ({selectedIds.size})
                        </button>
                    </div>
                </div>
            </div>
        );
    }

    return ExportRoleDialog;
}