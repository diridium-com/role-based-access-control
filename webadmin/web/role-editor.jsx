// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

/*
 * Add/Edit Role overlay — the web port of RoleEditorDialog.
 *
 * Name/Description over two tabs: Permissions (Select All / Deselect All /
 * Read-Only presets, grouped 2-column checkboxes from the fetched catalog,
 * the manageExtensions blast-radius tooltip) and Channel Restrictions
 * (All/Specific radios; live channels as "name (id)" checkboxes enabled only
 * for Specific; deleted-channel orphans listed with a per-row Purge checkbox,
 * default unchecked = keep the reference on Apply).
 *
 * Apply runs Swing's exact validation chain: name required; refusal to save
 * an existing role with no permission catalog (a silent wipe otherwise);
 * missing-base-permissions Yes/No warn; empty-whitelist flip Yes/No guard.
 * Orphan permissions (grants not in the fetched catalog) render no checkbox
 * and are silently preserved on Apply, mirroring the keep-by-default policy
 * for deleted-channel references.
 *
 * The admin role (identified by its isAdmin flag, not its name) locks
 * everything except Description; Apply re-sends its stored permissions and
 * channel ids unchanged. Like the Swing dialog's built Role, isAdmin is NOT
 * set on the payload (false on the wire) — the server preserves the stored
 * flag and AdminRoleGuard enforces the real protections.
 */

import {
    groupPermissions, orphanPermissionsOf, orphanChannelIdsOf, missingBase,
    READ_ONLY_PERMISSIONS, MANAGE_EXTENSIONS_WARNING, READ_ONLY_TOOLTIP,
    TITLE_ADD_ROLE, TITLE_EDIT_ROLE, MSG_NAME_REQUIRED, TITLE_VALIDATION_ERROR,
    MSG_CATALOG_EMPTY_EDIT, TITLE_PERMISSIONS_UNAVAILABLE,
    missingBaseWarningText, TITLE_MISSING_BASE_PERMISSIONS,
    MSG_EMPTY_WHITELIST_FLIP, TITLE_NO_CHANNEL_RESTRICTIONS,
    ORPHAN_CHANNELS_TITLE, ORPHAN_CHANNELS_HINT,
    orphanChannelRowLabel
} from './rbac-core.js';

/* Own classes, NOT host Tailwind utilities: the host generates utilities from
   ITS source scan, so a class no host file uses simply does not exist in
   app.css — and this plugin's sources are never scanned (the community-store
   cs-overlay precedent). Host COMPONENT classes (.panel, .btn, .tabs, .hint)
   are fine. */
const EDITOR_CSS = `
.rbac-overlay {
    position: fixed;
    top: 0; right: 0; bottom: 0; left: 0;
    display: flex;
    align-items: center;
    justify-content: center;
    background: rgba(0, 0, 0, 0.45);
    /* Below the host's .modal-overlay (100): the Apply confirms and validation
       alerts (ui.modal / ui.confirmDialog) must stack above this editor. */
    z-index: 95;
}
.rbac-editor {
    width: 720px;
    max-width: 92vw;
    height: 600px;
    max-height: 88vh;
    display: flex;
    flex-direction: column;
}
.rbac-editor > .panel-body {
    flex: 1;
    min-height: 0;
    overflow: auto;
    display: flex;
    flex-direction: column;
}
.rbac-form-row { flex: none; display: flex; align-items: center; gap: 8px; margin-bottom: 8px; }
.rbac-form-row > label { flex: none; width: 90px; margin: 0; }
.rbac-form-row > input { flex: 1; }
/* flex:none — the panel-body is a height-constrained flex column and the host's
   .tabs has overflow-y:hidden, so without it the overflowing permission grid
   squashes the tab strip to zero height (tabs invisible + unclickable). */
.rbac-editor .tabs { flex: none; margin: 4px 0 10px; }
.rbac-preset-row { display: flex; align-items: center; gap: 8px; margin-bottom: 10px; }
.rbac-perm-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; align-items: start; }
.rbac-fieldset { border: 1px solid var(--line, #8884); border-radius: 4px; padding: 4px 10px 8px; margin: 0; min-width: 0; }
.rbac-fieldset legend { font-size: 11px; font-weight: 600; padding: 0 4px; }
.rbac-check { display: flex; align-items: center; gap: 6px; font-size: 12px; margin: 3px 0; cursor: pointer; }
.rbac-check input { margin: 0; flex: none; }
.rbac-orphan-label { font-family: monospace; font-size: 11px; }
.rbac-channel-list {
    display: flex;
    flex-direction: column;
    margin-top: 8px;
    border: 1px solid var(--line, #8884);
    border-radius: 4px;
}
.rbac-channel-list .rbac-check {
    margin: 0;
    padding: 7px 10px;
    border-bottom: 1px solid color-mix(in srgb, var(--line, #888) 45%, transparent);
}
.rbac-channel-list .rbac-check:last-child { border-bottom: 0; }
.rbac-channel-list .rbac-check:hover { background: color-mix(in srgb, var(--accent, #46f) 7%, transparent); }
.rbac-channel-list .rbac-check:has(input:disabled) { opacity: 0.55; cursor: default; }
.rbac-ch-id { font-family: monospace; font-size: 11px; color: var(--text-dim, #888); }
.rbac-editor-foot {
    flex: none;
    display: flex;
    justify-content: flex-end;
    gap: 8px;
    padding: 10px 14px;
    border-top: 1px solid var(--line, #8884);
}
`;

export function makeRoleEditor(platform) {
    const React = platform.React;
    const ui = platform.ui;

    /* Validation alert (Swing's error JOptionPane): titled, OK-only, \n kept. */
    function alertDialog(title, message) {
        return new Promise((resolve) => {
            ui.modal({
                title,
                body: ui.h('div', { style: 'white-space: pre-line' }, message),
                onClose: () => resolve(),
                buttons: [{ label: 'OK', primary: true, onClick: () => resolve() }]
            });
        });
    }

    /* Yes/No confirm (Swing's YES_NO_OPTION), \n kept via pre-line — the host
       migrationDialog precedent. */
    function confirmYesNo(title, message) {
        return new Promise((resolve) => {
            ui.modal({
                title,
                body: ui.h('div', { style: 'white-space: pre-line' }, message),
                onClose: () => resolve(false),
                buttons: [
                    { label: 'No', onClick: () => resolve(false) },
                    { label: 'Yes', primary: true, onClick: () => resolve(true) }
                ]
            });
        });
    }

    /* props: role (normalized Role or null when adding), catalog (Set<string>
       or null), extGroups (permission → publishing plugin, for per-plugin
       headers), channels ([{id, name}] live, wire order), onApply(built),
       onCancel(). Apply closes via onApply like Swing: validation passes →
       the dialog is done; the panel commits and surfaces errors. */
    function RoleEditor({ role, catalog, extGroups, channels, onApply, onCancel }) {
        const isAdmin = !!(role && role.isAdmin);
        const catalogEmpty = !catalog || catalog.size === 0;
        const groups = React.useMemo(() => groupPermissions(catalog || [], extGroups), [catalog, extGroups]);
        const liveIds = React.useMemo(() => new Set(channels.map((c) => c.id)), [channels]);
        // Grants with no checkbox (not in the fetched catalog) — preserved on Apply.
        const orphanPerms = React.useMemo(() => orphanPermissionsOf(role, catalog || []), [role, catalog]);
        const orphanChannels = React.useMemo(() => orphanChannelIdsOf(role, liveIds), [role, liveIds]);

        const [name, setName] = React.useState(role ? role.name : '');
        const [description, setDescription] = React.useState(role ? role.description : '');
        const [selected, setSelected] = React.useState(() => new Set(
            role ? [...role.permissions].filter((p) => catalog && catalog.has(p)) : []));
        const [mode, setMode] = React.useState(
            role && role.channelIds.size > 0 ? 'specific' : 'all');
        const [checkedChannels, setCheckedChannels] = React.useState(() => new Set(
            role ? [...role.channelIds].filter((id) => liveIds.has(id)) : []));
        const [purged, setPurged] = React.useState(() => new Set());
        const [tab, setTab] = React.useState('permissions');

        const channelsEnabled = mode === 'specific' && !isAdmin;

        // Escape cancels (Swing dialog parity) — unless a host modal (confirm/
        // alert) is stacked on top, which owns the key.
        React.useEffect(() => {
            const onKey = (e) => {
                if (e.key === 'Escape' && !document.querySelector('.modal-overlay')) onCancel();
            };
            document.addEventListener('keydown', onKey);
            return () => document.removeEventListener('keydown', onKey);
        }, [onCancel]);

        const toggleIn = (set, value) => {
            const next = new Set(set);
            if (next.has(value)) next.delete(value); else next.add(value);
            return next;
        };

        async function apply() {
            const trimmedName = name.trim();
            if (!trimmedName) {
                await alertDialog(TITLE_VALIDATION_ERROR, MSG_NAME_REQUIRED);
                return;
            }

            // Refuse to save an existing role with no permission catalog: zero
            // checkboxes rendered means Apply would persist an empty set (a
            // silent wipe). Backstop behind the panel's own guard.
            if (catalogEmpty && role) {
                await alertDialog(TITLE_PERMISSIONS_UNAVAILABLE, MSG_CATALOG_EMPTY_EDIT);
                return;
            }

            // Checked permissions + catalog-gap grants preserved by default.
            const selectedPerms = new Set(selected);
            for (const perm of orphanPerms) selectedPerms.add(perm);

            const missing = missingBase(selectedPerms);
            if (missing.length > 0) {
                if (!await confirmYesNo(TITLE_MISSING_BASE_PERMISSIONS, missingBaseWarningText(missing))) {
                    return;
                }
            }

            const selectedChannels = new Set();
            if (mode === 'specific') {
                for (const id of checkedChannels) selectedChannels.add(id);
                // Keep references to deleted channels unless Purge was checked.
                for (const id of orphanChannels) {
                    if (!purged.has(id)) selectedChannels.add(id);
                }
                // Flip guard: "Specific Channels" with an empty set means
                // unrestricted (all channels), not "no access".
                if (selectedChannels.size === 0) {
                    if (!await confirmYesNo(TITLE_NO_CHANNEL_RESTRICTIONS, MSG_EMPTY_WHITELIST_FLIP)) {
                        return;
                    }
                }
            }

            onApply({
                id: role ? role.id : null,
                name: trimmedName,
                description: description.trim(),
                // Admin role: permission/channel controls are locked, so re-send
                // the stored values unchanged — only the description can differ.
                permissions: isAdmin ? new Set(role.permissions) : selectedPerms,
                channelIds: isAdmin ? new Set(role.channelIds) : selectedChannels
            });
        }

        return (
            <div className="rbac-overlay">
                <style>{EDITOR_CSS}</style>
                <div className="panel rbac-editor">
                    <div className="panel-header">{role ? TITLE_EDIT_ROLE : TITLE_ADD_ROLE}</div>
                    <div className="panel-body">
                        <div className="rbac-form-row">
                            <label>Name:</label>
                            <input type="text" value={name} disabled={isAdmin}
                                onChange={(e) => setName(e.target.value)} />
                        </div>
                        <div className="rbac-form-row">
                            <label>Description:</label>
                            <input type="text" value={description}
                                onChange={(e) => setDescription(e.target.value)} />
                        </div>

                        <div className="tabs">
                            <button className={'tab' + (tab === 'permissions' ? ' active' : '')}
                                onClick={() => setTab('permissions')}>Permissions</button>
                            <button className={'tab' + (tab === 'channels' ? ' active' : '')}
                                onClick={() => setTab('channels')}>Channel Restrictions</button>
                        </div>

                        {tab === 'permissions' ? (
                            <div>
                                <div className="rbac-preset-row">
                                    <button className="btn" disabled={isAdmin}
                                        onClick={() => setSelected(new Set(catalog || []))}>Select All</button>
                                    <button className="btn" disabled={isAdmin}
                                        onClick={() => setSelected(new Set())}>Deselect All</button>
                                    <button className="btn" disabled={isAdmin} title={READ_ONLY_TOOLTIP}
                                        onClick={() => setSelected(new Set(
                                            READ_ONLY_PERMISSIONS.filter((p) => catalog && catalog.has(p))))}>
                                        Read-Only</button>
                                </div>
                                <div className="rbac-perm-grid">
                                    {groups.map((group) => (
                                        <fieldset key={group.name} className="rbac-fieldset">
                                            <legend>{group.name}</legend>
                                            {group.permissions.map((perm) => (
                                                <label key={perm} className="rbac-check"
                                                    title={perm === 'manageExtensions' ? MANAGE_EXTENSIONS_WARNING : null}>
                                                    <input type="checkbox" checked={selected.has(perm)} disabled={isAdmin}
                                                        onChange={() => setSelected((s) => toggleIn(s, perm))} />
                                                    {perm}
                                                </label>
                                            ))}
                                        </fieldset>
                                    ))}
                                </div>
                            </div>
                        ) : (
                            <div>
                                <div className="rbac-preset-row">
                                    <label className="rbac-check">
                                        <input type="radio" name="rbac-channel-mode" checked={mode === 'all'}
                                            disabled={isAdmin} onChange={() => setMode('all')} />
                                        All Channels
                                    </label>
                                    <label className="rbac-check">
                                        <input type="radio" name="rbac-channel-mode" checked={mode === 'specific'}
                                            disabled={isAdmin} onChange={() => setMode('specific')} />
                                        Specific Channels
                                    </label>
                                </div>
                                {orphanChannels.length > 0 ? (
                                    <fieldset className="rbac-fieldset">
                                        <legend>{ORPHAN_CHANNELS_TITLE}</legend>
                                        <div className="hint">{ORPHAN_CHANNELS_HINT}</div>
                                        {orphanChannels.map((id) => (
                                            <label key={id} className="rbac-check">
                                                <input type="checkbox" checked={purged.has(id)} disabled={!channelsEnabled}
                                                    onChange={() => setPurged((s) => toggleIn(s, id))} />
                                                Purge
                                                <span className="rbac-orphan-label">{orphanChannelRowLabel(id)}</span>
                                            </label>
                                        ))}
                                    </fieldset>
                                ) : null}
                                <div className="rbac-channel-list">
                                    {channels.map((channel) => (
                                        <label key={channel.id} className="rbac-check">
                                            <input type="checkbox" checked={checkedChannels.has(channel.id)}
                                                disabled={!channelsEnabled}
                                                onChange={() => setCheckedChannels((s) => toggleIn(s, channel.id))} />
                                            <span>{channel.name}</span>
                                            <span className="rbac-ch-id">{channel.id}</span>
                                        </label>
                                    ))}
                                    {channels.length === 0 ? (
                                        <div className="hint">No channels</div>
                                    ) : null}
                                </div>
                            </div>
                        )}
                    </div>
                    <div className="rbac-editor-foot">
                        <button className="btn" onClick={onCancel}>Cancel</button>
                        <button className="btn btn-primary" onClick={() => apply()}>Apply</button>
                    </div>
                </div>
            </div>
        );
    }

    return RoleEditor;
}
