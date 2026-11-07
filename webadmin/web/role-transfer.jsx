// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

/*
 * Export Roles and Import Roles on the Roles settings panel: the two task
 * handlers and the dialogs they open. The panel keeps one `transfer` value
 * ({ kind: 'export', roles, channelMap } or { kind: 'import', fileText, initial }) and
 * renders <TransferDialogs> for it. Export reads the roles from the server on
 * each click, as the Swing Administrator does, never the panel's last list.
 */

import { MSG_NO_ROLES_TO_EXPORT, importRefusedText } from './role-transfer-core.js';
import { makeRoleExportDialog } from './role-export-dialog.jsx';
import { makeRoleImportDialog } from './role-import-dialog.jsx';

export function makeRoleTransfer(platform, api) {
    const React = platform.React;
    const ui = platform.ui;
    const ExportDialog = makeRoleExportDialog(platform, api);
    const ImportDialog = makeRoleImportDialog(platform, api);

    /* Resolves the value to open the export dialog with, or null (with a
       message) when the roles can't be read or no role but the admin role
       exists. channelMap is the panel's channel names, or null. */
    async function startExport(channelMap) {
        let roles;
        try {
            roles = await api.getRoles();
        } catch (e) {
            ui.toast(String(e && e.message || e), 'error');
            return null;
        }
        const exportable = roles.filter((r) => !r.isAdmin);
        if (exportable.length === 0) {
            ui.toast(MSG_NO_ROLES_TO_EXPORT, 'info');
            return null;
        }
        return { kind: 'export', roles: exportable, channelMap };
    }

    /* Pick a file and preview it. Resolves the value to open the import dialog
       with, or null (cancelled, unreadable, refused: the reason was shown). */
    async function startImport() {
        let picked;
        try {
            picked = await ui.pickFile('.xml');
        } catch (e) {
            ui.toast(String(e && e.message || e), 'error');
            return null;
        }
        if (!picked) return null;
        try {
            const initial = await api.importRoles(picked.content, {
                dryRun: true, applyChannels: true, matchChannelsByName: false
            });
            if (!initial.importable) {
                ui.toast(importRefusedText(initial.refusal), 'error');
                return null;
            }
            return { kind: 'import', fileText: picked.content, initial };
        } catch (e) {
            ui.toast(String(e && e.message || e), 'error');
            return null;
        }
    }

    /* props: transfer (as above, or null), onClose(), onImported() */
    function TransferDialogs({ transfer, onClose, onImported }) {
        if (!transfer) return null;
        if (transfer.kind === 'export') {
            return <ExportDialog roles={transfer.roles} channelMap={transfer.channelMap} onClose={onClose} />;
        }
        return <ImportDialog fileText={transfer.fileText} initial={transfer.initial}
            onClose={onClose} onImported={onImported} />;
    }

    return { startExport, startImport, TransferDialogs };
}
