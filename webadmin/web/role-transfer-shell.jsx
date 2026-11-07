// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

/*
 * The Export Roles and Import Roles dialogs in the overlay shell
 * (overlay-shell.jsx), with the rules of their tables, notes and callout.
 *
 * Own classes, not host Tailwind utilities (see the note in overlay-shell.jsx).
 */

import { makeOverlayShell } from './overlay-shell.jsx';

const TRANSFER_CSS = `
.rbac-xfer { width: min(1280px, 95vw); }
.rbac-xfer .rbac-check:has(input:disabled) { opacity: 0.55; cursor: default; }
.rbac-xfer-indent { margin-left: 22px; }
.rbac-xfer-table { width: 100%; margin-top: 10px; }
.rbac-xfer-table th, .rbac-xfer-table td { text-align: left; white-space: nowrap; vertical-align: top; }
.rbac-xfer-table th { cursor: pointer; user-select: none; }
.rbac-xfer-table th.rbac-sorted-asc::after { content: " \\25B4"; }
.rbac-xfer-table th.rbac-sorted-desc::after { content: " \\25BE"; }
.rbac-xfer-table td.rbac-xfer-notes { white-space: normal; min-width: 260px; }
.rbac-xfer-table td.rbac-xfer-id { font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 12px; }
.rbac-xfer-roles { max-height: 260px; overflow: auto; border: 1px solid var(--line, #8884); margin-top: 10px; }
.rbac-xfer-roles .rbac-xfer-table { margin-top: 0; }
.rbac-xfer-pick { cursor: pointer; }
.rbac-xfer-selected { background: rgba(37, 99, 235, 0.16); }
.rbac-xfer-callout {
    margin: 8px 0 4px;
    padding: 8px 12px;
    background: #fff7df;
    border: 1px solid #e8cf7a;
    border-radius: 3px;
    color: #1c2430;
}
.rbac-xfer-detail-grid { display: grid; grid-template-columns: 1fr minmax(260px, 2fr); gap: 16px; margin-top: 14px; }
.rbac-xfer-heading { margin: 0 0 2px; font-size: 12px; letter-spacing: 0.04em; text-transform: uppercase; opacity: 0.8; }
.rbac-xfer-scroll { max-height: 320px; overflow: auto; border: 1px solid var(--line, #8884); }
.rbac-xfer-scroll .rbac-xfer-table { margin-top: 0; }
.rbac-xfer-notice { padding: 4px 8px; opacity: 0.8; }
.rbac-xfer-legend { margin: 0 0 4px; font-size: 11px; opacity: 0.7; }
`;

export function makeTransferShell(React) {
    const Shell = makeOverlayShell(React);
    /* props: as the overlay shell's, without className and css */
    return function TransferShell(props) {
        return <Shell {...props} className="rbac-xfer" css={TRANSFER_CSS} />;
    };
}
