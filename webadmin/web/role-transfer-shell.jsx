// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

/*
 * The overlay frame shared by the Export Roles and Import Roles dialogs: a
 * titled panel with a scrolling body and a button row, closed by Escape unless
 * a host modal (an error dialog) is stacked on top and owns the key.
 *
 * Own classes, not host Tailwind utilities (see the note in role-editor.jsx).
 */

const TRANSFER_CSS = `
.rbac-xfer-overlay {
    position: fixed;
    top: 0; right: 0; bottom: 0; left: 0;
    display: flex;
    align-items: center;
    justify-content: center;
    background: rgba(0, 0, 0, 0.45);
    /* Below the host's .modal-overlay (100) so error dialogs stack above. */
    z-index: 95;
}
.rbac-xfer {
    width: 720px;
    max-width: 92vw;
    max-height: 88vh;
    display: flex;
    flex-direction: column;
}
.rbac-xfer > .panel-body { flex: 1; min-height: 0; overflow: auto; }
.rbac-xfer-foot {
    flex: none;
    display: flex;
    justify-content: flex-end;
    gap: 8px;
    padding: 10px 14px;
    border-top: 1px solid var(--line, #8884);
}
.rbac-xfer .rbac-check { display: flex; align-items: center; gap: 6px; font-size: 12px; margin: 3px 0; cursor: pointer; }
.rbac-xfer .rbac-check input { margin: 0; flex: none; }
.rbac-xfer .rbac-check:has(input:disabled) { opacity: 0.55; cursor: default; }
.rbac-xfer-indent { margin-left: 22px; }
.rbac-xfer-list { margin: 4px 0 8px 22px; font-size: 12px; }
.rbac-xfer-table { width: 100%; margin-top: 10px; }
.rbac-xfer-table td { vertical-align: top; }
`;

export function makeTransferShell(React) {
    return function TransferShell({ title, onCancel, footer, children }) {
        React.useEffect(() => {
            const onKey = (e) => {
                if (e.key === 'Escape' && !document.querySelector('.modal-overlay')) onCancel();
            };
            document.addEventListener('keydown', onKey);
            return () => document.removeEventListener('keydown', onKey);
        }, [onCancel]);
        return (
            <div className="rbac-xfer-overlay">
                <style>{TRANSFER_CSS}</style>
                <div className="panel rbac-xfer" role="dialog" aria-label={title}>
                    <div className="panel-header">{title}</div>
                    <div className="panel-body">{children}</div>
                    <div className="rbac-xfer-foot">{footer}</div>
                </div>
            </div>
        );
    };
}
