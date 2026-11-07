// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

/*
 * The overlay frame of the role editor and the Export Roles and Import Roles
 * dialogs: a titled panel with a scrolling body and a button row, closed by
 * Escape unless a host modal (an error dialog, a confirm) is stacked on top and
 * owns the key, or the dialog says it can't be closed now (closable false, an
 * import being applied).
 *
 * Own classes, NOT host Tailwind utilities: the host generates utilities from
 * ITS source scan, so a class no host file uses simply does not exist in
 * app.css, and this plugin's sources are never scanned (the community-store
 * cs-overlay precedent). Host COMPONENT classes (.panel, .btn, .tabs, .hint)
 * are fine.
 */

const SHELL_CSS = `
.rbac-overlay {
    position: fixed;
    top: 0; right: 0; bottom: 0; left: 0;
    display: flex;
    align-items: center;
    justify-content: center;
    background: rgba(0, 0, 0, 0.45);
    /* Below the host's .modal-overlay (100): its confirms and error dialogs
       (ui.modal / ui.confirmDialog) must stack above this one. */
    z-index: 95;
}
.rbac-overlay-panel { max-height: 88vh; display: flex; flex-direction: column; }
.rbac-overlay-panel > .panel-body { flex: 1; min-height: 0; overflow: auto; }
.rbac-overlay-foot {
    flex: none;
    display: flex;
    justify-content: flex-end;
    gap: 8px;
    padding: 10px 14px;
    border-top: 1px solid var(--line, #8884);
}
.rbac-check { display: flex; align-items: center; gap: 6px; font-size: 12px; margin: 3px 0; cursor: pointer; }
.rbac-check input { margin: 0; flex: none; }
`;

export function makeOverlayShell(React) {
    /* props: title, className (the panel's size, with its rules in css), css (the
       dialog's own rules), closable (false ignores Escape), onCancel(), footer, children */
    return function OverlayShell({ title, className, css, closable = true, onCancel, footer, children }) {
        // A layout effect, not a passive one: the dialog can open from a state update inside a
        // promise (Export reads the roles first), and React then attaches passive effects a tick
        // after the paint, so an Escape pressed as soon as the dialog shows would find no listener.
        React.useLayoutEffect(() => {
            if (!closable) return undefined;
            const onKey = (e) => {
                if (e.key === 'Escape' && !document.querySelector('.modal-overlay')) onCancel();
            };
            document.addEventListener('keydown', onKey);
            return () => document.removeEventListener('keydown', onKey);
        }, [onCancel, closable]);
        return (
            <div className="rbac-overlay">
                <style>{SHELL_CSS + (css || '')}</style>
                <div className={'panel rbac-overlay-panel ' + className} role="dialog" aria-label={title}>
                    <div className="panel-header">{title}</div>
                    <div className="panel-body">{children}</div>
                    <div className="rbac-overlay-foot">{footer}</div>
                </div>
            </div>
        );
    };
}
