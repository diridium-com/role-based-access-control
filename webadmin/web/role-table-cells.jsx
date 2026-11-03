// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

/*
 * Cells of the Export Roles and Import Roles tables. A list cell shows one
 * entry per line, never joined with commas.
 */

export function makeListCell(React) {
    /* props: lines (an array of strings; empty gives an empty cell) */
    return function ListCell({ lines }) {
        return <td>{lines.map((line, i) => <div key={i}>{line}</div>)}</td>;
    };
}
