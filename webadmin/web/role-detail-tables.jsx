// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

/*
 * The tables of the Export Roles and Import Roles dialogs: a header row whose
 * columns sort on a click (ascending, then descending), and the two detail
 * tables below the roles table, permissions on the left and channels on the
 * right, for the role selected above. Sorting only reorders rows; it never
 * changes the selection or any tick.
 */

import { sortRows } from './role-transfer-core.js';

export function makeDetailTables(React) {
    // [sort, toggle]: sort is { col, dir } or null; a click on a column sorts it
    // ascending, a second click on the same column descending, then ascending again.
    function useSort() {
        const [sort, setSort] = React.useState(null);
        const toggle = (col) => setSort((s) =>
            (s && s.col === col && s.dir === 'asc' ? { col, dir: 'desc' } : { col, dir: 'asc' }));
        return [sort, toggle];
    }

    /* props: columns (header labels), sort, onSort(col) */
    function SortHeader({ columns, sort, onSort }) {
        return (
            <thead>
                <tr>
                    {columns.map((label, col) => {
                        const on = sort && sort.col === col;
                        return (
                            <th key={col} className={on ? 'rbac-sorted-' + sort.dir : ''}
                                aria-sort={on ? (sort.dir === 'asc' ? 'ascending' : 'descending') : undefined}
                                tabIndex={0} onClick={() => onSort(col)}
                                onKeyDown={(e) => {
                                    if (e.key === 'Enter' || e.key === ' ') {
                                        e.preventDefault();
                                        onSort(col);
                                    }
                                }}>{label}</th>
                        );
                    })}
                </tr>
            </thead>
        );
    }

    /* One detail table. props: columns, rows (arrays of cell text), idColumns
       (column numbers shown in monospace), legend (a line under the heading),
       notice (a line above the rows), empty (shown instead of the table when
       there is nothing to show), notApplied (a line that replaces the legend
       and the table) */
    function DetailTable({ columns, rows, idColumns, legend, notice, empty, notApplied }) {
        const [sort, toggle] = useSort();
        const shown = sort ? sortRows(rows, sort.col, sort.dir) : rows;
        const showEmpty = empty && rows.length === 0;
        if (notApplied) return <div className="rbac-xfer-notice">{notApplied}</div>;
        return (
            <div>
                {legend ? <div className="rbac-xfer-legend">{legend}</div> : null}
                <div className="rbac-xfer-scroll">
                    {notice ? <div className="rbac-xfer-notice">{notice}</div> : null}
                    {showEmpty ? <div className="rbac-xfer-notice">{empty}</div> : null}
                    {rows.length > 0 ? (
                        <table className="dt rbac-xfer-table">
                            <SortHeader columns={columns} sort={sort} onSort={toggle} />
                            <tbody>
                                {shown.map((cells, i) => (
                                    <tr key={i}>
                                        {cells.map((text, col) => (
                                            <td key={col} className={idColumns.includes(col) ? 'rbac-xfer-id' : ''}>{text}</td>
                                        ))}
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    ) : null}
                </div>
            </div>
        );
    }

    /* The two detail tables side by side, each under its heading.
       props: permissions and channels, each { heading, columns, rows, idColumns, legend, notice, empty, notApplied } */
    function DetailTables({ permissions, channels }) {
        return (
            <div className="rbac-xfer-detail-grid">
                <div>
                    <h4 className="rbac-xfer-heading">{permissions.heading}</h4>
                    <DetailTable idColumns={[]} {...permissions} />
                </div>
                <div>
                    <h4 className="rbac-xfer-heading">{channels.heading}</h4>
                    <DetailTable {...channels} />
                </div>
            </div>
        );
    }

    return { useSort, SortHeader, DetailTables };
}
