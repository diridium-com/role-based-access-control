// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import java.util.ArrayList;
import java.util.List;
import java.util.function.BooleanSupplier;

import javax.swing.table.AbstractTableModel;

/**
 * The rows of the Import Roles table: a tick box, then one column per fact about the role
 * (the role, the action, the descriptions and the permission and channel counts). The
 * ticks survive a fresh preview through {@link RoleImportText#keepTicks}.
 */
class RoleImportTableModel extends AbstractTableModel {

    static final String[] COLUMNS = {"Import", "Role", "Action", "Description currently",
            "Description after import", "Permissions", "Channels", "Notes"};

    private final BooleanSupplier busy;
    private final Runnable onTickChanged;
    private List<RoleImportRow> rows = new ArrayList<>();
    private boolean[] ticked = new boolean[0];

    /**
     * @param busy          whether the dialog is waiting on the server, which freezes the tick boxes
     * @param onTickChanged called after the user changes a tick
     */
    RoleImportTableModel(BooleanSupplier busy, Runnable onTickChanged) {
        this.busy = busy;
        this.onTickChanged = onTickChanged;
    }

    void setRows(List<RoleImportRow> newRows) {
        List<RoleImportRow> next = newRows == null ? new ArrayList<>() : new ArrayList<>(newRows);
        ticked = RoleImportText.keepTicks(rows, ticked, next);
        rows = next;
        fireTableDataChanged();
    }

    /** @return the preview row at a model row index */
    RoleImportRow rowAt(int row) {
        return rows.get(row);
    }

    boolean tickable(int row) {
        return RoleImportText.tickable(rows.get(row).getAction());
    }

    boolean anyTicked() {
        for (boolean t : ticked) {
            if (t) {
                return true;
            }
        }
        return false;
    }

    List<Integer> pickedIndexes() {
        List<Integer> picked = new ArrayList<>();
        for (int i = 0; i < ticked.length; i++) {
            if (ticked[i]) {
                picked.add(rows.get(i).getIndex());
            }
        }
        return picked;
    }

    @Override
    public int getRowCount() {
        return rows.size();
    }

    @Override
    public int getColumnCount() {
        return COLUMNS.length;
    }

    @Override
    public String getColumnName(int column) {
        return COLUMNS[column];
    }

    @Override
    public Class<?> getColumnClass(int column) {
        return column == 0 ? Boolean.class : String.class;
    }

    @Override
    public boolean isCellEditable(int row, int column) {
        return column == 0 && !busy.getAsBoolean() && tickable(row);
    }

    @Override
    public Object getValueAt(int row, int column) {
        RoleImportRow r = rows.get(row);
        switch (column) {
            case 0:
                return ticked[row];
            case 1:
                return r.getName();
            case 2:
                return RoleImportText.actionLabel(r.getAction());
            case 3:
                return r.getDescriptionNow() == null ? "" : r.getDescriptionNow();
            case 4:
                return r.getDescriptionAfter() == null ? "" : r.getDescriptionAfter();
            case 5:
                return RoleImportText.permissionsCountText(r);
            case 6:
                return RoleImportText.channelsCountText(r);
            default:
                return RoleImportText.notes(r);
        }
    }

    @Override
    public void setValueAt(Object value, int row, int column) {
        if (column == 0 && tickable(row)) {
            ticked[row] = Boolean.TRUE.equals(value);
            fireTableCellUpdated(row, column);
            onTickChanged.run();
        }
    }
}
