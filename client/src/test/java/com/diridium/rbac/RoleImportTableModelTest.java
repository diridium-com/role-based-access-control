// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.Collections;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

/**
 * The Import Roles table without a dialog: its rows and columns, the pick column, and the ticks
 * kept through a fresh preview of the same file.
 */
class RoleImportTableModelTest {

    private final boolean[] busy = {false};
    private final AtomicInteger tickChanges = new AtomicInteger();

    private RoleImportTableModel model() {
        return new RoleImportTableModel(() -> busy[0], tickChanges::incrementAndGet);
    }

    private static RoleImportRow row(int index, String name, RoleImportRow.Action action) {
        RoleImportRow r = new RoleImportRow();
        r.setIndex(index);
        r.setName(name);
        r.setAction(action);
        return r;
    }

    @Test
    void rowsAndColumns() {
        RoleImportTableModel m = model();
        RoleImportRow lab = row(0, "Lab", RoleImportRow.Action.CREATE);
        lab.setDescriptionAfter("Lab staff");
        lab.setPermissionsAfter(Arrays.asList("viewChannels", "viewDashboard"));
        lab.setReason("A new role.");
        RoleImportRow ops = row(1, "Ops", RoleImportRow.Action.OVERWRITE);
        ops.setExistsHere(true);
        ops.setDescriptionNow("Old");
        ops.setDescriptionAfter("New");
        ops.setPermissionsNow(Arrays.asList("viewChannels"));
        ops.setPermissionsAfter(Arrays.asList("viewChannels", "viewDashboard"));
        m.setRows(Arrays.asList(lab, ops));

        assertEquals(2, m.getRowCount());
        assertEquals(Arrays.asList("Import", "Role", "Action", "Description currently", "Description after import",
                "Permissions", "Channels", "Notes"), Arrays.asList(RoleImportTableModel.COLUMNS));
        assertEquals(8, m.getColumnCount());
        assertEquals("Notes", m.getColumnName(7));
        assertEquals(Boolean.class, m.getColumnClass(0));
        assertEquals(String.class, m.getColumnClass(1));
        assertEquals(Arrays.asList(true, "Lab", "New", "", "Lab staff", "2", "every", "A new role."), rowValues(m, 0));
        assertEquals(Arrays.asList(false, "Ops", "Overwrite", "Old", "New", "1 → 2", "every", ""), rowValues(m, 1));
        assertEquals("Ops", m.rowAt(1).getName());
    }

    @Test
    void pickColumn_onlyNewAndOverwriteRows_andNothingWhileBusy() {
        RoleImportTableModel m = model();
        m.setRows(Arrays.asList(row(0, "Lab", RoleImportRow.Action.CREATE), row(1, "Ops", RoleImportRow.Action.OVERWRITE),
                row(2, "Old", RoleImportRow.Action.SKIP), row(3, "Same", RoleImportRow.Action.UNCHANGED)));
        assertTrue(m.isCellEditable(0, 0));
        assertTrue(m.isCellEditable(1, 0));
        assertFalse(m.isCellEditable(2, 0), "Skipped");
        assertFalse(m.isCellEditable(3, 0), "Unchanged");
        assertFalse(m.isCellEditable(0, 1), "only the pick column");
        busy[0] = true;
        assertFalse(m.isCellEditable(0, 0), "frozen while the dialog waits on the server");
        busy[0] = false;

        m.setValueAt(true, 2, 0);
        assertEquals(false, m.getValueAt(2, 0), "a row that can't be ticked stays unticked");
        assertEquals(0, tickChanges.get());
        m.setValueAt(true, 1, 0);
        assertEquals(1, tickChanges.get());
        assertTrue(m.anyTicked());
        assertEquals(Arrays.asList(0, 1), m.pickedIndexes());
        m.setValueAt(false, 0, 0);
        m.setValueAt(false, 1, 0);
        assertFalse(m.anyTicked());
        assertTrue(m.pickedIndexes().isEmpty());
    }

    @Test
    void pickedIndexes_areFilePositions() {
        RoleImportTableModel m = model();
        m.setRows(Arrays.asList(row(4, "Lab", RoleImportRow.Action.CREATE), row(7, "Desk", RoleImportRow.Action.CREATE)));
        assertEquals(Arrays.asList(4, 7), m.pickedIndexes());
    }

    @Test
    void ticksSurviveAFreshPreviewOfTheSameFile() {
        RoleImportTableModel m = model();
        m.setRows(Arrays.asList(row(0, "Lab", RoleImportRow.Action.CREATE), row(1, "Ops", RoleImportRow.Action.OVERWRITE)));
        m.setValueAt(false, 0, 0);
        m.setValueAt(true, 1, 0);

        m.setRows(Arrays.asList(row(0, "Lab", RoleImportRow.Action.CREATE), row(1, "Ops", RoleImportRow.Action.OVERWRITE),
                row(2, "Desk", RoleImportRow.Action.CREATE)));
        assertEquals(false, m.getValueAt(0, 0), "the user's untick is kept");
        assertEquals(true, m.getValueAt(1, 0), "the user's tick is kept");
        assertEquals(true, m.getValueAt(2, 0), "a new row starts at its default");
        assertEquals(Arrays.asList(1, 2), m.pickedIndexes());

        RoleImportRow found = row(0, "Lab", RoleImportRow.Action.CREATE);
        RoleImportRow becameNew = row(1, "Ops", RoleImportRow.Action.CREATE);
        RoleImportRow noChannel = row(2, "Desk", RoleImportRow.Action.CREATE);
        noChannel.setNoChannelFound(true);
        m.setRows(Arrays.asList(found, becameNew, noChannel));
        assertEquals(false, m.getValueAt(0, 0), "same row: still unticked");
        assertEquals(true, m.getValueAt(1, 0), "Overwrite became New: the default for New");
        assertEquals(true, m.getValueAt(2, 0), "its no-channel-found state changed: the default");

        m.setRows(null);
        assertEquals(0, m.getRowCount());
        assertFalse(m.anyTicked());
        m.setRows(Collections.<RoleImportRow>emptyList());
        assertTrue(m.pickedIndexes().isEmpty());
    }

    @Test
    void theCloseButtonClosesTheDialogOnlyWhileNoCallRuns() {
        boolean[] running = {true};
        AtomicInteger closes = new AtomicInteger();
        RoleImportDialog.CloseWhenIdle guard = new RoleImportDialog.CloseWhenIdle(() -> running[0], closes::incrementAndGet);
        guard.windowClosing(null);
        assertEquals(0, closes.get(), "refused while an apply or a preview runs");
        running[0] = false;
        guard.windowClosing(null);
        assertEquals(1, closes.get());
    }

    private static java.util.List<Object> rowValues(RoleImportTableModel m, int row) {
        java.util.List<Object> values = new java.util.ArrayList<>();
        for (int c = 0; c < m.getColumnCount(); c++) {
            values.add(m.getValueAt(row, c));
        }
        return values;
    }
}
