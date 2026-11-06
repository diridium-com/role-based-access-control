// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import java.awt.Component;

import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.border.EmptyBorder;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.TableColumnModelEvent;
import javax.swing.event.TableColumnModelListener;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableColumn;

/**
 * A table cell renderer for multi-line text: line breaks in the value start new lines and
 * long lines wrap at the column width. A {@link JTable} does not size rows to such cells
 * by itself, so {@link #fitRowHeights} sets each row to its tallest cell. Used by the roles
 * table of the role import dialog, whose Notes cell can run to several sentences.
 */
class WrappingCellRenderer extends JTextArea implements TableCellRenderer {

    WrappingCellRenderer() {
        setLineWrap(true);
        setWrapStyleWord(true);
        setOpaque(true);
        setBorder(new EmptyBorder(2, 4, 2, 4));
    }

    @Override
    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
            boolean hasFocus, int row, int column) {
        setText(value == null ? "" : value.toString());
        setFont(table.getFont());
        setForeground(isSelected ? table.getSelectionForeground() : table.getForeground());
        setBackground(isSelected ? table.getSelectionBackground() : table.getBackground());
        // The height depends on the width, so give the area the column's width first.
        setSize(table.getColumnModel().getColumn(column).getWidth(), Short.MAX_VALUE);
        return this;
    }

    /**
     * Gives the columns from {@code firstColumn} on one wrapping renderer, and refits the
     * row heights whenever a column is resized.
     */
    static void install(JTable table, int firstColumn) {
        WrappingCellRenderer renderer = new WrappingCellRenderer();
        for (int i = firstColumn; i < table.getColumnCount(); i++) {
            table.getColumnModel().getColumn(i).setCellRenderer(renderer);
        }
        table.getColumnModel().addColumnModelListener(new TableColumnModelListener() {
            @Override
            public void columnMarginChanged(ChangeEvent e) {
                fitRowHeights(table);
            }

            @Override
            public void columnAdded(TableColumnModelEvent e) {
            }

            @Override
            public void columnRemoved(TableColumnModelEvent e) {
            }

            @Override
            public void columnMoved(TableColumnModelEvent e) {
            }

            @Override
            public void columnSelectionChanged(ListSelectionEvent e) {
            }
        });
    }

    /**
     * Sets every row's height to the tallest of its cells rendered by a wrapping renderer at
     * the columns' current widths. Call it after the rows change and after a column resize.
     */
    static void fitRowHeights(JTable table) {
        for (int row = 0; row < table.getRowCount(); row++) {
            int height = table.getRowHeight();
            for (int col = 0; col < table.getColumnCount(); col++) {
                TableColumn column = table.getColumnModel().getColumn(col);
                TableCellRenderer renderer = table.getCellRenderer(row, col);
                if (column.getWidth() <= 0 || !(renderer instanceof WrappingCellRenderer)) {
                    continue;
                }
                Component c = table.prepareRenderer(renderer, row, col);
                c.setSize(column.getWidth(), Short.MAX_VALUE);
                height = Math.max(height, c.getPreferredSize().height);
            }
            if (table.getRowHeight(row) != height) {
                table.setRowHeight(row, height);
            }
        }
    }
}
