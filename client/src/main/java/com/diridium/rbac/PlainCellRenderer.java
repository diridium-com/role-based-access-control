// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import java.awt.Component;
import java.awt.Font;

import javax.swing.JComponent;
import javax.swing.JTable;
import javax.swing.table.DefaultTableCellRenderer;

/**
 * A label cell renderer that shows its text as written. A role or channel name that begins with
 * {@code <html>} would otherwise render as markup. Optionally sets a font (the ids use a
 * monospaced one).
 */
class PlainCellRenderer extends DefaultTableCellRenderer {

    private final Font font;

    PlainCellRenderer(Font font) {
        this.font = font;
        putClientProperty("html.disable", Boolean.TRUE);
    }

    @Override
    public Component getTableCellRendererComponent(JTable t, Object value, boolean selected, boolean focus,
            int row, int column) {
        Component c = super.getTableCellRendererComponent(t, value, selected, focus, row, column);
        if (font != null) {
            c.setFont(font);
        }
        ((JComponent) c).putClientProperty("html.disable", Boolean.TRUE);
        return c;
    }
}
