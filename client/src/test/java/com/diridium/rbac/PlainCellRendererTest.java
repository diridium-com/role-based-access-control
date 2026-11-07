// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.awt.Component;

import javax.swing.DefaultListCellRenderer;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JTable;
import javax.swing.plaf.basic.BasicHTML;
import javax.swing.table.DefaultTableCellRenderer;

import org.junit.jupiter.api.Test;

/**
 * A role or channel name that begins with {@code <html>} is shown as written, never rendered as
 * markup. Swing keeps the view of rendered markup in the label's {@link BasicHTML#propertyKey}
 * property, so a null there means plain text; the controls show the check sees markup when
 * nothing stops it.
 */
class PlainCellRendererTest {

    private static final String MARKUP = "<html><b>Lab</b></html>";

    private static Object htmlView(Component c) {
        return ((JComponent) c).getClientProperty(BasicHTML.propertyKey);
    }

    private static JTable table() {
        return new JTable(new Object[][] {{MARKUP}}, new Object[] {"Name"});
    }

    @Test
    void control_theDefaultRenderersRenderMarkup() {
        assertNotNull(htmlView(new DefaultTableCellRenderer().getTableCellRendererComponent(table(), MARKUP,
                false, false, 0, 0)));
        assertNotNull(htmlView(new DefaultListCellRenderer().getListCellRendererComponent(new JList<Object>(),
                MARKUP, 0, false, false)));
    }

    @Test
    void tableRenderer_showsMarkupAsText() {
        Component c = new PlainCellRenderer(null).getTableCellRendererComponent(table(), MARKUP, false, false, 0, 0);
        assertNull(htmlView(c));
        assertEquals(MARKUP, ((JLabel) c).getText());
    }

    @Test
    void listRenderer_showsMarkupAsText_andARoleByItsName() {
        PlainCellRenderer.ForList renderer = new PlainCellRenderer.ForList();
        assertNull(htmlView(renderer.getListCellRendererComponent(new JList<Object>(), MARKUP, 0, false, false)));
        Role role = new Role();
        role.setName(MARKUP);
        Component c = renderer.getListCellRendererComponent(new JList<Object>(), role, 0, true, false);
        assertEquals(MARKUP, ((JLabel) c).getText());
        assertNull(htmlView(c));
    }
}
