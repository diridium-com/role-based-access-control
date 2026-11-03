// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.table.AbstractTableModel;

import com.mirth.connect.client.ui.Frame;

/**
 * Modal dialog to pick the roles to export, shown as a table with each role's description,
 * permissions and channels. Every role starts ticked; Export is disabled while none is.
 * The caller passes the roles without the admin role, which is never exported.
 */
public class RoleExportDialog extends JDialog {

    private static final String[] COLUMNS = {"Export", "Role", "Description", "Permissions", "Channels"};
    private static final int[] WIDTHS = {50, 160, 220, 220, 220};

    private final List<Role> roles;
    private final String[][] cells;
    private final boolean[] ticked;
    private final JButton exportButton = new JButton("Export");
    private List<Integer> result;

    /**
     * @param parent     the owning frame
     * @param roles      the roles to offer, none of them the admin role
     * @param channelMap channel id to name, or {@code null} when the channel list was not loaded
     */
    public RoleExportDialog(Frame parent, List<Role> roles, Map<String, String> channelMap) {
        super(parent, "Export Roles", true);
        this.roles = new ArrayList<>(roles);
        cells = new String[roles.size()][];
        ticked = new boolean[roles.size()];
        for (int i = 0; i < cells.length; i++) {
            Role role = this.roles.get(i);
            ticked[i] = true;
            cells[i] = new String[] {role.getName(), role.getDescription() == null ? "" : role.getDescription(),
                    String.join("\n", new TreeSet<>(role.getPermissions() == null
                            ? Collections.<String>emptySet() : role.getPermissions())),
                    RoleImportText.exportChannelsCell(role, channelMap)};
        }

        JTable table = new JTable(new ExportModel());
        for (int i = 0; i < WIDTHS.length; i++) {
            table.getColumnModel().getColumn(i).setPreferredWidth(WIDTHS[i]);
        }
        table.getColumnModel().getColumn(0).setMaxWidth(50);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        WrappingCellRenderer.install(table, 1);
        JScrollPane scroll = new JScrollPane(table);
        scroll.setPreferredSize(new Dimension(860, 300));

        JLabel prompt = new JLabel("Pick the roles to export. The admin role is never exported.");
        JLabel included = new JLabel("Channel restrictions are included. When importing, you can choose not to apply them.");
        JPanel top = new JPanel();
        top.setLayout(new BoxLayout(top, BoxLayout.Y_AXIS));
        top.setBorder(BorderFactory.createEmptyBorder(8, 8, 4, 8));
        for (JLabel label : new JLabel[] {prompt, included}) {
            label.setAlignmentX(Component.LEFT_ALIGNMENT);
            top.add(label);
        }

        exportButton.addActionListener(e -> {
            result = new ArrayList<>();
            for (int i = 0; i < ticked.length; i++) {
                if (ticked[i]) {
                    result.add(this.roles.get(i).getId());
                }
            }
            dispose();
        });
        JButton cancelButton = new JButton("Cancel");
        cancelButton.addActionListener(e -> dispose());
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        buttons.add(exportButton);
        buttons.add(cancelButton);

        add(top, BorderLayout.NORTH);
        add(scroll, BorderLayout.CENTER);
        add(buttons, BorderLayout.SOUTH);
        getRootPane().setDefaultButton(exportButton);
        setResizable(true);
        pack();
        setMinimumSize(getSize());
        WrappingCellRenderer.fitRowHeights(table);
        setLocationRelativeTo(parent);
        updateExportEnabled();
    }

    private void updateExportEnabled() {
        boolean any = false;
        for (boolean t : ticked) {
            any |= t;
        }
        exportButton.setEnabled(any);
    }

    /** @return the ids of the ticked roles, or {@code null} if the user cancelled */
    public List<Integer> getResult() {
        return result;
    }

    /** One row per role: tick, then the role, description, permissions and channels. */
    private class ExportModel extends AbstractTableModel {
        @Override
        public int getRowCount() {
            return cells.length;
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
            return column == 0;
        }

        @Override
        public Object getValueAt(int row, int column) {
            return column == 0 ? (Object) ticked[row] : cells[row][column - 1];
        }

        @Override
        public void setValueAt(Object value, int row, int column) {
            if (column == 0) {
                ticked[row] = Boolean.TRUE.equals(value);
                fireTableCellUpdated(row, column);
                updateExportEnabled();
            }
        }
    }
}
