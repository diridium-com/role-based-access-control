// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableRowSorter;

import com.mirth.connect.client.ui.Frame;

/**
 * Modal dialog to pick the roles to export. The roles are a table on top with each role's
 * description and its permission and channel counts; selecting a role shows its permissions
 * and channels in two tables below. Every role starts ticked; Export is disabled while none
 * is. The caller passes the roles without the admin role, which is never exported.
 */
public class RoleExportDialog extends JDialog {

    private static final String[] COLUMNS = {"Export", "Role", "Description", "Permissions", "Channels"};
    private static final int[] WIDTHS = {50, 200, 500, 100, 100};

    private final List<Role> roles;
    private final Map<String, String> channelMap;
    private final boolean[] ticked;
    private final JTable table;
    private final RoleDetailTables details = new RoleDetailTables(true);
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
        this.channelMap = channelMap;
        ticked = new boolean[roles.size()];
        Arrays.fill(ticked, true);

        table = new JTable(new ExportModel());
        for (int i = 0; i < WIDTHS.length; i++) {
            table.getColumnModel().getColumn(i).setPreferredWidth(WIDTHS[i]);
        }
        table.getColumnModel().getColumn(0).setMaxWidth(50);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        TableRowSorter<ExportModel> sorter = new TableRowSorter<>((ExportModel) table.getModel());
        sorter.setComparator(3, (a, b) -> RoleImportText.compareCounts((String) a, (String) b));
        sorter.setComparator(4, (a, b) -> RoleImportText.compareCounts((String) a, (String) b));
        table.setRowSorter(sorter);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                showSelected();
            }
        });
        JScrollPane scroll = new JScrollPane(table);
        scroll.setPreferredSize(new Dimension(1260, 260));

        JPanel callout = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        callout.setBackground(new Color(0xFFF7DF));
        callout.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(0xE8CF7A)), BorderFactory.createEmptyBorder(8, 12, 8, 12)));
        JLabel included = new JLabel("Channel restrictions are included. ");
        JLabel choice = new JLabel("When importing, you can choose not to apply them.");
        choice.setFont(choice.getFont().deriveFont(Font.BOLD));
        callout.add(included);
        callout.add(choice);
        JLabel prompt = new JLabel("Pick the roles to export. The admin role is never exported.");
        JPanel top = new JPanel();
        top.setLayout(new BoxLayout(top, BoxLayout.Y_AXIS));
        top.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        callout.setAlignmentX(Component.LEFT_ALIGNMENT);
        prompt.setAlignmentX(Component.LEFT_ALIGNMENT);
        top.add(prompt);
        top.add(Box.createVerticalStrut(6));
        top.add(callout);

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

        JPanel middle = new JPanel(new BorderLayout());
        middle.setBorder(BorderFactory.createEmptyBorder(0, 8, 0, 8));
        middle.add(scroll, BorderLayout.NORTH);
        middle.add(details, BorderLayout.CENTER);
        add(top, BorderLayout.NORTH);
        add(middle, BorderLayout.CENTER);
        add(buttons, BorderLayout.SOUTH);
        getRootPane().setDefaultButton(exportButton);
        setResizable(true);
        pack();
        setMinimumSize(new Dimension(900, 600));
        setLocationRelativeTo(parent);
        if (!this.roles.isEmpty()) {
            table.setRowSelectionInterval(0, 0);
        }
        showSelected();
        updateExportEnabled();
    }

    private void showSelected() {
        int view = table.getSelectedRow();
        if (view < 0) {
            details.clear();
        } else {
            details.showExport(roles.get(table.convertRowIndexToModel(view)), channelMap);
        }
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

    /** One row per role: tick, then the role, description and the permission and channel counts. */
    private class ExportModel extends AbstractTableModel {
        @Override
        public int getRowCount() {
            return roles.size();
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
            Role role = roles.get(row);
            switch (column) {
                case 0:
                    return ticked[row];
                case 1:
                    return role.getName();
                case 2:
                    return role.getDescription() == null ? "" : role.getDescription();
                case 3:
                    return RoleExportText.permissionsCount(role);
                default:
                    return RoleExportText.channelsCount(role);
            }
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
