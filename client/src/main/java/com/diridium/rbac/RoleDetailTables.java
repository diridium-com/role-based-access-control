// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableRowSorter;

/**
 * The two tables below the roles table of the export and import dialogs, for the selected
 * role: its permissions on the left and its channels on the right, which is wider. Every
 * column sorts on a header click, and the id columns are monospaced. Showing another role
 * keeps the sort the user chose.
 */
class RoleDetailTables extends JPanel {

    private final RowsModel permissions;
    private final RowsModel channels;
    private final JLabel permissionsTitle = title();
    private final JLabel channelsTitle = title();
    private final JLabel channelsNote = new JLabel(" ");
    private final JLabel permissionsLegend = legend();
    private final JLabel channelsLegend = legend();
    private final JScrollPane channelsScroll;

    /**
     * @param export true for the export dialog's one-column permissions and Channel and Id
     *               columns, false for the import dialog's comparison columns
     */
    RoleDetailTables(boolean export) {
        super(new BorderLayout());
        permissions = new RowsModel(export ? new String[] {"Permission"} : RoleDetailRows.PERMISSION_COLUMNS);
        channels = new RowsModel(export ? RoleExportText.CHANNEL_COLUMNS : RoleDetailRows.CHANNEL_COLUMNS);
        int[] idColumns = export ? new int[] {1} : new int[] {1, 6};
        // The import channels table is wider than its pane at these widths and scrolls sideways
        // rather than squeezing the names and ids; the others fit and stretch to their pane.
        int[] permissionWidths = export ? new int[] {300} : new int[] {220, 50, 50, 200};
        int[] channelWidths = export ? new int[] {260, 290} : new int[] {200, 290, 45, 50, 140, 200, 290};
        channelsScroll = table(channels, idColumns, channelWidths, !export);
        permissionsLegend.setText(wrapped(export ? " " : RoleDetailRows.PERMISSIONS_LEGEND));
        channelsLegend.setText(wrapped(export ? " " : RoleDetailRows.CHANNELS_LEGEND));
        permissionsLegend.setVisible(!export);
        channelsLegend.setVisible(!export);
        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                section(permissionsTitle, permissionsLegend, null, table(permissions, new int[0], permissionWidths, false)),
                section(channelsTitle, channelsLegend, channelsNote, channelsScroll));
        split.setResizeWeight(0.3);
        split.setBorder(null);
        add(split, BorderLayout.CENTER);
        setPreferredSize(new Dimension(1260, 300));
        clear();
    }

    /**
     * Shows the permission and channel rows of an import preview row. While channel
     * restrictions are not applied, a line takes the place of the channels table and its legend.
     */
    void showImport(RoleImportRow row, boolean channelsApplied) {
        if (channelsApplied) {
            show(row.getName(), RoleDetailRows.permissionRows(row), RoleDetailRows.channelRows(row),
                    RoleImportText.everyChannelText(row));
        } else {
            show(row.getName(), RoleDetailRows.permissionRows(row), new ArrayList<String[]>(),
                    RoleDetailRows.CHANNELS_NOT_APPLIED);
        }
        channelsScroll.setVisible(channelsApplied);
        channelsLegend.setVisible(channelsApplied);
    }

    /** Shows a role's permissions and channels for export. */
    void showExport(Role role, Map<String, String> channelMap) {
        List<String[]> rows = RoleExportText.channelRows(role, channelMap);
        show(role.getName(), RoleExportText.permissionRows(role), rows, rows.isEmpty() ? RoleExportText.EVERY_CHANNEL_LINE : "");
    }

    /** Empties both tables, when no role is selected. */
    final void clear() {
        show(null, new ArrayList<String[]>(), new ArrayList<String[]>(), "");
    }

    private void show(String role, List<String[]> permissionRows, List<String[]> channelRows, String note) {
        permissionsTitle.setText(role == null ? "Permissions" : "Permissions of " + role);
        channelsTitle.setText(role == null ? "Channels" : "Channels of " + role);
        channelsNote.setText(note.isEmpty() ? " " : note);
        permissions.setRows(permissionRows);
        channels.setRows(channelRows);
    }

    private static JLabel title() {
        JLabel label = new JLabel();
        label.setFont(label.getFont().deriveFont(Font.BOLD));
        return label;
    }

    // A label wraps only as HTML; the width keeps a long legend from widening its pane.
    private static String wrapped(String text) {
        return "<html><body style='width: 480px'>" + text + "</body></html>";
    }

    private static JLabel legend() {
        JLabel label = new JLabel(" ");
        label.setFont(label.getFont().deriveFont(Font.PLAIN, label.getFont().getSize2D() - 1f));
        label.setForeground(Color.GRAY);
        return label;
    }

    private static JPanel section(JLabel heading, JLabel legend, JLabel note, JScrollPane scroll) {
        JPanel top = new JPanel();
        top.setLayout(new BoxLayout(top, BoxLayout.Y_AXIS));
        for (JLabel label : new JLabel[] {heading, legend, note}) {
            if (label != null) {
                label.setAlignmentX(Component.LEFT_ALIGNMENT);
                top.add(label);
            }
        }
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(4, 0, 0, 4));
        panel.add(top, BorderLayout.NORTH);
        panel.add(scroll, BorderLayout.CENTER);
        return panel;
    }

    private static JScrollPane table(RowsModel model, int[] idColumns, int[] widths, boolean scrollSideways) {
        JTable table = new JTable(model);
        TableRowSorter<RowsModel> sorter = new TableRowSorter<>(model);
        table.setRowSorter(sorter);
        table.setAutoResizeMode(scrollSideways ? JTable.AUTO_RESIZE_OFF : JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);
        for (int i = 0; i < widths.length; i++) {
            table.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);
        }
        Font mono = new Font(Font.MONOSPACED, Font.PLAIN, table.getFont().getSize());
        DefaultTableCellRenderer monospaced = new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable t, Object value, boolean selected,
                    boolean focus, int row, int column) {
                Component c = super.getTableCellRendererComponent(t, value, selected, focus, row, column);
                c.setFont(mono);
                return c;
            }
        };
        for (int column : idColumns) {
            table.getColumnModel().getColumn(column).setCellRenderer(monospaced);
        }
        return new JScrollPane(table);
    }

    /** A read-only table of strings; replacing the rows keeps the sorter's sort order. */
    private static class RowsModel extends AbstractTableModel {
        private final String[] columns;
        private List<String[]> rows = new ArrayList<>();

        RowsModel(String[] columns) {
            this.columns = columns;
        }

        void setRows(List<String[]> newRows) {
            rows = newRows;
            fireTableDataChanged();
        }

        @Override
        public int getRowCount() {
            return rows.size();
        }

        @Override
        public int getColumnCount() {
            return columns.length;
        }

        @Override
        public String getColumnName(int column) {
            return columns[column];
        }

        @Override
        public Object getValueAt(int row, int column) {
            return rows.get(row)[column];
        }
    }
}
