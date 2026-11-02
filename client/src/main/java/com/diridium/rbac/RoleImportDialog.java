// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.SwingWorker;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableCellRenderer;

import com.mirth.connect.client.core.ClientException;
import com.mirth.connect.client.ui.Frame;

/**
 * Modal dialog that previews a role export file and applies the roles the user ticks.
 *
 * <p>Changing either channel tick box previews the file again, because the plan token
 * depends on both settings. A failed apply shows the server's message and previews again
 * with the same settings, so the table shows the current state. The REST calls run on
 * {@link SwingWorker} threads and are supplied by a {@link Backend}.</p>
 */
public class RoleImportDialog extends JDialog {

    /** The two server calls, run off the event thread. */
    public interface Backend {
        RoleImportResult preview(boolean applyChannels, boolean matchChannelsByName) throws ClientException;

        RoleImportResult apply(List<Integer> pick, String planToken, boolean applyChannels,
                boolean matchChannelsByName) throws ClientException;
    }

    private static final String[] COLUMNS = {"", "Role", "Action", "Details"};

    private final Frame parent;
    private final Backend backend;

    private final JLabel fromLabel = new JLabel();
    private final JCheckBox applyBox = new JCheckBox("Apply channel restrictions from the file", true);
    private final JCheckBox matchBox = new JCheckBox("Also match channels by name when the id isn't found", false);
    private final JTextArea nameNote = new JTextArea();
    private final RowsModel model = new RowsModel();
    private final JTable table;
    private final JButton importButton = new JButton("Import");
    private final JButton cancelButton = new JButton("Cancel");

    // The preview the table shows; null while a preview is missing or out of date.
    private RoleImportResult current;
    private boolean busy;
    private int importedCount;

    /**
     * @param parent the owning frame
     * @param first  the first preview, importable
     * @param backend runs the preview and apply calls
     */
    public RoleImportDialog(Frame parent, RoleImportResult first, Backend backend) {
        super(parent, "Import Roles", true);
        this.parent = parent;
        this.backend = backend;

        table = new JTable(model) {
            @Override
            public Component prepareRenderer(TableCellRenderer renderer, int row, int column) {
                Component c = super.prepareRenderer(renderer, row, column);
                if (column == 0) {
                    c.setEnabled(!busy && model.tickable(row));
                }
                return c;
            }

            @Override
            public String getToolTipText(MouseEvent e) {
                int row = rowAtPoint(e.getPoint());
                return row >= 0 && columnAtPoint(e.getPoint()) == 3 ? (String) model.getValueAt(row, 3) : null;
            }
        };
        table.getColumnModel().getColumn(0).setMaxWidth(30);
        table.getColumnModel().getColumn(1).setPreferredWidth(160);
        table.getColumnModel().getColumn(2).setPreferredWidth(80);
        table.getColumnModel().getColumn(3).setPreferredWidth(440);
        JScrollPane scroll = new JScrollPane(table);
        scroll.setPreferredSize(new Dimension(760, 260));

        matchBox.setBorder(BorderFactory.createEmptyBorder(0, 24, 0, 0));
        nameNote.setEditable(false);
        nameNote.setOpaque(false);
        nameNote.setBorder(BorderFactory.createEmptyBorder(4, 24, 0, 0));
        JPanel top = new JPanel();
        top.setLayout(new BoxLayout(top, BoxLayout.Y_AXIS));
        top.setBorder(BorderFactory.createEmptyBorder(8, 8, 4, 8));
        for (Component c : new Component[] {fromLabel, applyBox, matchBox, nameNote}) {
            ((javax.swing.JComponent) c).setAlignmentX(Component.LEFT_ALIGNMENT);
            top.add(c);
        }

        applyBox.addActionListener(e -> settingsChanged());
        matchBox.addActionListener(e -> settingsChanged());
        importButton.addActionListener(e -> applyPicked());
        cancelButton.addActionListener(e -> dispose());
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        buttons.add(importButton);
        buttons.add(cancelButton);

        add(top, BorderLayout.NORTH);
        add(scroll, BorderLayout.CENTER);
        add(buttons, BorderLayout.SOUTH);

        show(first);
        pack();
        setLocationRelativeTo(parent);
    }

    /** @return how many roles the user imported; 0 if cancelled or nothing was applied */
    public int getImportedCount() {
        return importedCount;
    }

    private void show(RoleImportResult result) {
        current = result;
        fromLabel.setText(RoleImportText.fromLine(result));
        model.setRows(result.getRows());
        String note = RoleImportText.nameMatchNote(result.getChannelNameMatches(),
                applyBox.isSelected(), matchBox.isSelected());
        nameNote.setText(note == null ? "" : note);
        nameNote.setVisible(note != null);
        updateControls();
        pack();
    }

    private void updateControls() {
        applyBox.setEnabled(!busy);
        matchBox.setEnabled(!busy && applyBox.isSelected());
        table.setEnabled(!busy);
        cancelButton.setEnabled(!busy);
        importButton.setEnabled(!busy && current != null && model.anyTicked());
        table.repaint();
    }

    private void settingsChanged() {
        if (!applyBox.isSelected()) {
            matchBox.setSelected(false);
        }
        runPreview();
    }

    private void setBusy(boolean value) {
        busy = value;
        updateControls();
    }

    private void runPreview() {
        current = null;
        setBusy(true);
        boolean apply = applyBox.isSelected();
        boolean match = matchBox.isSelected();
        new SwingWorker<RoleImportResult, Void>() {
            @Override
            protected RoleImportResult doInBackground() throws Exception {
                return backend.preview(apply, match);
            }

            @Override
            protected void done() {
                busy = false;
                try {
                    RoleImportResult result = get();
                    if (!result.isImportable()) {
                        parent.alertError(RoleImportDialog.this, "This file can't be imported: " + result.getRefusal());
                        dispose();
                        return;
                    }
                    show(result);
                } catch (ExecutionException e) {
                    reportFailure(e);
                    updateControls();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    updateControls();
                }
            }
        }.execute();
    }

    private void applyPicked() {
        List<Integer> pick = model.pickedIndexes();
        String token = current.getPlanToken();
        boolean apply = applyBox.isSelected();
        boolean match = matchBox.isSelected();
        setBusy(true);
        new SwingWorker<RoleImportResult, Void>() {
            @Override
            protected RoleImportResult doInBackground() throws Exception {
                return backend.apply(pick, token, apply, match);
            }

            @Override
            protected void done() {
                busy = false;
                try {
                    RoleImportResult result = get();
                    if (result.isApplied()) {
                        importedCount = pick.size();
                        dispose();
                        return;
                    }
                } catch (ExecutionException e) {
                    reportFailure(e);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                // Show the current state with the same settings.
                runPreview();
            }
        }.execute();
    }

    private void reportFailure(ExecutionException e) {
        if (e.getCause() instanceof ClientException) {
            RoleTransferActions.report(parent, this, (ClientException) e.getCause());
        } else {
            parent.alertThrowable(this, e.getCause() != null ? e.getCause() : e);
        }
    }

    /** One row per role in the file: tick, role, action, details. */
    private class RowsModel extends AbstractTableModel {
        private List<RoleImportRow> rows = new ArrayList<>();
        private boolean[] ticked = new boolean[0];

        void setRows(List<RoleImportRow> newRows) {
            List<RoleImportRow> next = newRows == null ? new ArrayList<>() : new ArrayList<>(newRows);
            ticked = RoleImportText.keepTicks(rows, ticked, next);
            rows = next;
            fireTableDataChanged();
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
            return column == 0 && !busy && tickable(row);
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
                default:
                    return RoleImportText.details(r);
            }
        }

        @Override
        public void setValueAt(Object value, int row, int column) {
            if (column == 0 && tickable(row)) {
                ticked[row] = Boolean.TRUE.equals(value);
                fireTableCellUpdated(row, column);
                updateControls();
            }
        }
    }
}
