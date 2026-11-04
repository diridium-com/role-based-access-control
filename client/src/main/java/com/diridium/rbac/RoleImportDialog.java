// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
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
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableRowSorter;

import com.mirth.connect.client.core.ClientException;
import com.mirth.connect.client.ui.Frame;

/**
 * Modal dialog that previews a role export file and applies the roles the user ticks.
 *
 * <p>The roles are in a table on top, where the user ticks the ones to import and selects one
 * to see below it, in two tables, what the import would do to that role's permissions and
 * channels.</p>
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

    private static final int[] WIDTHS = {50, 130, 80, 150, 150, 90, 90, 330};

    private final Frame parent;
    private final Backend backend;

    private final JLabel fromLabel = new JLabel();
    private final JCheckBox applyBox = new JCheckBox("Apply channel restrictions from the import", true);
    private boolean applied = true;
    private final JCheckBox matchBox = new JCheckBox("Also match channels by name when the id isn't found", false);
    private final JLabel nameHint = new JLabel();
    private final RoleImportTableModel model = new RoleImportTableModel(() -> this.busy, this::updateControls);
    private final JTable table;
    private final RoleDetailTables details = new RoleDetailTables(false);
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
                    c.setEnabled(!busy && model.tickable(convertRowIndexToModel(row)));
                }
                return c;
            }
        };
        for (int i = 0; i < WIDTHS.length; i++) {
            table.getColumnModel().getColumn(i).setPreferredWidth(WIDTHS[i]);
        }
        table.getColumnModel().getColumn(0).setMaxWidth(50);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        WrappingCellRenderer.install(table, 1);
        TableRowSorter<RoleImportTableModel> sorter = new TableRowSorter<>(model);
        sorter.setComparator(5, (a, b) -> RoleImportText.compareCounts((String) a, (String) b));
        sorter.setComparator(6, (a, b) -> RoleImportText.compareCounts((String) a, (String) b));
        sorter.addRowSorterListener(e -> SwingUtilities.invokeLater(() -> WrappingCellRenderer.fitRowHeights(table)));
        table.setRowSorter(sorter);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                showSelected();
            }
        });
        JScrollPane scroll = new JScrollPane(table);
        scroll.setPreferredSize(new Dimension(1260, 260));

        matchBox.setBorder(BorderFactory.createEmptyBorder(0, 24, 0, 0));
        nameHint.setBorder(BorderFactory.createEmptyBorder(4, 24, 0, 0));
        nameHint.setVisible(false);
        JPanel top = new JPanel();
        top.setLayout(new BoxLayout(top, BoxLayout.Y_AXIS));
        top.setBorder(BorderFactory.createEmptyBorder(8, 8, 4, 8));
        for (Component c : new Component[] {fromLabel, applyBox, matchBox, nameHint}) {
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
        JPanel middle = new JPanel(new BorderLayout());
        middle.setBorder(BorderFactory.createEmptyBorder(0, 8, 0, 8));
        middle.add(scroll, BorderLayout.NORTH);
        middle.add(details, BorderLayout.CENTER);
        add(middle, BorderLayout.CENTER);
        add(buttons, BorderLayout.SOUTH);

        show(first);
        setResizable(true);
        pack();
        setMinimumSize(new Dimension(900, 600));
        WrappingCellRenderer.fitRowHeights(table);
        setLocationRelativeTo(parent);
    }

    /** @return how many roles the user imported; 0 if cancelled or nothing was applied */
    public int getImportedCount() {
        return importedCount;
    }

    private void show(RoleImportResult result) {
        current = result;
        applied = applyBox.isSelected();
        fromLabel.setText(RoleImportText.fromLine(result));
        int keepIndex = selectedRoleIndex();
        model.setRows(result.getRows());
        selectRole(keepIndex);
        int count = result.getChannelNameMatches() == null ? 0 : result.getChannelNameMatches().size();
        String hint = RoleImportText.nameMatchHint(count, applyBox.isSelected(), matchBox.isSelected());
        nameHint.setText(hint == null ? "" : hint);
        nameHint.setVisible(hint != null);
        updateControls();
        WrappingCellRenderer.fitRowHeights(table);
    }

    private int selectedRoleIndex() {
        int view = table.getSelectedRow();
        return view < 0 ? -1 : model.rowAt(table.convertRowIndexToModel(view)).getIndex();
    }

    // Selects the row of the role at this file position, else the first row.
    private void selectRole(int roleIndex) {
        int select = model.getRowCount() > 0 ? 0 : -1;
        for (int i = 0; i < model.getRowCount(); i++) {
            if (model.rowAt(i).getIndex() == roleIndex) {
                select = i;
            }
        }
        if (select < 0) {
            table.clearSelection();
            showSelected();
            return;
        }
        int view = table.convertRowIndexToView(select);
        table.setRowSelectionInterval(view, view);
        showSelected();
    }

    private void showSelected() {
        int view = table.getSelectedRow();
        if (view < 0) {
            details.clear();
        } else {
            details.showImport(model.rowAt(table.convertRowIndexToModel(view)), applied);
        }
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
}
