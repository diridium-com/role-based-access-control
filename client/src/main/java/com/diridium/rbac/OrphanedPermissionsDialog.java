// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.function.Consumer;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.SwingWorker;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableRowSorter;

import com.mirth.connect.client.core.ClientException;
import com.mirth.connect.client.ui.Frame;

/**
 * The admin-only Orphaned Permissions dialog: the permissions roles hold that neither the engine nor any installed
 * plugin registers, with Remove Selected and Remove All. The server lists them, never the engine's own permissions,
 * and checks each removal again. Web twin: orphaned-permissions.jsx, with the same texts in rbac-core.js.
 */
public class OrphanedPermissionsDialog extends JDialog {

    static final String TITLE = "Orphaned Permissions";
    static final String TOOLTIP = "Remove orphaned permissions.";
    static final String INTRO = "These permissions are orphaned, usually because a plugin changed or was removed. "
            + "Engine permissions are never listed here.";
    static final String EMPTY = "No role holds an orphaned permission.";

    /** The line naming the disabled plugins, or {@code null} when none is disabled. */
    static String disabledLine(List<String> plugins) {
        return plugins == null || plugins.isEmpty() ? null
                : "Disabled plugins: " + String.join(", ", plugins) + ". Their permissions may appear in this list.";
    }

    /** "Remove 3 orphaned permissions from 2 roles?", with the singular for one. */
    static String confirmation(List<UnregisteredGrant> grants) {
        long roles = grants.stream().map(UnregisteredGrant::getRoleId).distinct().count();
        return "Remove " + grants.size() + " orphaned permission" + (grants.size() == 1 ? "" : "s") + " from " + roles
                + " role" + (roles == 1 ? "" : "s") + "?";
    }

    private final Frame parent;
    private final Runnable refreshPanel;
    private final GrantModel model = new GrantModel();
    private final JTable table = new JTable(model);
    private final JLabel disabled = new JLabel();
    private final CardLayout cards = new CardLayout();
    private final JPanel center = new JPanel(cards);
    private final JButton removeSelected = new JButton("Remove Selected");
    private final JButton removeAll = new JButton("Remove All");
    private boolean removing;

    /** Loads the list, then shows the dialog. A failed load is reported and no dialog opens. */
    static void open(Frame parent, Runnable refreshPanel) {
        background(parent, parent, () -> rbac(parent).getUnregisteredGrants(),
                grants -> new OrphanedPermissionsDialog(parent, refreshPanel, grants).setVisible(true), null);
    }

    private OrphanedPermissionsDialog(Frame parent, Runnable refreshPanel, UnregisteredGrants grants) {
        super(parent, TITLE, true);
        this.parent = parent;
        this.refreshPanel = refreshPanel;

        table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        table.setDefaultRenderer(Object.class, new PlainCellRenderer(null));
        table.setRowSorter(new TableRowSorter<>(model));
        table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        table.getSelectionModel().addListSelectionListener(e -> updateButtons());
        JScrollPane scroll = new JScrollPane(table);
        scroll.setPreferredSize(new Dimension(700, 300));
        JLabel empty = new JLabel(EMPTY);
        empty.setVerticalAlignment(JLabel.TOP);
        center.add(scroll, "table");
        center.add(empty, "empty");
        center.setBorder(BorderFactory.createEmptyBorder(0, 8, 0, 8));

        JLabel intro = new JLabel(INTRO);
        JPanel top = new JPanel();
        top.setLayout(new BoxLayout(top, BoxLayout.Y_AXIS));
        top.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        intro.setAlignmentX(Component.LEFT_ALIGNMENT);
        disabled.setAlignmentX(Component.LEFT_ALIGNMENT);
        top.add(intro);
        top.add(Box.createVerticalStrut(6));
        top.add(disabled);

        removeSelected.addActionListener(e -> remove(selectedGrants()));
        removeAll.addActionListener(e -> remove(model.all()));
        JButton close = new JButton("Close");
        close.addActionListener(e -> dispose());
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        buttons.add(removeSelected);
        buttons.add(removeAll);
        buttons.add(close);

        add(top, BorderLayout.NORTH);
        add(center, BorderLayout.CENTER);
        add(buttons, BorderLayout.SOUTH);
        show(grants);
        setResizable(true);
        pack();
        setMinimumSize(new Dimension(640, 420));
        setLocationRelativeTo(parent);
    }

    private void show(UnregisteredGrants grants) {
        model.set(grants.getGrants());
        String line = disabledLine(grants.getDisabledPlugins());
        disabled.setText(line == null ? "" : line);
        disabled.setVisible(line != null);
        cards.show(center, model.getRowCount() == 0 ? "empty" : "table");
        updateButtons();
    }

    private void updateButtons() {
        removeSelected.setEnabled(!removing && table.getSelectedRowCount() > 0);
        removeAll.setEnabled(!removing && model.getRowCount() > 0);
    }

    private List<UnregisteredGrant> selectedGrants() {
        List<UnregisteredGrant> selected = new ArrayList<>();
        for (int view : table.getSelectedRows()) {
            selected.add(model.get(table.convertRowIndexToModel(view)));
        }
        return selected;
    }

    private void remove(List<UnregisteredGrant> grants) {
        if (grants.isEmpty() || JOptionPane.showConfirmDialog(this, confirmation(grants), TITLE,
                JOptionPane.YES_NO_OPTION) != JOptionPane.YES_OPTION) {
            return;
        }
        UnregisteredGrants request = new UnregisteredGrants();
        request.setGrants(new ArrayList<>(grants));
        removing = true;
        updateButtons();
        // The buttons come back once the list has reloaded, or when either call fails.
        background(parent, this, () -> rbac(parent).removeUnregisteredGrants(request), removed -> {
            refreshPanel.run();
            background(parent, this, () -> rbac(parent).getUnregisteredGrants(), reloaded -> {
                removing = false;
                show(reloaded);
            }, this::removalFailed);
        }, this::removalFailed);
    }

    private void removalFailed() {
        removing = false;
        updateButtons();
    }

    private static RbacServletInterface rbac(Frame parent) {
        return parent.mirthClient.getServlet(RbacServletInterface.class);
    }

    /**
     * Runs {@code call} off the event thread, then {@code onSuccess} on it; a failure is shown over {@code owner},
     * then {@code onFailure} runs, when given.
     */
    private static <T> void background(Frame parent, Component owner, Callable<T> call, Consumer<T> onSuccess,
            Runnable onFailure) {
        new SwingWorker<T, Void>() {
            @Override
            protected T doInBackground() throws Exception {
                return call.call();
            }

            @Override
            protected void done() {
                try {
                    onSuccess.accept(get());
                } catch (ExecutionException e) {
                    if (e.getCause() instanceof ClientException) {
                        RoleTransferActions.report(parent, owner, (ClientException) e.getCause());
                    } else {
                        parent.alertThrowable(owner, e.getCause() != null ? e.getCause() : e);
                    }
                    if (onFailure != null) {
                        onFailure.run();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    if (onFailure != null) {
                        onFailure.run();
                    }
                }
            }
        }.execute();
    }

    /** One row per orphaned permission: the role, then the permission. */
    private static class GrantModel extends AbstractTableModel {

        private static final String[] COLUMNS = {"Role", "Permission"};
        private final List<UnregisteredGrant> rows = new ArrayList<>();

        void set(List<UnregisteredGrant> grants) {
            rows.clear();
            if (grants != null) {
                rows.addAll(grants);
            }
            fireTableDataChanged();
        }

        UnregisteredGrant get(int row) {
            return rows.get(row);
        }

        List<UnregisteredGrant> all() {
            return new ArrayList<>(rows);
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
        public Object getValueAt(int row, int column) {
            UnregisteredGrant grant = rows.get(row);
            return column == 0 ? grant.getRoleName() : grant.getPermission();
        }
    }
}
