// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import java.awt.Component;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.function.Consumer;
import java.util.function.Supplier;

import javax.swing.SwingWorker;

import com.mirth.connect.client.core.ClientException;
import com.mirth.connect.client.ui.Frame;

/**
 * The Export Roles and Import Roles tasks of the settings panel: asking the server,
 * picking files, and showing the dialogs. Every server call runs on a {@link SwingWorker}.
 *
 * <p>The file is written and read here as plain UTF-8 text. The engine's
 * {@code Frame.exportFile} is not used because it encrypts the file when the engine's
 * export encryption is on, and a role file has to stay readable XML.</p>
 */
class RoleTransferActions {

    private static final String DEFAULT_FILE_NAME = "rbac-roles.xml";

    private final Frame parent;
    private final Runnable refreshPanel;
    private final Supplier<Map<String, String>> channelMap;

    /**
     * @param parent       the administrator's main frame
     * @param refreshPanel reloads the panel's roles after an import
     * @param channelMap   the panel's channel id to name map, or null when the channel list was not loaded
     */
    RoleTransferActions(Frame parent, Runnable refreshPanel, Supplier<Map<String, String>> channelMap) {
        this.parent = parent;
        this.refreshPanel = refreshPanel;
        this.channelMap = channelMap;
    }

    private RbacServletInterface rbac() {
        return parent.mirthClient.getServlet(RbacServletInterface.class);
    }

    // ========== Export ==========

    void exportRoles() {
        background(() -> rbac().getRoles(), roles -> {
            List<Role> exportable = new ArrayList<>();
            for (Role role : roles) {
                if (!role.isAdmin()) {
                    exportable.add(role);
                }
            }
            if (exportable.isEmpty()) {
                parent.alertInformation(parent, "There are no roles to export. The admin role is never exported.");
                return;
            }
            RoleExportDialog dialog = new RoleExportDialog(parent, exportable, channelMap.get());
            dialog.setVisible(true);
            List<Integer> ids = dialog.getResult();
            if (ids != null) {
                fetchAndSave(ids);
            }
        });
    }

    private void fetchAndSave(List<Integer> ids) {
        background(() -> rbac().exportRoles(new HashSet<>(ids)), text -> {
            File file = parent.createFileForExport(DEFAULT_FILE_NAME, "XML");
            if (file == null) {
                return;
            }
            try {
                Files.write(file.toPath(), text.getBytes(StandardCharsets.UTF_8));
            } catch (IOException e) {
                parent.alertError(parent, "File could not be written.");
                return;
            }
            parent.alertInformation(parent, "Exported " + ids.size() + " role(s).");
        });
    }

    // ========== Import ==========

    void importRoles() {
        File file = parent.browseForFile("XML");
        if (file == null) {
            return;
        }
        String text;
        try {
            text = new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8);
        } catch (IOException e) {
            parent.alertError(parent, "Unable to read file.");
            return;
        }
        if (text.startsWith("\uFEFF")) {
            text = text.substring(1);
        }
        final String fileText = text;
        RoleImportDialog.Backend backend = new RoleImportDialog.Backend() {
            @Override
            public RoleImportResult preview(boolean applyChannels, boolean matchChannelsByName) throws ClientException {
                return rbac().importRoles(fileText, true, applyChannels, matchChannelsByName,
                        Collections.<Integer>emptyList(), null);
            }

            @Override
            public RoleImportResult apply(List<Integer> pick, String planToken, boolean applyChannels,
                    boolean matchChannelsByName) throws ClientException {
                return rbac().importRoles(fileText, false, applyChannels, matchChannelsByName, pick, planToken);
            }
        };
        background(() -> backend.preview(true, false), first -> {
            if (!first.isImportable()) {
                parent.alertError(parent, "This file can't be imported: " + first.getRefusal());
                return;
            }
            RoleImportDialog dialog = new RoleImportDialog(parent, first, backend);
            dialog.setVisible(true);
            if (dialog.getImportedCount() > 0) {
                parent.alertInformation(parent, "Imported " + dialog.getImportedCount() + " role(s).");
                refreshPanel.run();
            }
        });
    }

    // ========== Shared ==========

    /**
     * Shows a failed server call. A message the server wrote (a 400, 409 or 403) is shown
     * as is; anything else, such as a lost connection, goes to the engine's own handling.
     */
    static void report(Frame parent, Component owner, ClientException e) {
        String message = RoleImportText.serverMessage(e);
        if (message != null) {
            parent.alertError(owner, message);
        } else {
            parent.alertThrowable(owner, e);
        }
    }

    /** Runs {@code call} off the event thread, then {@code onSuccess} on it; a failure is reported. */
    private <T> void background(Callable<T> call, Consumer<T> onSuccess) {
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
                        report(parent, parent, (ClientException) e.getCause());
                    } else {
                        parent.alertThrowable(parent, e.getCause() != null ? e.getCause() : e);
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        }.execute();
    }
}
