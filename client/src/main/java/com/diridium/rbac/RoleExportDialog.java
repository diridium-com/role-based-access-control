// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;

import com.mirth.connect.client.ui.Frame;

/**
 * Modal dialog to pick the roles to export. Every role starts ticked; Export is disabled
 * while none is. The caller passes the roles without the admin role, which is never exported.
 */
public class RoleExportDialog extends JDialog {

    private final Map<Role, JCheckBox> boxes = new LinkedHashMap<>();
    private final JButton exportButton = new JButton("Export");
    private List<Integer> result;

    /**
     * @param parent the owning frame
     * @param roles  the roles to offer, none of them the admin role
     */
    public RoleExportDialog(Frame parent, List<Role> roles) {
        super(parent, "Export Roles", true);

        JPanel list = new JPanel();
        list.setLayout(new BoxLayout(list, BoxLayout.Y_AXIS));
        list.setBorder(BorderFactory.createEmptyBorder(4, 8, 4, 8));
        for (Role role : roles) {
            JCheckBox box = new JCheckBox(role.getName(), true);
            box.addActionListener(e -> updateExportEnabled());
            boxes.put(role, box);
            list.add(box);
        }
        JScrollPane scroll = new JScrollPane(list);
        scroll.setPreferredSize(new java.awt.Dimension(360, 240));

        JLabel prompt = new JLabel("Pick the roles to export. The admin role is never exported.");
        prompt.setBorder(BorderFactory.createEmptyBorder(8, 8, 4, 8));

        exportButton.addActionListener(e -> {
            result = new ArrayList<>();
            for (Map.Entry<Role, JCheckBox> entry : boxes.entrySet()) {
                if (entry.getValue().isSelected()) {
                    result.add(entry.getKey().getId());
                }
            }
            dispose();
        });
        JButton cancelButton = new JButton("Cancel");
        cancelButton.addActionListener(e -> dispose());
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        buttons.add(exportButton);
        buttons.add(cancelButton);

        add(prompt, BorderLayout.NORTH);
        add(scroll, BorderLayout.CENTER);
        add(buttons, BorderLayout.SOUTH);
        getRootPane().setDefaultButton(exportButton);
        pack();
        setLocationRelativeTo(parent);
        updateExportEnabled();
    }

    private void updateExportEnabled() {
        exportButton.setEnabled(boxes.values().stream().anyMatch(JCheckBox::isSelected));
    }

    /** @return the ids of the ticked roles, or {@code null} if the user cancelled */
    public List<Integer> getResult() {
        return result;
    }
}
