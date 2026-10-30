// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 * The server's answer to a role import: the preview of a dry run, or the
 * outcome of an apply.
 *
 * <p>When {@link #isImportable()} is {@code false} the whole file was refused,
 * {@link #getRefusal()} says why, and there are no rows. Otherwise there is one
 * row per role in the file, and an apply must send back {@link #getPlanToken()}
 * so the server can tell whether the roles changed since the preview.</p>
 */
public class RoleImportResult implements Serializable {

    private static final long serialVersionUID = 1L;

    private boolean importable;
    private String refusal;
    private String formatVersion;
    private String sourceRbacVersion;
    private String sourceEngineVersion;
    private boolean applyChannels;
    private boolean applied;
    private String planToken;
    private List<RoleImportRow> rows = new ArrayList<>();

    public boolean isImportable() {
        return importable;
    }

    public void setImportable(boolean importable) {
        this.importable = importable;
    }

    /** @return why the file was refused, or {@code null} when it is importable */
    public String getRefusal() {
        return refusal;
    }

    public void setRefusal(String refusal) {
        this.refusal = refusal;
    }

    /** @return the format version the file declares, or {@code null} if it couldn't be read */
    public String getFormatVersion() {
        return formatVersion;
    }

    public void setFormatVersion(String formatVersion) {
        this.formatVersion = formatVersion;
    }

    /** @return the rbac version that wrote the file */
    public String getSourceRbacVersion() {
        return sourceRbacVersion;
    }

    public void setSourceRbacVersion(String sourceRbacVersion) {
        this.sourceRbacVersion = sourceRbacVersion;
    }

    /** @return the engine version the file was written on */
    public String getSourceEngineVersion() {
        return sourceEngineVersion;
    }

    public void setSourceEngineVersion(String sourceEngineVersion) {
        this.sourceEngineVersion = sourceEngineVersion;
    }

    /** @return whether the file's channel restrictions are applied */
    public boolean isApplyChannels() {
        return applyChannels;
    }

    public void setApplyChannels(boolean applyChannels) {
        this.applyChannels = applyChannels;
    }

    /** @return {@code true} once the picked rows have been written; {@code false} for a dry run */
    public boolean isApplied() {
        return applied;
    }

    public void setApplied(boolean applied) {
        this.applied = applied;
    }

    public String getPlanToken() {
        return planToken;
    }

    public void setPlanToken(String planToken) {
        this.planToken = planToken;
    }

    public List<RoleImportRow> getRows() {
        return rows;
    }

    public void setRows(List<RoleImportRow> rows) {
        this.rows = rows;
    }
}
