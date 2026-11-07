// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import java.nio.file.FileSystemException;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;

import com.mirth.connect.client.core.EntityException;
import com.mirth.connect.client.core.ForbiddenException;

/**
 * The wording and the small decisions of the role export and import dialogs, kept free of
 * Swing so they can be unit tested. The strings match the web administrator's.
 */
final class RoleImportText {

    static final String YES = "yes";
    static final String EVERY = "every";
    static final String NONE = "none";

    private RoleImportText() {
    }

    static String actionLabel(RoleImportRow.Action action) {
        if (action == null) {
            return "";
        }
        switch (action) {
            case CREATE:
                return "New";
            case OVERWRITE:
                return "Overwrite";
            case UNCHANGED:
                return "Unchanged";
            case SKIP:
                return "Skipped";
            default:
                return action.name();
        }
    }

    /** Only a New or an Overwrite row can be ticked. */
    static boolean tickable(RoleImportRow.Action action) {
        return action == RoleImportRow.Action.CREATE || action == RoleImportRow.Action.OVERWRITE;
    }

    /**
     * New starts ticked, Overwrite starts unticked; the rest can't be ticked.
     */
    static boolean defaultTicked(RoleImportRow row) {
        return row.getAction() == RoleImportRow.Action.CREATE;
    }

    /**
     * The ticks for a fresh preview of the same file: a row keeps the user's tick when the
     * row at the same position had the same name, action and no-channel-found state before;
     * any other row starts at its default, so a role whose channels are found once matching
     * by name is ticked again as a new role would be. The web administrator's mergeTicks
     * follows the same rule.
     */
    static boolean[] keepTicks(List<RoleImportRow> before, boolean[] tickedBefore, List<RoleImportRow> rows) {
        boolean[] ticked = new boolean[rows.size()];
        for (int i = 0; i < rows.size(); i++) {
            RoleImportRow row = rows.get(i);
            if (!tickable(row.getAction())) {
                continue;
            }
            ticked[i] = defaultTicked(row);
            for (int j = 0; j < before.size(); j++) {
                RoleImportRow old = before.get(j);
                if (old.getIndex() == row.getIndex()) {
                    if (Objects.equals(old.getName(), row.getName()) && old.getAction() == row.getAction()
                            && old.isNoChannelFound() == row.isNoChannelFound()) {
                        ticked[i] = tickedBefore[j];
                    }
                    break;
                }
            }
        }
        return ticked;
    }

    static String fromLine(RoleImportResult result) {
        return "From rbac " + orUnknown(result.getSourceRbacVersion())
                + " on OIE " + orUnknown(result.getSourceEngineVersion()) + ".";
    }

    /** The Notes cell: the server's text for the row, or empty when it has none. */
    static String notes(RoleImportRow row) {
        return row.getReason() == null ? "" : row.getReason();
    }

    /**
     * The line under the tick boxes saying how many channels in the import match a channel
     * on this engine only by name, or null when there is nothing to say (channel restrictions not
     * applied, no such channels, or the match-by-name box already ticked).
     */
    static String nameMatchHint(int count, boolean applyChannels, boolean matchByName) {
        if (!applyChannels || matchByName || count <= 0) {
            return null;
        }
        return (count == 1 ? "1 channel in the import matches a channel on this engine by name only."
                : count + " channels in the import match a channel on this engine by name only.")
                + " Tick the box above to use them.";
    }

    /** The hint for a preview, from the settings that preview was made with. */
    static String nameMatchHint(RoleImportResult result) {
        int count = result.getChannelNameMatches() == null ? 0 : result.getChannelNameMatches().size();
        return nameMatchHint(count, result.isApplyChannels(), result.isMatchChannelsByName());
    }

    /**
     * Whether the import dialog previews again after a failed apply: only when the server
     * answered with a message (a 400, 409 or 403). Anything else, such as a lost connection,
     * would fail the preview too.
     */
    static boolean previewAgainAfter(Throwable applyFailure) {
        return serverMessage(applyFailure) != null;
    }

    /** The row's permissions count: the file's count for a new role, else now, or "now → after" when it changes. */
    static String permissionsCountText(RoleImportRow row) {
        return countText(row, String.valueOf(list(row.getPermissionsNow()).size()),
                String.valueOf(list(row.getPermissionsAfter()).size()));
    }

    /** The row's channels count, with "every" for a role that sees every channel and "none" for one that sees none. */
    static String channelsCountText(RoleImportRow row) {
        String now = !row.isRestrictedNow() ? EVERY
                : list(row.getChannelsNow()).isEmpty() ? NONE : String.valueOf(list(row.getChannelsNow()).size());
        String after = !row.isRestrictedAfter() ? EVERY : usedCount(row) == 0 ? NONE : String.valueOf(usedCount(row));
        return countText(row, now, after);
    }

    /**
     * Joins a role's "now" and "after" counts: only the "after" for a role not here, only the
     * "now" for an Unchanged or Skipped row or when they are equal, else "now → after".
     */
    static String countText(RoleImportRow row, String now, String after) {
        if (!row.isExistsHere()) {
            return after;
        }
        RoleImportRow.Action action = row.getAction();
        if (action == RoleImportRow.Action.UNCHANGED || action == RoleImportRow.Action.SKIP || now.equals(after)) {
            return now;
        }
        return now + " → " + after;
    }

    /** Sorts count columns with {@link #compareCounts}. */
    static final Comparator<Object> COUNT_ORDER = (a, b) -> compareCounts((String) a, (String) b);

    /** Orders count texts by their first number, with "every" and "none" after any number, so "9" sorts before "10". */
    static int compareCounts(String a, String b) {
        int byFirst = Integer.compare(firstNumber(a), firstNumber(b));
        return byFirst != 0 ? byFirst : a.compareTo(b);
    }

    private static int firstNumber(String text) {
        String first = text.split(" ")[0];
        return first.matches("\\d+") ? Integer.parseInt(first) : Integer.MAX_VALUE;
    }

    private static boolean everyNow(RoleImportRow row) {
        return row.isExistsHere() && !row.isRestrictedNow();
    }

    private static boolean noneNow(RoleImportRow row) {
        return row.isExistsHere() && row.isRestrictedNow() && list(row.getChannelsNow()).isEmpty();
    }

    private static boolean everyAfter(RoleImportRow row) {
        return row.getAction() != RoleImportRow.Action.SKIP && !row.isRestrictedAfter();
    }

    private static boolean noneAfter(RoleImportRow row) {
        return row.getAction() != RoleImportRow.Action.SKIP && row.isRestrictedAfter() && usedCount(row) == 0;
    }

    private static int usedCount(RoleImportRow row) {
        int used = 0;
        for (RoleImportChannel channel : list(row.getChannelsAfter())) {
            if (channel.isUsed()) {
                used++;
            }
        }
        return used;
    }

    /**
     * The line above the channels table for a role that sees every channel or no channel
     * currently, after the import, or both; "" otherwise.
     */
    static String everyChannelText(RoleImportRow row) {
        String now = everyNow(row) ? "This role sees every channel currently."
                : noneNow(row) ? "This role sees no channels currently." : "";
        String after = everyAfter(row) ? "This role sees every channel after the import."
                : noneAfter(row) ? "This role sees no channels after the import." : "";
        return (now + " " + after).trim();
    }

    static <T> List<T> list(List<T> value) {
        return value == null ? Collections.<T>emptyList() : value;
    }

    static String text(String value) {
        return value == null ? "" : value;
    }

    /**
     * The text the server gave for a failed call, or null when the failure is not a server
     * answer with a message (a lost connection, say, which the caller hands to the
     * engine's own error handling). A 400 or 409 arrives as the cause's message; a 403's
     * reason is in the status line ("HTTP/1.1 403 Importing roles needs the admin role.").
     */
    static String serverMessage(Throwable t) {
        if (t instanceof ForbiddenException) {
            String reason = t.getMessage() == null ? "" : t.getMessage().replaceFirst("^HTTP/\\d(\\.\\d)? 403\\s*", "").trim();
            return reason.isEmpty() ? "You are not authorized to perform this action." : reason;
        }
        for (Throwable c = t; c != null; c = c.getCause()) {
            if (c instanceof EntityException && c.getMessage() != null && !c.getMessage().trim().isEmpty()) {
                return c.getMessage().trim();
            }
            if (c.getCause() == c) {
                break;
            }
        }
        return null;
    }

    /**
     * A file failure with its reason: {@code lead + ": " + reason + "."}. The reason is the
     * exception's message. A file system exception with no reason of its own carries only the
     * path, so its class name (AccessDeniedException, say) goes in front of it.
     */
    static String withReason(String lead, Exception e) {
        String message = e.getMessage() == null ? "" : e.getMessage().trim();
        String reason = message;
        if (message.isEmpty()) {
            reason = e.getClass().getSimpleName();
        } else if (e instanceof FileSystemException && ((FileSystemException) e).getReason() == null) {
            reason = e.getClass().getSimpleName() + ": " + message;
        }
        return lead + ": " + reason + (reason.endsWith(".") ? "" : ".");
    }

    private static String orUnknown(String value) {
        return value == null || value.isEmpty() ? "unknown" : value;
    }
}
