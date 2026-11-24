// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import java.util.Locale;

/**
 * The characters a role name, permission or description can't hold, and how rbac writes names into the log. The
 * engine's log pattern writes messages as they are, so a line break in a name logged by rbac starts a new line in
 * mirth.log that reads like a real one. A character XML can't carry (a bell, U+0007) in a stored role name,
 * permission or description also makes the role list fail for both Administrators and stops role export.
 */
final class NameCharacters {

    private NameCharacters() {
    }

    /**
     * A control character (C0, delete, C1), the Unicode line or paragraph separator, or a Unicode bidirectional
     * control character (the Bidi_Control property: U+061C, U+200E, U+200F, U+202A to U+202E, U+2066 to U+2069).
     * A right-to-left override (U+202E) in a role name made the rest of its log line read reversed in a browser
     * and in the Administrator's Server Log (measured on OIE 4.7.0).
     */
    static boolean isUnsafe(int c) {
        return Character.isISOControl(c) || c == 0x2028 || c == 0x2029 || isBidiControl(c);
    }

    private static boolean isBidiControl(int c) {
        return c == 0x061C || c == 0x200E || c == 0x200F || (c >= 0x202A && c <= 0x202E)
                || (c >= 0x2066 && c <= 0x2069);
    }

    /** True when the value holds a character {@link #isUnsafe} rejects. */
    static boolean hasUnsafe(String value) {
        return value != null && value.codePoints().anyMatch(NameCharacters::isUnsafe);
    }

    /** True when XML 1.0 can't carry the value, so the role list and role export fail on it. */
    static boolean breaksXml(String value) {
        return value != null && !value.codePoints().allMatch(RoleTransferFormat::isXmlChar);
    }

    /** True for a value a new role name or a newly added permission may not have. */
    static boolean isRefused(String value) {
        return hasUnsafe(value) || breaksXml(value);
    }

    /**
     * True for a description a role may not be given: a control character other than a tab or a line break, or a
     * character XML can't carry. A description may run over several lines, and rbac doesn't log descriptions.
     */
    static boolean isRefusedInDescription(String value) {
        return value != null && value.codePoints().anyMatch(c -> !RoleTransferFormat.isXmlChar(c)
                || (Character.isISOControl(c) && c != '\t' && c != '\n' && c != '\r'));
    }

    /**
     * The value for a log line, with each unsafe character written visibly: {@code \n}, {@code \r},
     * {@code \t}, or {@code \}{@code uXXXX} for any other.
     */
    static String forLog(String value) {
        if (!hasUnsafe(value)) {
            return value;
        }
        StringBuilder out = new StringBuilder(value.length() + 8);
        value.codePoints().forEach(c -> {
            switch (c) {
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (isUnsafe(c)) {
                        out.append(String.format(Locale.ROOT, "\\u%04X", c));
                    } else {
                        out.appendCodePoint(c);
                    }
                }
            }
        });
        return out.toString();
    }
}
