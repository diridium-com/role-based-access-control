// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class NameCharactersTest {

    @Test
    void forLog_writesLineBreaksAndOtherControlCharactersVisibly() {
        assertEquals("a\\nb\\rc\\td", NameCharacters.forLog("a\nb\rc\td"));
        assertEquals("bell\\u0007perm", NameCharacters.forLog("bell\u0007perm"));
        assertEquals("next\\u0085line", NameCharacters.forLog("next\u0085line"));
        assertEquals("line\\u2028sep\\u2029par", NameCharacters.forLog("line\u2028sep\u2029par"));
    }

    @Test
    void forLog_leavesVisibleCharactersAlone() {
        String name = "Équipe Lab (read-only) / Billing & Ops 'Q4'";
        assertEquals(name, NameCharacters.forLog(name));
        assertNull(NameCharacters.forLog(null));
    }

    @Test
    void isRefused_controlCharactersLineSeparatorsAndWhatXmlCannotCarry() {
        assertTrue(NameCharacters.isRefused("Lab\nX"));
        assertTrue(NameCharacters.isRefused("Lab\tX"));
        assertTrue(NameCharacters.isRefused("Lab\u0085X"));
        assertTrue(NameCharacters.isRefused("Lab\u2028X"));
        assertTrue(NameCharacters.isRefused("Lab\uFFFEX"), "not a control character, but XML can't carry it");
        assertTrue(NameCharacters.isRefused("Lab\uD800X"), "a lone surrogate");
        assertFalse(NameCharacters.isRefused("Équipe Lab (read-only) / Billing & Ops"));
        assertFalse(NameCharacters.isRefused(null));
    }

    @Test
    void breaksXml_onlyForWhatTheRoleListAndExportCannotCarry() {
        assertTrue(NameCharacters.breaksXml("bell\u0007perm"));
        assertFalse(NameCharacters.breaksXml("Lab\nX"), "a line break is fine in XML; only the log needs escaping");
    }

    @Test
    void forLog_writesBidirectionalControlsVisibly() {
        assertEquals("probe bidi \\u202Enimda yb detaerc", NameCharacters.forLog("probe bidi \u202Enimda yb detaerc"));
        assertEquals("a\\u2066b\\u200Fc\\u061Cd", NameCharacters.forLog("a\u2066b\u200Fc\u061Cd"));
    }

    @Test
    void isRefused_bidirectionalControls_butNotRightToLeftLetters() {
        assertTrue(NameCharacters.isRefused("Lab\u202EX"));
        assertTrue(NameCharacters.isRefused("Lab\u2069X"));
        assertTrue(NameCharacters.isRefused("Lab\u200EX"));
        assertFalse(NameCharacters.isRefused("\u05E2\u05D1\u05E8\u05D9\u05EA"), "Hebrew letters are not controls");
    }

    @Test
    void isRefusedInDescription_allowsTabsAndLineBreaks_refusesOtherControlsAndWhatXmlCannotCarry() {
        assertFalse(NameCharacters.isRefusedInDescription("first line\r\nsecond\tline"));
        assertFalse(NameCharacters.isRefusedInDescription(null));
        assertTrue(NameCharacters.isRefusedInDescription("desc\u0007bell"));
        assertTrue(NameCharacters.isRefusedInDescription("desc\u0085next"));
        assertTrue(NameCharacters.isRefusedInDescription("desc\uFFFEx"));
    }
}
