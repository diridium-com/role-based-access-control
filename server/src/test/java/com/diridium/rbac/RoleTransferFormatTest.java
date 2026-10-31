// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

import com.diridium.rbac.RoleTransferFormat.Channel;
import com.diridium.rbac.RoleTransferFormat.ExportFile;
import com.diridium.rbac.RoleTransferFormat.ExportedRole;
import com.diridium.rbac.RoleTransferFormat.Refusal;

/**
 * Tests the role export file format: what is written reads back exactly, and every
 * file format 1 doesn't define is refused with a reason rather than partly read.
 */
class RoleTransferFormatTest {

    private static final String HEADER = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            + "<rbacRoles formatVersion=\"1\" rbacVersion=\"1.3.0\" engineVersion=\"4.7.0\">\n";

    private static final String LAB = "<role><name>Lab</name><description>d</description>"
            + "<permissions><permission>viewChannels</permission></permissions>"
            + "<channels restricted=\"true\"><channel id=\"c1\" name=\"Lab In\"/></channels></role>";

    // ========== Round trip ==========

    @Test
    void writtenFile_readsBackExactly() throws Exception {
        String awkward = "A & B <c> \"d\" 'e'\ttab\nline\r\nCRLF é 😀";
        List<ExportedRole> roles = List.of(
                new ExportedRole(" Lab users ", awkward, List.of("viewChannels", "Search Source Code"), true,
                        List.of(new Channel("c1", awkward), new Channel("c2", ""))),
                new ExportedRole("Everyone", null, List.of(), false, List.of()));

        ExportFile file = RoleTransferFormat.parse(RoleTransferFormat.write("1.3.0", "4.7.0", roles));

        assertEquals("1", file.formatVersion());
        assertEquals("1.3.0", file.rbacVersion());
        assertEquals("4.7.0", file.engineVersion());
        assertEquals(2, file.roles().size());
        ExportedRole lab = file.roles().get(0);
        assertEquals(" Lab users ", lab.name());
        assertEquals(awkward, lab.description());
        assertEquals(List.of("viewChannels", "Search Source Code"), lab.permissions());
        assertTrue(lab.restricted());
        assertEquals(List.of(new Channel("c1", awkward), new Channel("c2", "")), lab.channels());
        ExportedRole everyone = file.roles().get(1);
        assertEquals("", everyone.description(), "a null description is written as empty");
        assertEquals(List.of(), everyone.permissions());
        assertFalse(everyone.restricted());
        assertEquals(List.of(), everyone.channels());
    }

    @Test
    void write_refusesACharacterXmlCannotCarry_namingTheRole() {
        List<ExportedRole> roles = List.of(new ExportedRole("Lab", "bell \u0007", List.of(), false, List.of()));
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> RoleTransferFormat.write("1.3.0", "4.7.0", roles));
        assertEquals("The role 'Lab' has a character a role export file can't hold, in its description.",
                e.getMessage());
        assertTrue(e.getCause() instanceof IllegalArgumentException, "the cause is kept");
    }

    @Test
    void read_acceptsCommentsWhitespaceCdataAndAByteOrderMark() throws Exception {
        String text = "\uFEFF" + HEADER + "<!-- exported for the lab -->\n"
                + "<role>\n <name>Lab</name>\n <description><![CDATA[a < b]]></description>\n"
                + " <permissions/>\n <channels restricted=\"false\"/>\n</role>\n</rbacRoles>";
        ExportedRole role = RoleTransferFormat.parse(text).roles().get(0);
        assertEquals("a < b", role.description());
    }

    @Test
    void read_aMissingDescriptionIsEmpty() throws Exception {
        String text = HEADER + "<role><name>Lab</name><permissions/><channels restricted=\"false\"/></role></rbacRoles>";
        assertEquals("", RoleTransferFormat.parse(text).roles().get(0).description());
    }

    // ========== Version ==========

    @Test
    void newerFormat_isRefusedAsNewer_beforeAnyOtherCheck() {
        String text = "<rbacRoles formatVersion=\"2\" rbacVersion=\"1.4.0\" engineVersion=\"4.8.0\" newThing=\"x\">"
                + "<role><name>Lab</name><somethingNew/></role></rbacRoles>";
        assertRefused(text, "This file is format 2, written by rbac 1.4.0. This rbac reads format 1.");
    }

    @Test
    void missingFormatVersion_isRefused() {
        assertRefused("<rbacRoles rbacVersion=\"1.3.0\" engineVersion=\"4.7.0\">" + LAB + "</rbacRoles>",
                "doesn't say which format version");
    }

    @Test
    void missingRbacOrEngineVersion_isRefused() {
        assertRefused("<rbacRoles formatVersion=\"1\" engineVersion=\"4.7.0\">" + LAB + "</rbacRoles>",
                "without its rbacVersion attribute");
        assertRefused("<rbacRoles formatVersion=\"1\" rbacVersion=\"1.3.0\">" + LAB + "</rbacRoles>",
                "without its engineVersion attribute");
    }

    // ========== Undefined content ==========

    @Test
    void wrongTopElement_isRefused() {
        assertRefused("<channels/>", "its top element is <channels>");
    }

    @Test
    void undefinedAttributes_areRefused() {
        assertRefused("<rbacRoles formatVersion=\"1\" rbacVersion=\"1\" engineVersion=\"4\" extra=\"x\">" + LAB
                + "</rbacRoles>", "the attribute extra on <rbacRoles>");
        assertRefused("<rbacRoles xmlns=\"urn:x\" formatVersion=\"1\" rbacVersion=\"1\" engineVersion=\"4\">" + LAB
                + "</rbacRoles>", "the attribute xmlns on <rbacRoles>");
        assertRefused(HEADER + LAB.replace("name=\"Lab In\"", "name=\"Lab In\" port=\"1\"") + "</rbacRoles>",
                "the attribute port on <channel>");
        assertRefused(HEADER + LAB.replace("<name>", "<name lang=\"en\">") + "</rbacRoles>",
                "the attribute lang on <name>");
    }

    @Test
    void undefinedElements_areRefused() {
        assertRefused(HEADER + "<group/>" + "</rbacRoles>", "<group> in <rbacRoles>");
        assertRefused(HEADER + LAB.replace("<description>", "<owner>x</owner><description>") + "</rbacRoles>",
                "<owner> in role 1");
        assertRefused(HEADER + LAB.replace("<permission>viewChannels</permission>", "<grant>x</grant>")
                + "</rbacRoles>", "<grant> in the role 'Lab'");
        assertRefused(HEADER + LAB.replace("<name>Lab</name>", "<name>Lab<b/></name>") + "</rbacRoles>",
                "<b> in role 1");
    }

    @Test
    void textWhereTheFormatHasNone_isRefused() {
        assertRefused(HEADER + LAB.replace("<permissions>", "<permissions>loose text") + "</rbacRoles>",
                "text inside <permissions>");
        assertRefused(HEADER + LAB.replace("name=\"Lab In\"/>", "name=\"Lab In\">x</channel>") + "</rbacRoles>",
                "text inside <channel>");
    }

    // ========== Required fields ==========

    @Test
    void missingRequiredFields_areRefused() {
        assertRefused(HEADER + LAB.replace("<name>Lab</name>", "") + "</rbacRoles>", "role 1 has no <name>");
        assertRefused(HEADER + LAB.replace("<permissions><permission>viewChannels</permission></permissions>", "")
                + "</rbacRoles>", "the role 'Lab' has no <permissions>");
        assertRefused(HEADER + LAB.replaceAll("<channels.*</channels>", "") + "</rbacRoles>",
                "the role 'Lab' has no <channels>");
        assertRefused(HEADER + LAB.replace(" restricted=\"true\"", "") + "</rbacRoles>",
                "<channels> without its restricted attribute");
        assertRefused(HEADER + LAB.replace(" name=\"Lab In\"", "") + "</rbacRoles>",
                "<channel> without its name attribute");
    }

    @Test
    void repeatedOrEmptyFields_areRefused() {
        assertRefused(HEADER + LAB.replace("<name>Lab</name>", "<name>Lab</name><name>Lab2</name>") + "</rbacRoles>",
                "more than one <name>");
        assertRefused(HEADER + LAB.replace("<name>Lab</name>", "<name>  </name>") + "</rbacRoles>",
                "has an empty name");
        assertRefused(HEADER + LAB.replace("viewChannels</permission>", "viewChannels</permission>"
                + "<permission>viewChannels</permission>") + "</rbacRoles>", "lists the permission 'viewChannels' twice");
        assertRefused(HEADER + LAB.replace("viewChannels", " ") + "</rbacRoles>", "has an empty permission");
        assertRefused(HEADER + LAB.replace("id=\"c1\"", "id=\"\"") + "</rbacRoles>", "has an empty id");
        assertRefused(HEADER + LAB.replace("<channel id=\"c1\" name=\"Lab In\"/>",
                "<channel id=\"c1\" name=\"Lab In\"/><channel id=\"c1\" name=\"Again\"/>") + "</rbacRoles>",
                "lists the channel c1 twice");
    }

    @Test
    void lengthsOverTheColumnSizes_areRefused() {
        assertRefused(HEADER + LAB.replace("<name>Lab</name>", "<name>" + "n".repeat(256) + "</name>") + "</rbacRoles>",
                "a name longer than 255");
        assertRefused(HEADER + LAB.replace("viewChannels", "p".repeat(256)) + "</rbacRoles>",
                "a permission longer than 255");
        assertRefused(HEADER + LAB.replace("<description>d</description>", "<description>" + "d".repeat(1025)
                + "</description>") + "</rbacRoles>", "a description longer than 1024");
        // At the limits, accepted.
        assertAccepted(HEADER + LAB.replace("<name>Lab</name>", "<name>" + "n".repeat(255) + "</name>")
                .replace("<description>d</description>", "<description>" + "d".repeat(1024) + "</description>")
                + "</rbacRoles>");
    }

    @Test
    void channelRestrictions_mustBeConsistent() {
        assertRefused(HEADER + LAB.replace("<channel id=\"c1\" name=\"Lab In\"/>", "") + "</rbacRoles>",
                "restricted to channels but lists none");
        assertRefused(HEADER + LAB.replace("restricted=\"true\"", "restricted=\"false\"") + "</rbacRoles>",
                "sees every channel (restricted=\"false\") but also lists channels");
        assertRefused(HEADER + LAB.replace("restricted=\"true\"", "restricted=\"yes\"") + "</rbacRoles>",
                "it must be true or false");
    }

    @Test
    void duplicateRoleNames_areRefused() {
        assertRefused(HEADER + LAB + LAB + "</rbacRoles>", "The file has more than one role named 'Lab'.");
    }

    @Test
    void namesThatDifferOnlyInCase_areTwoRoles() throws Exception {
        // Postgres, Derby and Oracle hold them as two roles, so their export has to read back.
        ExportFile file = RoleTransferFormat.parse(
                HEADER + LAB + LAB.replace("<name>Lab</name>", "<name>LAB</name>") + "</rbacRoles>");
        assertEquals(List.of("Lab", "LAB"), file.roles().stream().map(ExportedRole::name).toList());
    }

    @Test
    void aFileWithNoRoles_isRefused() {
        assertRefused(HEADER + "</rbacRoles>", "The file has no roles.");
    }

    // ========== Damaged and hostile files ==========

    @Test
    void emptyOrOversizedOrDamagedFiles_areRefused() {
        assertRefused("", "The file is empty.");
        assertRefused("  \n", "The file is empty.");
        assertRefused("x".repeat(RoleTransferFormat.MAX_CHARS + 1), "larger than 5 MB");
        assertRefused("not xml at all", "isn't well-formed XML");
        assertRefused(HEADER + LAB, "isn't well-formed XML");
        assertRefused(HEADER + LAB.replace("<description>d", "<description>&undeclared;") + "</rbacRoles>",
                "isn't well-formed XML");
    }

    @Test
    void xml11_isRefused() {
        // XML 1.1 can carry a bell character, which XML 1.0, and so an export, can't.
        assertRefused(HEADER.replace("version=\"1.0\"", "version=\"1.1\"")
                + LAB.replace(">d<", ">&#x7;<") + "</rbacRoles>",
                "The file is XML 1.1. Role export files are XML 1.0.");
    }

    @Test
    void aDoctype_isRefused() {
        assertRefused("<!DOCTYPE rbacRoles>" + HEADER.substring(HEADER.indexOf("<rbacRoles")) + LAB + "</rbacRoles>",
                "The file has a DOCTYPE.");
    }

    @Test
    void anExternalEntity_isRefusedWithoutBeingRead() {
        String xxe = "<?xml version=\"1.0\"?>\n<!DOCTYPE rbacRoles [<!ENTITY secret SYSTEM \"file:///etc/passwd\">]>\n"
                + HEADER.substring(HEADER.indexOf("<rbacRoles")) + LAB.replace(">d<", ">&secret;<") + "</rbacRoles>";
        assertRefused(xxe, "The file has a DOCTYPE.");
    }

    @Test
    void entityExpansion_isRefused() {
        StringBuilder laughs = new StringBuilder("<?xml version=\"1.0\"?>\n<!DOCTYPE rbacRoles [<!ENTITY a0 \"lol\">");
        for (int i = 1; i <= 10; i++) {
            laughs.append("<!ENTITY a").append(i).append(" \"").append(("&a" + (i - 1) + ";").repeat(10)).append("\">");
        }
        laughs.append("]>\n").append(HEADER.substring(HEADER.indexOf("<rbacRoles")))
                .append(LAB.replace(">d<", ">&a10;<")).append("</rbacRoles>");
        assertRefused(laughs.toString(), "The file has a DOCTYPE.");
    }

    private static void assertRefused(String text, String expected) {
        Refusal refusal = assertThrows(Refusal.class, () -> RoleTransferFormat.parse(text));
        assertTrue(refusal.getMessage().contains(expected),
                "expected the refusal to contain [" + expected + "] but it was [" + refusal.getMessage() + "]");
    }

    private static void assertAccepted(String text) {
        try {
            RoleTransferFormat.parse(text);
        } catch (Refusal e) {
            throw new AssertionError("refused: " + e.getMessage(), e);
        }
    }
}
