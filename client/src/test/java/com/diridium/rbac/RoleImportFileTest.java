// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AccessDeniedException;
import java.nio.file.FileSystemException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;

import org.junit.jupiter.api.Test;

/**
 * The import file is refused over 5 MB before it is read, and refused when it isn't UTF-8; file
 * failures show their reason. The files are written under the module's target folder.
 */
class RoleImportFileTest {

    private static final byte[] BOM = {(byte) 0xEF, (byte) 0xBB, (byte) 0xBF};
    // "Rôle" as Windows-1252 writes it: 0xF4 alone is not UTF-8.
    private static final byte[] CP1252 = {'R', (byte) 0xF4, 'l', 'e'};

    private static Path file(String name, byte[] bytes) throws IOException {
        Path dir = Paths.get(System.getProperty("basedir", "."), "target", "role-import-file-test");
        Files.createDirectories(dir);
        return Files.write(dir.resolve(name), bytes);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] all = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, all, a.length, b.length);
        return all;
    }

    @Test
    void sizeLimitIsFiveMegabytes() throws Exception {
        RoleImportFile.checkSize(5_242_880L);
        RoleImportFile.Refused refused = assertThrows(RoleImportFile.Refused.class,
                () -> RoleImportFile.checkSize(5_242_881L));
        assertEquals("This file is larger than 5 MB.", refused.getMessage());
    }

    @Test
    void decode_utf8WithOrWithoutBom() throws Exception {
        byte[] utf8 = "<rbacRoles name=\"Café Québec\"/>".getBytes(StandardCharsets.UTF_8);
        assertEquals("<rbacRoles name=\"Café Québec\"/>", RoleImportFile.decode(utf8));
        assertEquals("<rbacRoles name=\"Café Québec\"/>", RoleImportFile.decode(concat(BOM, utf8)));
    }

    @Test
    void decode_refusesTextThatIsNotUtf8() {
        // Control: the lenient decode the client used before turns the byte into U+FFFD, which the server accepts.
        assertTrue(new String(CP1252, StandardCharsets.UTF_8).contains(String.valueOf((char) 0xFFFD)));
        RoleImportFile.Refused refused = assertThrows(RoleImportFile.Refused.class, () -> RoleImportFile.decode(CP1252));
        assertEquals("This file is not UTF-8 text.", refused.getMessage());
    }

    @Test
    void read_refusesALargeFileAndOneThatIsNotUtf8_andReadsTheRest() throws Exception {
        byte[] large = new byte[5_242_881];
        Arrays.fill(large, (byte) 'a');
        assertEquals("This file is larger than 5 MB.", assertThrows(RoleImportFile.Refused.class,
                () -> RoleImportFile.read(file("large.xml", large))).getMessage());
        assertEquals("This file is not UTF-8 text.", assertThrows(RoleImportFile.Refused.class,
                () -> RoleImportFile.read(file("cp1252.xml", CP1252))).getMessage());
        assertEquals("Lab", RoleImportFile.read(file("bom.xml", concat(BOM, "Lab".getBytes(StandardCharsets.UTF_8)))));
    }

    @Test
    void withReason_givesTheExceptionsReason() {
        assertEquals("File could not be written: No space left on device.",
                RoleImportText.withReason("File could not be written", new IOException("No space left on device")));
        assertEquals("Unable to read file: Is a directory.",
                RoleImportText.withReason("Unable to read file", new IOException("Is a directory.")));
        assertEquals("Unable to read file: AccessDeniedException: /home/u/roles.xml.",
                RoleImportText.withReason("Unable to read file", new AccessDeniedException("/home/u/roles.xml")),
                "a path alone is no reason: the class name says it");
        assertEquals("File could not be written: /x.xml: The process cannot access the file.",
                RoleImportText.withReason("File could not be written",
                        new FileSystemException("/x.xml", null, "The process cannot access the file")));
        assertEquals("Unable to read file: IOException.", RoleImportText.withReason("Unable to read file", new IOException()));
    }
}
