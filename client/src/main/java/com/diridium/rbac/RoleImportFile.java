// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Reads a role import file as text. A file over 5 MB is refused before it is read, and a file
 * that isn't UTF-8 is refused rather than read with replacement characters, which the server
 * would accept as part of a name.
 */
final class RoleImportFile {

    /** 5 MB. The server refuses a file over 5 MB of characters, and UTF-8 never has fewer bytes. */
    static final long MAX_BYTES = 5L * 1024 * 1024;
    static final String TOO_LARGE = "This file is larger than 5 MB.";
    static final String NOT_UTF8 = "This file is not UTF-8 text.";

    /** A file the client refuses; the message is the text to show. */
    static final class Refused extends Exception {
        Refused(String message) {
            super(message);
        }
    }

    private RoleImportFile() {
    }

    /** The file's text, without a leading byte order mark. */
    static String read(Path file) throws IOException, Refused {
        checkSize(Files.size(file));
        return decode(Files.readAllBytes(file));
    }

    static void checkSize(long bytes) throws Refused {
        if (bytes > MAX_BYTES) {
            throw new Refused(TOO_LARGE);
        }
    }

    static String decode(byte[] bytes) throws Refused {
        String text;
        try {
            text = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes)).toString();
        } catch (CharacterCodingException e) {
            throw new Refused(NOT_UTF8);
        }
        return text.startsWith("\uFEFF") ? text.substring(1) : text;
    }
}
