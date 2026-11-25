// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

/*
 * What the web role editor refuses before saving (rbac-core.js nameRefused, descriptionRefused, editorRefusal): the
 * server's rule, NameCharacters in the shared Java module. Both answer the cases in name-character-cases.txt;
 * the client module's NameCharacterCasesTest reads the same file.
 *
 * Run: npm test   (from webadmin/; node --test web/)
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {
    nameRefused, descriptionRefused, editorRefusal, MSG_NAME_CHARACTERS, MSG_DESCRIPTION_CHARACTERS
} from './rbac-core.js';

const BELL = String.fromCharCode(7);
const RLO = String.fromCharCode(0x202e);

function cases() {
    const text = fs.readFileSync(new URL('./name-character-cases.txt', import.meta.url), 'utf8');
    return text.split('\n').filter((line) => line.trim() && !line.startsWith('#')).map((line) => {
        const first = line.indexOf(' ');
        const second = line.indexOf(' ', first + 1);
        const value = line.slice(second + 1).replace(/\\u([0-9a-fA-F]{4})/g,
            (match, hex) => String.fromCharCode(parseInt(hex, 16)));
        return { line, field: line.slice(0, first), expected: line.slice(first + 1, second), value };
    });
}

test('the shared messages match the ones the web editor shows', () => {
    const messages = cases().filter((c) => c.field === 'message');
    assert.equal(messages.length, 2);
    for (const m of messages) {
        const shown = m.expected === 'name' ? MSG_NAME_CHARACTERS : MSG_DESCRIPTION_CHARACTERS;
        assert.equal(m.line, `message ${m.expected} ${shown}`);
    }
});

test('the shared cases get the expected answers', () => {
    const all = cases().filter((c) => c.field !== 'message');
    assert.ok(all.length >= 20, `read only ${all.length} cases`);
    const wrong = all.filter((c) => {
        const refused = c.field === 'name' ? nameRefused(c.value) : descriptionRefused(c.value);
        return refused !== (c.expected === 'refused');
    });
    assert.deepEqual(wrong.map((c) => c.line), []);
});

test('editorRefusal checks only a new or changed name or description', () => {
    assert.equal(editorRefusal(null, null, 'Lab' + String.fromCharCode(9) + 'X', ''), MSG_NAME_CHARACTERS);
    assert.equal(editorRefusal('Lab', 'd', 'Lab' + RLO + 'X', 'd'), MSG_NAME_CHARACTERS);
    assert.equal(editorRefusal('Lab' + RLO, 'd', 'Lab' + RLO, 'd'), null, 'an existing name is kept');
    assert.equal(editorRefusal('Lab', 'd', 'Lab', 'd' + BELL), MSG_DESCRIPTION_CHARACTERS);
    assert.equal(editorRefusal('Lab', 'd' + BELL, 'Lab', 'd' + BELL), null, 'an existing description is kept');
    assert.equal(editorRefusal(null, null, 'Lab', 'first\nsecond'), null);
});
