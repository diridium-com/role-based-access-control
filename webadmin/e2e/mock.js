// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

/*
 * Vendored mock-engine harness (trimmed from oie-web-client e2e/mock.js):
 * intercept every /api/* request in the browser and fulfill it from fixtures,
 * so the web administrator runs end-to-end with no engine. Unmatched calls
 * return an empty body (parseBody → null → asList → []) so the app never hangs
 * or crashes on a call a test didn't anticipate.
 *
 * mockEngineWithRbac() additionally serves THIS plugin's real built bundle the
 * way a live engine would (the oie-web-client engine-plugins.spec.js pattern):
 * GET /webplugins discovery lists 'rbac', the manifest is ../plugin.json, and
 * the entry module is ../web/plugin.js read from disk — so the specs exercise
 * the actual shipped code, not a stub.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DEFAULT_FIXTURES } from './fixtures.js';

const WEB_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const PLUGIN_MANIFEST = JSON.parse(fs.readFileSync(path.join(WEB_DIR, 'plugin.json'), 'utf8'));
const PLUGIN_JS = fs.readFileSync(path.join(WEB_DIR, 'web', 'plugin.js'), 'utf8');

export async function mockEngine(page, overrides = {}) {
    const fixtures = { ...DEFAULT_FIXTURES, ...overrides };
    const patterns = Object.keys(fixtures).filter((k) => k.includes('*'));

    await page.route('**/api/**', async (route) => {
        const req = route.request();
        const path = new URL(req.url()).pathname.replace(/^\/api/, '');
        const key = `${req.method()} ${path}`;

        let fx = fixtures[key];
        if (fx === undefined) {
            for (const p of patterns) {
                const [method, pat] = p.split(' ');
                if (method !== req.method()) continue;
                const re = new RegExp('^' + pat.replace(/[.]/g, '\\.').replace(/\*/g, '[^/]+') + '$');
                if (re.test(path)) { fx = fixtures[p]; break; }
            }
        }

        if (typeof fx === 'function') fx = fx(req);
        if (fx === undefined) {
            return route.fulfill({ status: 200, contentType: 'text/plain', body: '' });
        }
        if (typeof fx === 'string') {
            return route.fulfill({ status: 200, contentType: 'text/plain', body: fx });
        }
        if (fx && fx.__status) {
            return route.fulfill({ status: fx.__status, contentType: 'application/json', body: JSON.stringify(fx.body ?? {}) });
        }
        return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(fx) });
    });
}

/**
 * mockEngine + the engine-served rbac web plugin. `overrides` should include
 * the /extensions/rbac fixtures for the profile under test (see
 * fixtures.rbacFixtures()).
 */
export async function mockEngineWithRbac(page, overrides = {}) {
    await mockEngine(page, {
        // Discovery: the engine ships one extension with a web half.
        'GET /webplugins': ['rbac'],
        // Its manifest, served raw by the engine — the REAL plugin.json.
        'GET /webplugins/rbac/plugin.json': PLUGIN_MANIFEST,
        ...overrides
    });
    // The plugin's ES-module entry: the REAL built bundle, served from disk.
    // Registered AFTER mockEngine so this route wins, with a real JavaScript
    // MIME type (import() refuses to execute a text/plain module). Trailing *
    // tolerates a dev server's `?import` query.
    await page.route('**/api/webplugins/rbac/web/plugin.js*', (route) => route.fulfill({
        status: 200, contentType: 'text/javascript', body: PLUGIN_JS
    }));
}

/** Sign in through the real login form (used when /users/current → 401). */
export async function login(page, username = 'admin', password = 'admin') {
    await page.getByPlaceholder('admin').fill(username);
    await page.locator('input[type=password]').fill(password);
    await page.getByRole('button', { name: 'Sign in' }).click();
}
