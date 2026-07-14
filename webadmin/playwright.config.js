// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

/*
 * Mock e2e for the rbac web administrator plugin. Boots the oie-web-client
 * host (Node server; /api is mocked in-browser by e2e/mock.js, so no engine is
 * needed) and loads the REAL built web/plugin.js the way an engine would serve
 * it. Point WEBADMIN_DIR at your oie-web-client checkout if it is not the
 * sibling of this repository.
 *
 *   WEBADMIN_DIR=~/src/oie-web-client npx playwright test
 */

import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig, devices } from '@playwright/test';

const HERE = path.dirname(fileURLToPath(import.meta.url));
// Default: the oie-web-client checkout next to this repository.
const WEBADMIN_DIR = process.env.WEBADMIN_DIR
    || path.resolve(HERE, '..', '..', 'oie-web-client');

// A port of our own so a dev server on the default 3030 never clashes.
const PORT = Number(process.env.WEBADMIN_PORT || 3131);
const BASE_URL = `http://localhost:${PORT}`;

export default defineConfig({
    testDir: './e2e',
    fullyParallel: false,
    forbidOnly: !!process.env.CI,
    retries: 1,
    // The suite shares ONE host server (same rationale as the host's own e2e).
    workers: 1,
    reporter: process.env.CI ? 'github' : 'list',
    use: {
        baseURL: BASE_URL,
        trace: 'on-first-retry',
    },
    // Boot the host web administrator. With /api mocked it needs no engine.
    webServer: {
        command: `npm start --prefix ${JSON.stringify(path.join(WEBADMIN_DIR, 'web-administrator'))}`,
        url: BASE_URL,
        reuseExistingServer: !process.env.CI,
        timeout: 60_000,
        env: { ...process.env, WEBADMIN_PORT: String(PORT) },
    },
    projects: [
        { name: 'ui', use: { ...devices['Desktop Chrome'] } },
    ],
});
