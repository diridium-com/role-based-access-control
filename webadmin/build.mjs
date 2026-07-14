// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

import { build } from 'esbuild';

// Compile the web administrator UI (web/plugin.jsx + its imports -> web/plugin.js).
// The @oie/* packages stay external — the host resolves them at runtime to its one
// framework instance; React comes from platform.React. Everything else (the RBAC
// api / task-permission-map / roles-panel modules) is bundled in.
await build({
    entryPoints: ['web/plugin.jsx'],
    outfile: 'web/plugin.js',
    bundle: true,
    format: 'esm',
    target: 'es2022',
    jsx: 'transform',
    jsxFactory: 'React.createElement',
    jsxFragment: 'React.Fragment',
    external: ['@oie/web-api', '@oie/web-ui', '@oie/web-shell'],
});
console.log('built web/plugin.js');
