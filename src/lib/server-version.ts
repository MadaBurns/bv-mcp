// SPDX-License-Identifier: BUSL-1.1

import pkg from '../../package.json';

/**
 * Server version — auto-synced from package.json at build time.
 *
 * Previously a hand-edited literal; the doc comment said "keep in sync with
 * package.json" but the manual step was forgotten through v3.3.5, v3.3.6, and
 * v3.3.7 — the MCP server kept advertising `version: "3.3.4"` in the
 * `initialize` response while the package shipped at 3.3.7. `resolveJsonModule`
 * is on in tsconfig, and esbuild (wrangler's bundler) inlines the import at
 * build time, so there's no runtime fs access.
 */
export const SERVER_VERSION: string = pkg.version;
