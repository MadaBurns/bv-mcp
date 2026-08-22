// SPDX-License-Identifier: BUSL-1.1

/**
 * Types for Vite's `?raw` import suffix, which several audits use to read
 * prose/config files as strings (the Workers pool has no filesystem, so
 * `?raw` is how a spec inspects README.md, server.json, smithery.yaml, etc.).
 *
 * Vite resolves these at build time, but `tsc` has no idea what `?raw` means,
 * so every such import raised TS2307. Those errors were simply banked into
 * `test/typecheck-baseline.json` — 8 for readme-tool-surface, 7 for
 * server-json-tool-count, and so on. Baselined noise is worse than it looks:
 * it raises a file's allowance, so a REAL type error in the same file can
 * appear without tripping the ratchet.
 *
 * Declaring the module shape fixes the whole class at once instead.
 */

declare module '*?raw' {
	const content: string;
	export default content;
}
