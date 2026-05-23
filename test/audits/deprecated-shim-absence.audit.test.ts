// SPDX-License-Identifier: BUSL-1.1

/**
 * Audit: the deprecated scoring/schema shim files (deleted in commits 86586f6,
 * c3ffb44, 7ff1dc0, 8c42263) must not be reintroduced. Each shim was a thin
 * re-export of the canonical `@blackveil/dns-checks/scoring` package or
 * `src/schemas/tool-definitions`; keeping them around drifts imports and
 * confuses contributors.
 *
 * NOTE: `src/lib/scoring-config.ts` is intentionally NOT in this list because
 * it still houses the project-local `parseScoringConfigCached` memoized
 * wrapper. See `src/lib/scoring-config.ts` for the surviving contract.
 *
 * Implementation note: `node:fs` existsSync is not reliable in the Cloudflare
 * Workers test pool. `import.meta.glob` with `query: '?raw'` is resolved by
 * Vite at build time against the real filesystem and works correctly inside the
 * Workers runtime without executing the imported modules.
 */

import { describe, it, expect } from 'vitest';

// Resolve filenames at Vite transform time via raw-string imports.
// Using `?raw` avoids executing the modules in the Workers runtime.
const handlerFiles = import.meta.glob('../../src/handlers/*.ts', {
	query: '?raw',
	import: 'default',
	eager: true,
}) as Record<string, string>;

const libFiles = import.meta.glob('../../src/lib/*.ts', {
	query: '?raw',
	import: 'default',
	eager: true,
}) as Record<string, string>;

const handlerNames = new Set(Object.keys(handlerFiles).map((p) => p.split('/').pop()!));
const libNames = new Set(Object.keys(libFiles).map((p) => p.split('/').pop()!));

const DELETED_SHIMS: Array<{ dir: 'handlers' | 'lib'; file: string }> = [
	{ dir: 'handlers', file: 'tool-schemas.ts' },
	{ dir: 'lib', file: 'context-profiles.ts' },
	{ dir: 'lib', file: 'scoring-engine.ts' },
	{ dir: 'lib', file: 'scoring-model.ts' },
];

describe('deprecated shim absence', () => {
	for (const { dir, file } of DELETED_SHIMS) {
		const rel = `src/${dir}/${file}`;
		it(`${rel} must not be reintroduced`, () => {
			const nameSet = dir === 'handlers' ? handlerNames : libNames;
			expect(nameSet.has(file)).toBe(false);
		});
	}
});
