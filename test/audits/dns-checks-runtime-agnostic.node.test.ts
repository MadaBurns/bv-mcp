// SPDX-License-Identifier: BUSL-1.1

/**
 * INVARIANT: `@blackveil/dns-checks` imports no Node built-in, ever.
 *
 * The package is consumed by workerd deployments that run WITHOUT the
 * `nodejs_compat` compatibility flag — this repo's own Worker is one of them
 * (`wrangler.jsonc` declares only `global_fetch_strictly_public`). A `node:` import
 * there is not a graceful degradation, it is a module-resolution failure at startup.
 * Nothing else catches it: typecheck resolves Node built-ins happily, and the unit
 * suite runs under Node/workerd-with-compat where they exist.
 *
 * This is why `cert/enrich.ts` takes a `DerKeyParser` as an INJECTED function rather
 * than importing `node:crypto` to decode an X.509 DER. If a future change
 * "simplifies" that injection into a direct import, this test is what fails.
 *
 * Runs in the NODE project (`vitest.node.config.mts`), not the workerd pool — it
 * walks the real filesystem, which the workerd virtual FS cannot do.
 */

import { describe, it, expect } from 'vitest';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';

const SRC_ROOT = resolve(__dirname, '../../packages/dns-checks/src');

/** Every shipped `.ts` under the package src/, excluding tests (which legitimately run under Node). */
function collectSourceFiles(dir: string, acc: string[] = []): string[] {
	for (const entry of readdirSync(dir)) {
		const full = join(dir, entry);
		if (statSync(full).isDirectory()) {
			if (entry === '__tests__') continue;
			collectSourceFiles(full, acc);
		} else if (entry.endsWith('.ts') && !entry.endsWith('.test.ts') && !entry.endsWith('.spec.ts')) {
			acc.push(full);
		}
	}
	return acc;
}

// Matches `from 'node:x'`, `import 'node:x'`, `require('node:x')`, dynamic `import('node:x')`.
const NODE_IMPORT = /(?:from|import|require)\s*\(?\s*['"]node:[^'"]+['"]/g;

describe('@blackveil/dns-checks runtime-agnostic boundary', () => {
	const files = collectSourceFiles(SRC_ROOT);

	it('finds source files to audit (guards against a silently empty sweep)', () => {
		// A collector that silently returned [] would make the assertion below pass
		// while checking nothing at all.
		expect(files.length).toBeGreaterThan(20);
	});

	it('imports no Node built-in anywhere in shipped package source', () => {
		const offenders: string[] = [];
		for (const file of files) {
			const matches = readFileSync(file, 'utf8').match(NODE_IMPORT);
			if (matches) offenders.push(`${relative(SRC_ROOT, file)}: ${matches.join(', ')}`);
		}
		expect(offenders).toEqual([]);
	});

	it('detects a node: import when one is present (proves the matcher discriminates)', () => {
		// A regex that matched nothing would produce the same green result above.
		expect("import { X509Certificate } from 'node:crypto';".match(NODE_IMPORT)).not.toBeNull();
		expect("const { readFile } = require('node:fs');".match(NODE_IMPORT)).not.toBeNull();
		expect("await import('node:path')".match(NODE_IMPORT)).not.toBeNull();
		// …and does not fire on prose or on a non-builtin specifier.
		expect("import { z } from 'zod';".match(NODE_IMPORT)).toBeNull();
		expect('// see node:crypto for why this decoder is injected'.match(NODE_IMPORT)).toBeNull();
	});
});
