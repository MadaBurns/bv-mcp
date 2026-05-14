#!/usr/bin/env node
/**
 * Regenerates packages/dns-checks/src/__tests__/fixtures/whois/index.ts from
 * the *.txt files in that directory. Run whenever a fixture is added or edited.
 *
 * Usage:
 *   node packages/dns-checks/scripts/regen-whois-fixtures.mjs
 *
 * Why a TS index instead of fs.readFileSync at test runtime:
 *   The root vitest config runs tests in the Cloudflare workers pool which has
 *   no fs access to the workspace tree. Inlining as TS string constants makes
 *   the parser tests pool-agnostic (run via root `npm test` AND per-workspace).
 */

import { readdirSync, readFileSync, writeFileSync } from 'fs';
import { join } from 'path';

const dir = 'packages/dns-checks/src/__tests__/fixtures/whois';
const files = readdirSync(dir).filter(f => f.endsWith('.txt')).sort();

const out = [
	'// SPDX-License-Identifier: BUSL-1.1',
	'// Auto-generated from packages/dns-checks/src/__tests__/fixtures/whois/*.txt — do not edit by hand.',
	'// Regenerate with: node packages/dns-checks/scripts/regen-whois-fixtures.mjs',
	'',
	'export const WHOIS_FIXTURES = {',
];

for (const f of files) {
	const key = f.replace(/[-.]/g, '_');
	const content = readFileSync(join(dir, f), 'utf8');
	out.push(`  ${JSON.stringify(key)}: ${JSON.stringify(content)},`);
}

out.push('} as const;');
out.push('');

writeFileSync(join(dir, 'index.ts'), out.join('\n'));
console.log(`Regenerated ${files.length} WHOIS fixtures → ${dir}/index.ts`);
