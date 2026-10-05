// SPDX-License-Identifier: BUSL-1.1

/**
 * Fence audit for the RESERVED registry schema (SQ-178 decision, 2026-09-24;
 * delivered by SQ-210).
 *
 * Two parts of the shared registry D1 look like data sources and are not:
 *
 *   - `tenant_keys.last_used_at` is NOT TRACKED. Key auth does not read
 *     `tenant_keys` at all today (`src/tenants/tenant-resolver.ts` :148 TODO), so
 *     NULL is never evidence a key is unused. Using it for rotation or dormancy
 *     decisions would retire live keys.
 *   - `billing_events` is reserved. bv-mcp never writes it; the billing SSOT is
 *     bv-web-prod, so an empty table does not mean no billing.
 *
 * This audit fails on any reference to `last_used_at` / `lastUsedAt`,
 * `billing_events` / `billingEvents`, or the `tenant_keys` / `tenantKeys` table
 * outside an allowlist, unless the referencing line carries a design-note pointer
 * (`SQ-178`). Wiring any of these up is a design decision: either extend the
 * allowlist here with a stated reason, or carry the pointer on the line.
 *
 * What counts as a reference: a LEXICAL match, per line. Pure comment lines in
 * code files are not references (prose about the tables is neither a read nor a
 * write); markdown has no comment rule and needs the pointer.
 *
 * CONTROL STRENGTH. Both positive controls below are caught by the lexical match,
 * so this is not a partial control for them:
 *   1. a named-column writer (`UPDATE tenant_keys SET last_used_at = ...`);
 *   2. a Drizzle full-row read (`db.select().from(tenantKeys)`). Reading the table
 *      through Drizzle requires naming the `tenantKeys` identifier somewhere (an
 *      import, or a `schema.tenantKeys` member access), and that token is the match.
 * Residual evasions a grep cannot see, deliberately not claimed as covered:
 * computed access (`registry['tenant' + 'Keys']`), enumerating the whole schema
 * namespace (`Object.values(registry)`), and SQL assembled from fragments. Those
 * are code-review territory. The fixtures below are in-memory strings, never files.
 *
 * Runs in the Workers pool: the sources arrive via Vite `import.meta.glob(?raw)`,
 * so no filesystem is needed. CHANGELOG.md is not scanned (a historical record
 * that legitimately names the tables); `docs/**` is, minus the gitignored
 * `docs/{plans,code-review,superpowers}` local-notes directories.
 */

import { describe, expect, it } from 'vitest';

/**
 * Vite injects `import.meta.glob`, but the test tree's `tsconfig` does not pull in
 * `vite/client`, so `ImportMeta` has no `glob` member. Narrowing through this local
 * interface keeps the file at zero type errors under the `typecheck:tests` ratchet.
 */
interface GlobbingImportMeta {
	glob(patterns: string[], options: { eager: true; query: '?raw'; import: 'default' }): Record<string, string>;
}

const RAW_SOURCES = (import.meta as unknown as GlobbingImportMeta).glob(
	[
		'../../src/**/*.{ts,mjs,js,sql}',
		'../../scripts/**/*.{ts,mjs,js,py,sql}',
		'../../test/**/*.{ts,mjs,js}',
		'../../packages/*/src/**/*.{ts,js}',
		'../../docs/**/*.md',
		// Gitignored + pre-commit-blocked local notes: never tracked, so never shipped. Vite's
		// glob ignores .gitignore, so without these exclusions the fence fails on any checkout
		// that holds them (and on Sidequest's merged-tree verification of the shared checkout).
		'!../../docs/plans/**',
		'!../../docs/code-review/**',
		'!../../docs/superpowers/**',
		'!**/node_modules/**',
	],
	{ eager: true, query: '?raw', import: 'default' },
);

/**
 * Vite keys each glob hit relative to THIS file and collapses the path to its shortest
 * form (`../../test/x.ts` becomes `../x.ts`), so resolve against `test/audits/` instead of
 * stripping `../` blindly.
 */
function repoRelative(globKey: string): string {
	const parts = ['test', 'audits'];
	for (const seg of globKey.split('/')) {
		if (seg === '..') parts.pop();
		else if (seg !== '.') parts.push(seg);
	}
	return parts.join('/');
}

/** Repo-root-relative path -> source text. */
const TREE: Record<string, string> = Object.fromEntries(Object.entries(RAW_SOURCES).map(([k, v]) => [repoRelative(k), v]));

const RESERVED_SOURCE = 'last_used_at|lastUsedAt|billing_events|billingEvents|tenant_keys|tenantKeys';
const DESIGN_NOTE_POINTER = /SQ-178/;
const THIS_FILE = 'test/audits/tenant-reserved-schema.audit.test.ts';

/**
 * Paths where every reserved token is expected. Each entry is an exact path or a
 * directory prefix (ending in `/`).
 */
const FULL_ALLOWLIST: readonly string[] = [
	'src/tenants/db/schema/registry.ts', // the schema itself
	'src/tenants/db/migrations/', // generated SQL + meta snapshots
	'test/tenants/db/registry-schema.spec.ts', // schema shape spec
	'test/tenants/tenant-d1.spec.ts', // registry D1 integration spec
	THIS_FILE, // fixtures and the pattern above
];

/**
 * Existing legitimate references that are not comments, each tolerated for ONLY the
 * tokens listed, so a `last_used_at` / `billing_events` reference can never hide
 * behind them.
 */
const NARROW_ALLOWLIST: ReadonlyArray<{ path: string; tokens: RegExp; reason: string }> = [
	{
		path: 'scripts/tenants/provision-tenant.mjs',
		tokens: /^tenant_keys$/,
		reason: 'provisioning INSERTs a key row (key_hash, super_tenant_id, sub_tenant_id, scope only)',
	},
	{
		path: 'test/tenants/db/tenant-schema.spec.ts',
		tokens: /^(tenantKeys|billingEvents)$/,
		reason: 'asserts the registry schema module still exports the tables',
	},
];

interface Violation {
	file: string;
	line: number;
	token: string;
	text: string;
}

function isFullyAllowed(file: string): boolean {
	return FULL_ALLOWLIST.some((entry) => (entry.endsWith('/') ? file.startsWith(entry) : file === entry));
}

function isCommentOnly(file: string, line: string): boolean {
	if (file.endsWith('.md')) return false;
	if (file.endsWith('.py')) return /^\s*#/.test(line);
	if (file.endsWith('.sql')) return /^\s*--/.test(line);
	return /^\s*(\/\/|\/\*|\*)/.test(line);
}

function findViolations(tree: Record<string, string>): Violation[] {
	const out: Violation[] = [];
	for (const [file, text] of Object.entries(tree)) {
		if (isFullyAllowed(file)) continue;
		const narrow = NARROW_ALLOWLIST.find((n) => n.path === file);
		const lines = text.split('\n');
		for (let i = 0; i < lines.length; i++) {
			const line = lines[i];
			const tokens = line.match(new RegExp(RESERVED_SOURCE, 'g'));
			if (!tokens) continue;
			if (DESIGN_NOTE_POINTER.test(line) || isCommentOnly(file, line)) continue;
			for (const token of tokens) {
				if (narrow?.tokens.test(token)) continue;
				out.push({ file, line: i + 1, token, text: line.trim().slice(0, 140) });
			}
		}
	}
	return out;
}

describe('reserved registry schema fence (SQ-178)', () => {
	it('the source glob is non-empty and sees the files this fence exists for (fail-open guard)', () => {
		const paths = Object.keys(TREE);
		expect(paths.length).toBeGreaterThan(200);
		expect(paths).toContain('src/tenants/db/schema/registry.ts');
		expect(paths).toContain('src/tenants/tenant-resolver.ts');
		expect(paths).toContain('scripts/tenants/provision-tenant.mjs');
		expect(paths).toContain('docs/tenant-ops-runbook.md');
		expect(paths.some((p) => p.includes('node_modules'))).toBe(false);
	});

	it('no reference to last_used_at / billing_events / tenant_keys outside the allowlist', () => {
		const violations = findViolations(TREE);
		expect(
			violations,
			`Reserved registry schema referenced outside the allowlist (SQ-178). ` +
				`Add a design-note pointer (SQ-178) on the line or extend the allowlist with a reason:\n` +
				violations.map((v) => `  ${v.file}:${v.line} [${v.token}] ${v.text}`).join('\n'),
		).toEqual([]);
	});

	it('every narrow allowlist entry still exists and still carries a reference (no stale exemptions)', () => {
		for (const n of NARROW_ALLOWLIST) {
			const text = TREE[n.path];
			expect(text, `${n.path} (${n.reason}) is allowlisted but missing`).toBeDefined();
			expect(new RegExp(RESERVED_SOURCE).test(text), `${n.path} no longer references the tables; drop the entry`).toBe(true);
		}
	});

	it('the schema file carries both honest docstrings and the runbook carries the dormancy rule', () => {
		const schema = TREE['src/tenants/db/schema/registry.ts'];
		expect(schema).toContain('last_used_at is NOT TRACKED');
		expect(schema).toContain('NULL is never evidence a key is unused');
		expect(schema).toContain('billing_events is reserved');
		expect(schema).toContain('An empty table does not mean no billing');
		const runbook = TREE['docs/tenant-ops-runbook.md'];
		expect(runbook).toMatch(/dormancy decisions must not use `tenant_keys\.last_used_at`/);
	});

	describe('positive controls (the audit must trip on these)', () => {
		it('trips on a named-column writer', () => {
			const fixture = {
				'src/fixture/touch-key.ts':
					"await env.DB.prepare('UPDATE tenant_keys SET last_used_at = ? WHERE key_hash = ?').bind(Date.now(), hash).run();\n",
			};
			const hits = findViolations(fixture);
			expect(hits.map((h) => h.token)).toEqual(expect.arrayContaining(['tenant_keys', 'last_used_at']));
		});

		it('trips on a Drizzle select().from(tenantKeys) full-row read, via the identifier alone', () => {
			const fixture = {
				'src/fixture/read-keys.ts':
					"import { tenantKeys } from '../tenants/db/schema/registry';\nconst rows = await db.select().from(tenantKeys);\n",
			};
			const hits = findViolations(fixture);
			expect(hits.map((h) => h.line)).toEqual([1, 2]);
			expect(hits.every((h) => h.token === 'tenantKeys')).toBe(true);
		});

		it('trips on a namespaced and an aliased read', () => {
			expect(findViolations({ 'src/fixture/ns.ts': 'const r = await db.select().from(schema.tenantKeys);\n' })).toHaveLength(1);
			expect(findViolations({ 'src/fixture/alias.ts': "import { tenantKeys as keys } from './registry';\n" })).toHaveLength(1);
		});

		it('trips on a billing_events writer', () => {
			const hits = findViolations({ 'src/fixture/bill.ts': "db.prepare('INSERT INTO billing_events (id) VALUES (?)');\n" });
			expect(hits.map((h) => h.token)).toEqual(['billing_events']);
		});

		it('a narrow-allowlisted file still trips on a token outside its allowance', () => {
			const hits = findViolations({
				'scripts/tenants/provision-tenant.mjs': '`INSERT INTO tenant_keys (key_hash, last_used_at) VALUES (?, ?)`;\n',
			});
			expect(hits.map((h) => h.token)).toEqual(['last_used_at']);
		});
	});

	describe('negative controls (the audit must stay quiet on these)', () => {
		it('allows a comment-only line, a design-note pointer, and an allowlisted path', () => {
			expect(findViolations({ 'src/fixture/a.ts': '// tenant_keys.scope is read later (TODO)\n' })).toEqual([]);
			expect(findViolations({ 'src/fixture/b.ts': ' * last_used_at is not tracked\n' })).toEqual([]);
			expect(findViolations({ 'src/fixture/c.ts': 'const k = tenantKeys; // SQ-178 reviewed: type-only\n' })).toEqual([]);
			expect(findViolations({ 'src/tenants/db/schema/registry.ts': 'export const tenantKeys = 1;\n' })).toEqual([]);
			expect(findViolations({ 'src/tenants/db/migrations/registry/0000_x.sql': 'CREATE TABLE tenant_keys (x);\n' })).toEqual([]);
		});

		it('markdown has no comment rule: it needs the pointer', () => {
			expect(findViolations({ 'docs/x.md': '* use tenant_keys.last_used_at for dormancy\n' })).toHaveLength(2);
			expect(findViolations({ 'docs/x.md': '* tenant_keys.last_used_at is untracked (SQ-178)\n' })).toEqual([]);
		});
	});
});
