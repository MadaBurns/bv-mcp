// SPDX-License-Identifier: BUSL-1.1

/**
 * Tests for the brand-audit watch MCP tools.
 *
 * The single `action`-discriminated `brand_audit_watch` tool was split into
 * three single-purpose tools to satisfy the Anthropic Directory requirement
 * that read and destructive operations live in separate tools:
 *   - list_brand_audit_watches   (read-only)  — enumerate the caller's watches
 *   - register_brand_audit_watch (write)      — create a new watch row
 *   - delete_brand_audit_watch   (destructive)— remove a watch (owner-scoped)
 *
 * Webhook URL is validated for SSRF at register time AND at delivery time
 * (cron handler). At register, the SSRF check is done via the canonical
 * validateOutboundUrl from lib/sanitize.
 *
 * D1 IS REAL HERE (see `d1Databases: ['BRAND_AUDIT_DB']` in vitest.config.mts)
 * — every statement below executes against actual SQLite via the Workers
 * pool's D1 shim, not a hand-rolled string-matching mock. A malformed query
 * (bad column name, a type the runtime rejects, a broken WHERE clause) throws
 * here exactly as it would against production D1; a prior version of this
 * file asserted only on the generated SQL string, which could not fail no
 * matter how broken the query was (SQ-69).
 */

import { describe, it, expect, beforeAll, beforeEach } from 'vitest';
import { env } from 'cloudflare:test';
import type { BrandAuditWatchDeps } from '../src/tools/brand-audit-watch';
import { TOOLS } from '../src/schemas/tool-definitions';

// wrangler.jsonc deliberately does not declare BRAND_AUDIT_DB (it's a
// private binding injected only at deploy time — see src/index.ts's
// `BvMcpEnv = Env & { BRAND_AUDIT_DB?: D1Database; ... }`), so the generated
// `Env` type `cloudflare:test`'s ProvidedEnv extends does not know about it
// even though vitest.config.mts provisions a real one for this test file.
function brandAuditDb(): D1Database {
	return (env as unknown as { BRAND_AUDIT_DB: D1Database }).BRAND_AUDIT_DB;
}

// Mirrors the production table (see src/lib/db/brand-audit-schema.ts and the
// identical CREATE TABLE in test/scheduled/brand-audit-cron-d1.node.test.ts).
const SCHEMA = `
CREATE TABLE IF NOT EXISTS brand_audit_watches (
  id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL,
  domain TEXT NOT NULL,
  interval TEXT NOT NULL,
  webhook_url TEXT,
  last_run_at INTEGER,
  last_classification_hash TEXT,
  last_classification_result_json TEXT,
  pending_webhook_json TEXT,
  active INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL
);`;

beforeAll(async () => {
	// D1 exec treats newlines as statement boundaries; compact while keeping
	// the semicolon boundary (same normalization the .node.test.ts sibling uses).
	await brandAuditDb().exec(SCHEMA.replace(/\s+/g, ' ').trim());
});

// vitest.config.mts sets `isolatedStorage: false` for this project, so D1
// state persists across tests in this file unless cleared explicitly.
beforeEach(async () => {
	await brandAuditDb().exec('DELETE FROM brand_audit_watches;');
});

interface D1Call {
	sql: string;
	binds: unknown[];
}

/**
 * Thin recording wrapper around the REAL D1 binding. Every statement still
 * actually executes against real SQLite — `calls` only lets assertions
 * inspect the exact SQL/binds a call sent, it never substitutes for
 * execution. `forceRunError` simulates a genuine D1 outage for the one test
 * that exercises the tool's own persistenceFailure catch path.
 */
function wrapRealD1(db: D1Database, opts: { forceRunError?: boolean } = {}) {
	const calls: D1Call[] = [];
	const wrapped = {
		prepare(sql: string) {
			let bound: D1PreparedStatement = db.prepare(sql);
			let binds: unknown[] = [];
			const stmt = {
				bind(...args: unknown[]) {
					binds = args;
					bound = db.prepare(sql).bind(...args);
					return stmt;
				},
				async first<T = unknown>(column?: string) {
					calls.push({ sql, binds });
					return bound.first<T>(column as never);
				},
				async run() {
					calls.push({ sql, binds });
					if (opts.forceRunError) throw new Error('d1_run_failed');
					return bound.run();
				},
				async all<T = unknown>() {
					calls.push({ sql, binds });
					return bound.all<T>();
				},
			};
			return stmt;
		},
	} as unknown as D1Database;
	return { db: wrapped, calls };
}

async function seedWatches(db: D1Database, ownerId: string, count: number) {
	for (let i = 0; i < count; i++) {
		await db
			.prepare(
				'INSERT INTO brand_audit_watches (id, owner_id, domain, interval, webhook_url, last_run_at, last_classification_hash, active, created_at) VALUES (?, ?, ?, ?, NULL, NULL, NULL, 1, ?)',
			)
			.bind(`seed-${ownerId}-${i}`, ownerId, `seed-${i}.${ownerId}.example.com`, 'daily', Date.now())
			.run();
	}
}

function makeDeps(over: Partial<BrandAuditWatchDeps> = {}): BrandAuditWatchDeps {
	return {
		db: brandAuditDb(),
		generateId: () => 'watch-test-id',
		now: () => 1_750_000_000_000,
		...over,
	};
}

describe('register_brand_audit_watch', () => {
	it('creates a row and returns the watch id', async () => {
		const { registerBrandAuditWatch } = await import('../src/tools/brand-audit-watch');
		const { db, calls } = wrapRealD1(brandAuditDb());
		const deps = makeDeps({ db });

		const result = await registerBrandAuditWatch(
			{ domain: 'apple.com', interval: 'weekly', webhook_url: 'https://hooks.example.com/abc' },
			'owner-1',
			deps,
		);

		const summary = result.findings.find((f) => f.metadata?.summary === true);
		expect(summary?.metadata?.watchId).toBe('watch-test-id');
		expect(summary?.metadata?.domain).toBe('apple.com');

		const insert = calls.find((c) => c.sql.includes('INSERT INTO brand_audit_watches'));
		expect(insert).toBeDefined();
		expect(insert?.binds).toContain('owner-1');
		expect(insert?.binds).toContain('apple.com');
		expect(insert?.binds).toContain('weekly');
		expect(insert?.binds).toContain('https://hooks.example.com/abc');

		// Real proof: the row actually landed in SQLite, not just a mock call log.
		const row = await brandAuditDb()
			.prepare('SELECT owner_id, domain, interval, webhook_url FROM brand_audit_watches WHERE id = ?')
			.bind('watch-test-id')
			.first<{ owner_id: string; domain: string; interval: string; webhook_url: string }>();
		expect(row).toEqual({ owner_id: 'owner-1', domain: 'apple.com', interval: 'weekly', webhook_url: 'https://hooks.example.com/abc' });
	});

	it('rejects a webhook URL that fails SSRF validation (private IP)', async () => {
		const { registerBrandAuditWatch } = await import('../src/tools/brand-audit-watch');
		const deps = makeDeps();

		const result = await registerBrandAuditWatch(
			{ domain: 'apple.com', interval: 'daily', webhook_url: 'http://10.0.0.1/internal' },
			'owner-1',
			deps,
		);
		const error = result.findings.find((f) => f.metadata?.invalidInput === true);
		expect(error).toBeDefined();
	});

	it('accepts register without webhook_url (logging-only watch)', async () => {
		const { registerBrandAuditWatch } = await import('../src/tools/brand-audit-watch');
		const { db, calls } = wrapRealD1(brandAuditDb());
		const deps = makeDeps({ db });

		const result = await registerBrandAuditWatch({ domain: 'apple.com', interval: 'monthly' }, 'owner-1', deps);
		const summary = result.findings.find((f) => f.metadata?.summary === true);
		expect(summary?.metadata?.watchId).toBeDefined();
		const insert = calls.find((c) => c.sql.includes('INSERT INTO brand_audit_watches'));
		expect(insert?.binds).toContain(null);
	});

	it('uses D1 meta.changes=0 to report the cap without a preflight COUNT', async () => {
		const { registerBrandAuditWatch } = await import('../src/tools/brand-audit-watch');
		await seedWatches(brandAuditDb(), 'owner-1', 20);
		const { db, calls } = wrapRealD1(brandAuditDb());
		const deps = makeDeps({ db });
		const result = await registerBrandAuditWatch({ domain: 'apple.com', interval: 'daily' }, 'owner-1', deps);
		const error = result.findings.find((f) => f.metadata?.watchLimitExceeded === true);
		expect(error).toBeDefined();
		expect(result.findings.find((f) => f.metadata?.summary === true)).toBeUndefined();

		const insert = calls.find((c) => c.sql.includes('INSERT INTO brand_audit_watches'));
		expect(insert?.sql).toContain('SELECT COUNT(*)');
		expect(insert?.sql).toContain('WHERE owner_id = ? AND active = 1');
		expect(insert?.binds.slice(-2)).toEqual(['owner-1', 20]);

		// Real proof: nothing past the cap was actually written.
		const count = await brandAuditDb()
			.prepare('SELECT COUNT(*) AS n FROM brand_audit_watches WHERE owner_id = ?')
			.bind('owner-1')
			.first<{ n: number }>();
		expect(count?.n).toBe(20);
	});

	it('keeps thrown D1 insert failures on the persistenceFailure path', async () => {
		const { registerBrandAuditWatch } = await import('../src/tools/brand-audit-watch');
		const { db } = wrapRealD1(brandAuditDb(), { forceRunError: true });
		const result = await registerBrandAuditWatch({ domain: 'apple.com', interval: 'daily' }, 'owner-1', makeDeps({ db }));
		expect(result.findings.find((f) => f.metadata?.persistenceFailure === true)).toBeDefined();
		expect(result.findings.find((f) => f.metadata?.summary === true)).toBeUndefined();
	});

	it('admits at most 20 distinct concurrent registrations for each principal', async () => {
		const { registerBrandAuditWatch } = await import('../src/tools/brand-audit-watch');
		let nextId = 0;
		const deps = makeDeps({ generateId: () => `watch-concurrent-${nextId++}` });

		const registerMany = (ownerId: string) =>
			Promise.all(
				Array.from({ length: 48 }, (_, index) =>
					registerBrandAuditWatch({ domain: `brand-${index}.${ownerId}.example.com`, interval: 'daily' }, ownerId, deps),
				),
			);
		const [ownerAResults, ownerBResults] = await Promise.all([registerMany('owner-a'), registerMany('owner-b')]);

		for (const [ownerId, results] of [
			['owner-a', ownerAResults],
			['owner-b', ownerBResults],
		] as const) {
			// Real proof: the atomic INSERT...SELECT guard, executed by real
			// SQLite under real concurrent callers, never over-admits.
			const rows = await brandAuditDb()
				.prepare('SELECT id, domain FROM brand_audit_watches WHERE owner_id = ? AND active = 1')
				.bind(ownerId)
				.all<{ id: string; domain: string }>();
			expect(rows.results).toHaveLength(20);
			expect(new Set(rows.results.map((r) => r.id)).size).toBe(20);
			expect(new Set(rows.results.map((r) => r.domain)).size).toBe(20);
			expect(results.filter((result) => result.findings.some((f) => f.metadata?.summary === true))).toHaveLength(20);
			expect(results.filter((result) => result.findings.some((f) => f.metadata?.watchLimitExceeded === true))).toHaveLength(28);
		}
	});

	it('rejects a blocklisted / SSRF-class watched domain at register time (no INSERT)', async () => {
		const { registerBrandAuditWatch } = await import('../src/tools/brand-audit-watch');
		const { db, calls } = wrapRealD1(brandAuditDb());
		const deps = makeDeps({ db });

		// An IP literal is rejected by validateDomain (SSRF/blocklist guard). It must
		// be refused at register time rather than stored and failed every cron cycle.
		const result = await registerBrandAuditWatch({ domain: '127.0.0.1', interval: 'daily' }, 'owner-1', deps);

		const error = result.findings.find((f) => f.metadata?.invalidInput === true);
		expect(error).toBeDefined();

		// No row is written for a rejected domain.
		const insert = calls.find((c) => c.sql.includes('INSERT INTO brand_audit_watches'));
		expect(insert).toBeUndefined();
		const count = await brandAuditDb().prepare('SELECT COUNT(*) AS n FROM brand_audit_watches').first<{ n: number }>();
		expect(count?.n).toBe(0);
	});
});

describe('list_brand_audit_watches', () => {
	it("returns the caller's active watches, newest first", async () => {
		const { listBrandAuditWatches } = await import('../src/tools/brand-audit-watch');
		const callbackToken = 'abcdefghijklmnopqrstuvwxyzABCDEF';
		const insert = brandAuditDb().prepare(
			'INSERT INTO brand_audit_watches (id, owner_id, domain, interval, webhook_url, last_run_at, last_classification_hash, active, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)',
		);
		await insert.bind('w-1', 'owner-1', 'apple.com', 'weekly', null, null, null, 1).run();
		await insert
			.bind(
				'w-2',
				'owner-1',
				'brand-zeta.example.com',
				'monthly',
				`https://www.blackveilsecurity.com/api/webhooks/brand-drift?t=${callbackToken}`,
				2,
				'a'.repeat(64),
				2,
			)
			.run();
		const deps = makeDeps();

		const result = await listBrandAuditWatches('owner-1', deps);
		const summary = result.findings.find((f) => f.metadata?.summary === true);
		const watches = summary?.metadata?.watches as Array<Record<string, unknown>>;
		expect(watches).toHaveLength(2);
		const expectedDigest = Array.from(
			new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(callbackToken))),
			(byte) => byte.toString(16).padStart(2, '0'),
		).join('');
		// ORDER BY created_at DESC: w-2 (created_at=2) is real-execution-proven to
		// sort ahead of w-1 (created_at=1) — the previous mock's `.all()` ignored
		// ORDER BY entirely and returned insertion order regardless, so this exact
		// ordering was never actually exercised before SQ-69.
		expect(watches[0]?.watchId).toBe('w-2');
		expect(watches[0]?.webhookTokenFingerprint).toBe(expectedDigest);
		expect(watches[1]?.watchId).toBe('w-1');
		expect(watches[1]?.webhookTokenFingerprint).toBeNull();
		expect(JSON.stringify(watches)).not.toContain(callbackToken);
		expect(JSON.stringify(watches)).not.toContain('webhook_url');
	});
});

describe('delete_brand_audit_watch', () => {
	it('deletes a watch owned by the caller', async () => {
		const { deleteBrandAuditWatch } = await import('../src/tools/brand-audit-watch');
		await brandAuditDb()
			.prepare(
				'INSERT INTO brand_audit_watches (id, owner_id, domain, interval, webhook_url, last_run_at, last_classification_hash, active, created_at) VALUES (?, ?, ?, ?, NULL, NULL, NULL, 1, ?)',
			)
			.bind('w-1', 'owner-1', 'apple.com', 'weekly', 1)
			.run();
		const { db, calls } = wrapRealD1(brandAuditDb());
		const deps = makeDeps({ db });

		const result = await deleteBrandAuditWatch({ watchId: 'w-1' }, 'owner-1', deps);
		const summary = result.findings.find((f) => f.metadata?.summary === true);
		expect(summary?.metadata?.deleted).toBe(true);
		const del = calls.find((c) => c.sql.includes('DELETE FROM brand_audit_watches'));
		expect(del?.binds).toContain('w-1');
		expect(del?.binds).toContain('owner-1');

		// Real proof: the row is actually gone from SQLite.
		const remaining = await brandAuditDb()
			.prepare('SELECT COUNT(*) AS n FROM brand_audit_watches WHERE id = ?')
			.bind('w-1')
			.first<{ n: number }>();
		expect(remaining?.n).toBe(0);
	});

	it("refuses to delete another owner's watch (notFound, not accessDenied)", async () => {
		const { deleteBrandAuditWatch } = await import('../src/tools/brand-audit-watch');
		await brandAuditDb()
			.prepare(
				'INSERT INTO brand_audit_watches (id, owner_id, domain, interval, webhook_url, last_run_at, last_classification_hash, active, created_at) VALUES (?, ?, ?, ?, NULL, NULL, NULL, 1, ?)',
			)
			.bind('w-2', 'owner-other', 'x.com', 'daily', 1)
			.run();
		const deps = makeDeps();
		const result = await deleteBrandAuditWatch({ watchId: 'w-2' }, 'owner-1', deps);
		const notFound = result.findings.find((f) => f.metadata?.notFound === true);
		const accessDenied = result.findings.find((f) => f.metadata?.accessDenied === true);
		expect(notFound).toBeDefined();
		expect(accessDenied).toBeUndefined();

		// Real proof: the row survives — a cross-owner delete never reaches D1.
		const remaining = await brandAuditDb()
			.prepare('SELECT COUNT(*) AS n FROM brand_audit_watches WHERE id = ?')
			.bind('w-2')
			.first<{ n: number }>();
		expect(remaining?.n).toBe(1);
	});
});

describe('brand-audit watch tool surface (directory read/write split)', () => {
	const byName = (n: string) => TOOLS.find((t) => t.name === n);

	it('exposes three single-purpose tools and removes the catch-all', () => {
		expect(byName('brand_audit_watch')).toBeUndefined();
		expect(byName('list_brand_audit_watches')).toBeDefined();
		expect(byName('register_brand_audit_watch')).toBeDefined();
		expect(byName('delete_brand_audit_watch')).toBeDefined();
	});

	it('annotates each tool by its operation kind', () => {
		expect(byName('list_brand_audit_watches')?.annotations).toMatchObject({ readOnlyHint: true, destructiveHint: false });
		expect(byName('register_brand_audit_watch')?.annotations).toMatchObject({ readOnlyHint: false, destructiveHint: false });
		expect(byName('delete_brand_audit_watch')?.annotations).toMatchObject({ readOnlyHint: false, destructiveHint: true });
	});
});
