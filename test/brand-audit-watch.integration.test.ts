// SPDX-License-Identifier: BUSL-1.1

/**
 * Tests for the brand_audit_watch MCP tool.
 *
 * Three actions on a single tool surface:
 *   - register: create a new watch row in brand_audit_watches
 *   - list:     enumerate the caller's active watches
 *   - delete:   remove a watch (owner-scoped — can't delete another owner's)
 *
 * Webhook URL is validated for SSRF at register time AND at delivery time
 * (cron handler). At register, the SSRF check is done via the canonical
 * validateOutboundUrl from lib/sanitize.
 */

import { describe, it, expect } from 'vitest';
import type { BrandAuditWatchDeps } from '../src/tools/brand-audit-watch';

interface D1Call {
	sql: string;
	binds: unknown[];
}

function makeMockD1(opts: { existing?: Record<string, unknown>[]; throwOnRun?: boolean; existingCount?: number } = {}) {
	const calls: D1Call[] = [];
	const db = {
		prepare(sql: string) {
			let binds: unknown[] = [];
			const stmt = {
				bind(...args: unknown[]) {
					binds = args;
					return stmt;
				},
				async first() {
					calls.push({ sql, binds });
					if (sql.includes('SELECT COUNT(*)')) {
						return { count: opts.existingCount ?? 0 };
					}
					if (sql.includes('FROM brand_audit_watches WHERE id =')) {
						return opts.existing?.[0] ?? null;
					}
					return null;
				},
				async run() {
					calls.push({ sql, binds });
					if (opts.throwOnRun) throw new Error('d1_run_failed');
					return { success: true, meta: { changes: 1 } };
				},
				async all() {
					calls.push({ sql, binds });
					return { results: opts.existing ?? [], success: true, meta: {} };
				},
			};
			return stmt;
		},
	} as unknown as D1Database;
	return { db, calls };
}

function makeDeps(over: Partial<BrandAuditWatchDeps> = {}): BrandAuditWatchDeps {
	const { db } = makeMockD1();
	return {
		db,
		generateId: () => 'watch-test-id',
		now: () => 1_750_000_000_000,
		...over,
	};
}

describe('brandAuditWatch — register', () => {
	it('creates a row and returns the watch id', async () => {
		const { brandAuditWatch } = await import('../src/tools/brand-audit-watch');
		const { db, calls } = makeMockD1();
		const deps = makeDeps({ db });

		const result = await brandAuditWatch(
			{ action: 'register', domain: 'apple.com', interval: 'weekly', webhook_url: 'https://hooks.example.com/abc' },
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
	});

	it('rejects a webhook URL that fails SSRF validation (private IP)', async () => {
		const { brandAuditWatch } = await import('../src/tools/brand-audit-watch');
		const { db } = makeMockD1();
		const deps = makeDeps({ db });

		const result = await brandAuditWatch(
			{ action: 'register', domain: 'apple.com', interval: 'daily', webhook_url: 'http://10.0.0.1/internal' },
			'owner-1',
			deps,
		);
		const error = result.findings.find((f) => f.metadata?.invalidInput === true);
		expect(error).toBeDefined();
	});

	it('accepts register without webhook_url (logging-only watch)', async () => {
		const { brandAuditWatch } = await import('../src/tools/brand-audit-watch');
		const { db, calls } = makeMockD1();
		const deps = makeDeps({ db });

		const result = await brandAuditWatch(
			{ action: 'register', domain: 'apple.com', interval: 'monthly' },
			'owner-1',
			deps,
		);
		const summary = result.findings.find((f) => f.metadata?.summary === true);
		expect(summary?.metadata?.watchId).toBeDefined();
		const insert = calls.find((c) => c.sql.includes('INSERT INTO brand_audit_watches'));
		expect(insert?.binds).toContain(null);
	});

	it('refuses to register when the principal already has 20 watches (cap)', async () => {
		const { brandAuditWatch } = await import('../src/tools/brand-audit-watch');
		const { db } = makeMockD1({ existingCount: 20 });
		const deps = makeDeps({ db });
		const result = await brandAuditWatch(
			{ action: 'register', domain: 'apple.com', interval: 'daily' },
			'owner-1',
			deps,
		);
		const error = result.findings.find((f) => f.metadata?.watchLimitExceeded === true);
		expect(error).toBeDefined();
	});
});

describe('brandAuditWatch — list', () => {
	it("returns the caller's active watches", async () => {
		const { brandAuditWatch } = await import('../src/tools/brand-audit-watch');
		const rows = [
			{ id: 'w-1', owner_id: 'owner-1', domain: 'apple.com', interval: 'weekly', webhook_url: null, last_run_at: null, last_classification_hash: null, active: 1, created_at: 1 },
			{ id: 'w-2', owner_id: 'owner-1', domain: 'brand-zeta.example.com', interval: 'monthly', webhook_url: 'https://hooks.example.com/a', last_run_at: 2, last_classification_hash: 'a'.repeat(64), active: 1, created_at: 2 },
		];
		const { db } = makeMockD1({ existing: rows });
		const deps = makeDeps({ db });

		const result = await brandAuditWatch({ action: 'list' }, 'owner-1', deps);
		const summary = result.findings.find((f) => f.metadata?.summary === true);
		expect((summary?.metadata?.watches as unknown[])).toHaveLength(2);
	});
});

describe('brandAuditWatch — delete', () => {
	it('deletes a watch owned by the caller', async () => {
		const { brandAuditWatch } = await import('../src/tools/brand-audit-watch');
		const { db, calls } = makeMockD1({
			existing: [{ id: 'w-1', owner_id: 'owner-1', domain: 'apple.com', interval: 'weekly', webhook_url: null, last_run_at: null, last_classification_hash: null, active: 1, created_at: 1 }],
		});
		const deps = makeDeps({ db });

		const result = await brandAuditWatch({ action: 'delete', watchId: 'w-1' }, 'owner-1', deps);
		const summary = result.findings.find((f) => f.metadata?.summary === true);
		expect(summary?.metadata?.deleted).toBe(true);
		const del = calls.find((c) => c.sql.includes('DELETE FROM brand_audit_watches'));
		expect(del?.binds).toContain('w-1');
		expect(del?.binds).toContain('owner-1');
	});

	it("refuses to delete another owner's watch (notFound, not accessDenied)", async () => {
		const { brandAuditWatch } = await import('../src/tools/brand-audit-watch');
		const { db } = makeMockD1({
			existing: [{ id: 'w-2', owner_id: 'owner-other', domain: 'x.com', interval: 'daily', webhook_url: null, last_run_at: null, last_classification_hash: null, active: 1, created_at: 1 }],
		});
		const deps = makeDeps({ db });
		const result = await brandAuditWatch({ action: 'delete', watchId: 'w-2' }, 'owner-1', deps);
		const notFound = result.findings.find((f) => f.metadata?.notFound === true);
		const accessDenied = result.findings.find((f) => f.metadata?.accessDenied === true);
		expect(notFound).toBeDefined();
		expect(accessDenied).toBeUndefined();
	});
});
