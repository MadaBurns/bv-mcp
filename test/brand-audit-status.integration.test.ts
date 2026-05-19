// SPDX-License-Identifier: BUSL-1.1

/**
 * Tests for the brand_audit_status MCP tool.
 *
 * Read-only D1 lookup for a previously-enqueued audit. Returns:
 *   - audit-level status ('queued' | 'running' | 'completed' | 'failed')
 *   - progress fraction ('N/M')
 *   - per-target status array
 *
 * Owner-scoped: an audit row is only visible to its owner (owner_id === principalId).
 * A request for someone else's auditId returns notFound, not access-denied — defending
 * against ID enumeration.
 */

import { describe, it, expect } from 'vitest';
import type { BrandAuditStatusDeps } from '../src/tools/brand-audit-status';

interface D1Call {
	sql: string;
	binds: unknown[];
}

function makeMockD1(opts: { audit?: Record<string, unknown> | null; targets?: Record<string, unknown>[]; throwOnFirst?: boolean } = {}) {
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
					if (opts.throwOnFirst) throw new Error('d1_first_failed');
					if (sql.includes('FROM brand_audits')) return opts.audit ?? null;
					return null;
				},
				async all() {
					calls.push({ sql, binds });
					if (sql.includes('FROM brand_audit_targets')) {
						return { results: opts.targets ?? [], success: true, meta: {} };
					}
					return { results: [], success: true, meta: {} };
				},
				async run() {
					calls.push({ sql, binds });
					return { success: true, meta: {} };
				},
			};
			return stmt;
		},
	} as unknown as D1Database;
	return { db, calls };
}

function makeDeps(overrides: Partial<BrandAuditStatusDeps> = {}): BrandAuditStatusDeps {
	const { db } = makeMockD1();
	return { db, ...overrides };
}

describe('brandAuditStatus', () => {
	it('returns audit status + progress + per-target statuses', async () => {
		const { brandAuditStatus } = await import('../src/tools/brand-audit-status');
		const { db } = makeMockD1({
			audit: {
				id: 'aud-1',
				owner_id: 'owner-abc',
				status: 'running',
				total_targets: 3,
				completed_targets: 2,
				format: 'both',
				created_at: 1_750_000_000_000,
				updated_at: 1_750_000_060_000,
				completed_at: null,
			},
			targets: [
				{ audit_id: 'aud-1', target: 'apple.com', status: 'completed', created_at: 1_750_000_000_000, completed_at: 1_750_000_030_000, error: null, pdf_r2_key: null },
				{ audit_id: 'aud-1', target: 'microsoft.com', status: 'completed', created_at: 1_750_000_000_000, completed_at: 1_750_000_050_000, error: null, pdf_r2_key: null },
				{ audit_id: 'aud-1', target: 'brand-gamma.com', status: 'running', created_at: 1_750_000_000_000, completed_at: null, error: null, pdf_r2_key: null },
			],
		});

		const result = await brandAuditStatus('aud-1', 'owner-abc', { db });

		const summary = result.findings.find((f) => f.metadata?.summary === true);
		expect(summary?.metadata?.auditId).toBe('aud-1');
		expect(summary?.metadata?.status).toBe('running');
		expect(summary?.metadata?.progress).toBe('2/3');
		expect(summary?.metadata?.completed).toBe(2);
		expect(summary?.metadata?.total).toBe(3);
		expect((summary?.metadata?.targets as unknown[])).toHaveLength(3);
		expect(summary?.metadata?.targetStatusCounts).toEqual({
			queued: 0,
			running: 1,
			completed: 2,
			failed: 0,
		});
		expect(summary?.metadata?.ageMs).toBeTypeOf('number');
		expect(summary?.metadata?.updatedAgeMs).toBeTypeOf('number');
	});

	it('coalesces a completed parent plus populated target result_json into a completed target status', async () => {
		const { brandAuditStatus } = await import('../src/tools/brand-audit-status');
		const { db } = makeMockD1({
			audit: {
				id: 'aud-race',
				owner_id: 'owner-abc',
				status: 'completed',
				total_targets: 1,
				completed_targets: 1,
				format: 'both',
				created_at: 1_750_000_000_000,
				updated_at: 1_750_000_100_000,
				completed_at: 1_750_000_100_000,
			},
			targets: [
				{
					audit_id: 'aud-race',
					target: 'example.com',
					status: 'running',
					created_at: 1_750_000_000_000,
					completed_at: null,
					error: null,
					pdf_r2_key: null,
					result_json: '{"category":"brand_discovery","findings":[]}',
				},
			],
		});

		const result = await brandAuditStatus('aud-race', 'owner-abc', { db });

		const summary = result.findings.find((f) => f.metadata?.summary === true);
		expect(summary?.metadata?.targetStatusCounts).toEqual({
			queued: 0,
			running: 0,
			completed: 1,
			failed: 0,
		});
		expect(summary?.metadata?.targets).toEqual([
			expect.objectContaining({ target: 'example.com', status: 'completed' }),
		]);
	});

	it('does not coalesce an explicitly failed target even if result_json is present', async () => {
		const { brandAuditStatus } = await import('../src/tools/brand-audit-status');
		const { db } = makeMockD1({
			audit: {
				id: 'aud-failed',
				owner_id: 'owner-abc',
				status: 'completed',
				total_targets: 1,
				completed_targets: 1,
				format: 'json',
				created_at: 1_750_000_000_000,
				updated_at: 1_750_000_100_000,
				completed_at: 1_750_000_100_000,
			},
			targets: [
				{
					audit_id: 'aud-failed',
					target: 'example.com',
					status: 'failed',
					created_at: 1_750_000_000_000,
					completed_at: 1_750_000_090_000,
					error: 'failed',
					pdf_r2_key: null,
					result_json: '{"category":"brand_discovery","findings":[]}',
				},
			],
		});

		const result = await brandAuditStatus('aud-failed', 'owner-abc', { db });

		const summary = result.findings.find((f) => f.metadata?.summary === true);
		expect(summary?.metadata?.targetStatusCounts).toMatchObject({ completed: 0, failed: 1 });
		expect(summary?.metadata?.targets).toEqual([
			expect.objectContaining({ target: 'example.com', status: 'failed' }),
		]);
	});

	it('returns notFound when auditId is unknown', async () => {
		const { brandAuditStatus } = await import('../src/tools/brand-audit-status');
		const deps = makeDeps();
		const result = await brandAuditStatus('aud-missing', 'owner-abc', deps);
		const errorFinding = result.findings.find((f) => f.metadata?.notFound === true);
		expect(errorFinding).toBeDefined();
	});

	it('returns notFound (not accessDenied) when audit belongs to a different owner', async () => {
		const { brandAuditStatus } = await import('../src/tools/brand-audit-status');
		const { db } = makeMockD1({
			audit: {
				id: 'aud-2',
				owner_id: 'owner-other',
				status: 'completed',
				total_targets: 1,
				completed_targets: 1,
				format: 'json',
				created_at: 1, updated_at: 2, completed_at: 3,
			},
		});
		const result = await brandAuditStatus('aud-2', 'owner-abc', { db });
		const notFound = result.findings.find((f) => f.metadata?.notFound === true);
		const accessDenied = result.findings.find((f) => f.metadata?.accessDenied === true);
		expect(notFound).toBeDefined();
		expect(accessDenied).toBeUndefined();
	});

	it('reports D1 read failure as a structured error', async () => {
		const { brandAuditStatus } = await import('../src/tools/brand-audit-status');
		const { db } = makeMockD1({ throwOnFirst: true });
		const result = await brandAuditStatus('aud-1', 'owner-abc', { db });
		const errorFinding = result.findings.find((f) => f.metadata?.readFailure === true);
		expect(errorFinding).toBeDefined();
	});

	it('rejects empty/invalid auditId', async () => {
		const { brandAuditStatus } = await import('../src/tools/brand-audit-status');
		const result = await brandAuditStatus('', 'owner-abc', makeDeps());
		const invalid = result.findings.find((f) => f.metadata?.invalidInput === true);
		expect(invalid).toBeDefined();
	});
});
