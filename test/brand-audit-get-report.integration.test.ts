// SPDX-License-Identifier: BUSL-1.1

/**
 * Tests for the brand_audit_get_report MCP tool.
 *
 * Read-only D1 lookup returning either:
 *   - Per-target result_json when `target` is provided + status='completed'
 *   - Audit-level results_json aggregate when `target` is omitted + audit status='completed'
 *   - notReady when the audit/target hasn't finished yet
 *
 * Owner-scoped (same ID-enumeration defense as brand_audit_status).
 *
 * R2 signed URL path (PDF mode) is Phase 3 — out of scope here.
 */

import { describe, it, expect } from 'vitest';

interface RowMap {
	audit?: Record<string, unknown> | null;
	target?: Record<string, unknown> | null;
	targets?: Record<string, unknown>[];
}

function makeMockD1(rows: RowMap) {
	const calls: { sql: string; binds: unknown[] }[] = [];
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
					if (sql.includes('FROM brand_audits')) return rows.audit ?? null;
					if (sql.includes('FROM brand_audit_targets')) return rows.target ?? null;
					return null;
				},
				async all() {
					calls.push({ sql, binds });
					if (sql.includes('FROM brand_audit_targets')) {
						return { results: rows.targets ?? [], success: true, meta: {} };
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

describe('brandAuditGetReport', () => {
	it('returns per-target result_json when target is provided and status=completed', async () => {
		const { brandAuditGetReport } = await import('../src/tools/brand-audit-get-report');
		const fakeResult = { category: 'brand_discovery', score: 100, findings: [{ category: 'brand_discovery', title: 'apple.net', severity: 'info', detail: '', metadata: { bucket: 'consolidated' } }] };
		const { db } = makeMockD1({
			audit: { id: 'aud-1', owner_id: 'owner-abc', status: 'completed', format: 'json' },
			target: { audit_id: 'aud-1', target: 'apple.com', status: 'completed', result_json: JSON.stringify(fakeResult), error: null, completed_at: 1 },
		});

		const result = await brandAuditGetReport(
			{ auditId: 'aud-1', target: 'apple.com' },
			'owner-abc',
			{ db },
		);

		const summary = result.findings.find((f) => f.metadata?.summary === true);
		expect(summary?.metadata?.auditId).toBe('aud-1');
		expect(summary?.metadata?.target).toBe('apple.com');
		expect(summary?.metadata?.result).toMatchObject({ category: 'brand_discovery' });
	});

	it('returns notReady when target is still queued/running', async () => {
		const { brandAuditGetReport } = await import('../src/tools/brand-audit-get-report');
		const { db } = makeMockD1({
			audit: { id: 'aud-1', owner_id: 'owner-abc', status: 'running' },
			target: { audit_id: 'aud-1', target: 'apple.com', status: 'running', result_json: null, error: null, completed_at: null },
		});

		const result = await brandAuditGetReport(
			{ auditId: 'aud-1', target: 'apple.com' },
			'owner-abc',
			{ db },
		);

		const notReady = result.findings.find((f) => f.metadata?.notReady === true);
		expect(notReady).toBeDefined();
	});

	it('coalesces completed parent plus target result_json into a readable completed target', async () => {
		const { brandAuditGetReport } = await import('../src/tools/brand-audit-get-report');
		const fakeResult = { category: 'brand_discovery', score: 100, findings: [] };
		const { db } = makeMockD1({
			audit: { id: 'aud-1', owner_id: 'owner-abc', status: 'completed', format: 'json' },
			target: {
				audit_id: 'aud-1',
				target: 'apple.com',
				status: 'running',
				result_json: JSON.stringify(fakeResult),
				error: null,
				completed_at: null,
			},
		});

		const result = await brandAuditGetReport(
			{ auditId: 'aud-1', target: 'apple.com' },
			'owner-abc',
			{ db },
		);

		const summary = result.findings.find((f) => f.metadata?.summary === true);
		expect(summary?.metadata).toMatchObject({
			status: 'completed',
			result: fakeResult,
		});
		expect(result.findings.find((f) => f.metadata?.notReady === true)).toBeUndefined();
	});

	it('returns notFound when target row does not exist for the audit', async () => {
		const { brandAuditGetReport } = await import('../src/tools/brand-audit-get-report');
		const { db } = makeMockD1({
			audit: { id: 'aud-1', owner_id: 'owner-abc', status: 'completed' },
			target: null,
		});
		const result = await brandAuditGetReport(
			{ auditId: 'aud-1', target: 'never-seen.example.com' },
			'owner-abc',
			{ db },
		);
		expect(result.findings.find((f) => f.metadata?.notFound === true)).toBeDefined();
	});

	it('returns audit-level aggregate when target is omitted and audit status=completed', async () => {
		const { brandAuditGetReport } = await import('../src/tools/brand-audit-get-report');
		const aggregate = { totalCandidates: 7, buckets: { consolidated: 3, shadowIt: 1, indeterminate: 2, impersonation: 1 } };
		const { db } = makeMockD1({
			audit: { id: 'aud-1', owner_id: 'owner-abc', status: 'completed', results_json: JSON.stringify(aggregate), format: 'json' },
		});

		const result = await brandAuditGetReport({ auditId: 'aud-1' }, 'owner-abc', { db });
		const summary = result.findings.find((f) => f.metadata?.summary === true);
		expect(summary?.metadata?.aggregate).toMatchObject({ totalCandidates: 7 });
	});

	// Dead-zone closure (2026-05-21 brand-beta.example.com hang). See
	// brand-audit-status.integration.test.ts for the full rationale.
	describe('dead-zone closure for stuck running targets', () => {
		it('synthesises status=failed for a running target whose deadline has passed', async () => {
			const { brandAuditGetReport } = await import('../src/tools/brand-audit-get-report');
			const { BRAND_AUDIT_TARGET_DEADLINE_MS } = await import('../src/lib/brand-audit-reaper');
			const createdAt = 1_750_000_000_000;
			const now = createdAt + BRAND_AUDIT_TARGET_DEADLINE_MS + 5_000;
			const { db } = makeMockD1({
				audit: { id: 'aud-disney', owner_id: 'owner-abc', status: 'running', format: 'json' },
				target: {
					audit_id: 'aud-disney',
					target: 'brand-beta.example.com',
					status: 'running',
					result_json: null,
					error: null,
					completed_at: null,
					created_at: createdAt,
				},
			});

			const result = await brandAuditGetReport(
				{ auditId: 'aud-disney', target: 'brand-beta.example.com' },
				'owner-abc',
				{ db, now: () => now },
			);

			// No more "notReady" for the duration of the dead zone.
			expect(result.findings.find((f) => f.metadata?.notReady === true)).toBeUndefined();
			const summary = result.findings.find((f) => f.metadata?.summary === true);
			expect(summary?.metadata?.status).toBe('failed');
			expect(summary?.metadata?.error).toMatch(/stuck/i);
		});

		it('issues a best-effort UPDATE to persist the synthesised failed status', async () => {
			const { brandAuditGetReport } = await import('../src/tools/brand-audit-get-report');
			const { BRAND_AUDIT_TARGET_DEADLINE_MS } = await import('../src/lib/brand-audit-reaper');
			const createdAt = 1_750_000_000_000;
			const now = createdAt + BRAND_AUDIT_TARGET_DEADLINE_MS + 5_000;
			const { db, calls } = makeMockD1({
				audit: { id: 'aud-disney', owner_id: 'owner-abc', status: 'running', format: 'json' },
				target: {
					audit_id: 'aud-disney',
					target: 'brand-beta.example.com',
					status: 'running',
					result_json: null,
					error: null,
					completed_at: null,
					created_at: createdAt,
				},
			});

			await brandAuditGetReport(
				{ auditId: 'aud-disney', target: 'brand-beta.example.com' },
				'owner-abc',
				{ db, now: () => now },
			);

			const persistFlip = calls.find(
				(c) =>
					c.sql.includes('UPDATE brand_audit_targets') &&
					c.sql.includes("status = 'failed'") &&
					c.sql.includes("status = 'running'") &&
					(c.binds as unknown[]).includes('brand-beta.example.com'),
			);
			expect(persistFlip).toBeDefined();
		});

		it('does NOT synthesise failed for a running target still within deadline', async () => {
			const { brandAuditGetReport } = await import('../src/tools/brand-audit-get-report');
			const { BRAND_AUDIT_TARGET_DEADLINE_MS } = await import('../src/lib/brand-audit-reaper');
			const createdAt = 1_750_000_000_000;
			const now = createdAt + BRAND_AUDIT_TARGET_DEADLINE_MS - 60_000;
			const { db } = makeMockD1({
				audit: { id: 'aud-inflight', owner_id: 'owner-abc', status: 'running', format: 'json' },
				target: {
					audit_id: 'aud-inflight',
					target: 'example.com',
					status: 'running',
					result_json: null,
					error: null,
					completed_at: null,
					created_at: createdAt,
				},
			});

			const result = await brandAuditGetReport(
				{ auditId: 'aud-inflight', target: 'example.com' },
				'owner-abc',
				{ db, now: () => now },
			);

			// Legitimate in-flight audit still returns notReady, not synthesised-failed.
			expect(result.findings.find((f) => f.metadata?.notReady === true)).toBeDefined();
		});
	});

	describe('aggregate-mode dead-zone closure', () => {
		it('renders status=failed and persists the batch flip when all targets synthesized failed', async () => {
			const { brandAuditGetReport } = await import('../src/tools/brand-audit-get-report');
			const { BRAND_AUDIT_TARGET_DEADLINE_MS } = await import('../src/lib/brand-audit-reaper');
			const createdAt = 1_750_000_000_000;
			const now = createdAt + BRAND_AUDIT_TARGET_DEADLINE_MS + 10_000;
			const { db, calls } = makeMockD1({
				audit: {
					id: 'aud-deadzone',
					owner_id: 'owner-abc',
					status: 'running',
					results_json: null,
					format: 'json',
				},
				targets: [
					{ status: 'running', created_at: createdAt },
					{ status: 'running', created_at: createdAt },
				],
			});

			const result = await brandAuditGetReport({ auditId: 'aud-deadzone' }, 'owner-abc', { db, now: () => now });
			const summary = result.findings.find((f) => f.metadata?.summary === true);

			expect(summary?.metadata?.status).toBe('failed');
			expect(summary?.metadata?.aggregate).toBeNull();
			const batchFlip = calls.find(
				(c) =>
					c.sql.includes('UPDATE brand_audits') &&
					(c.binds as unknown[])[0] === 'failed',
			);
			expect(batchFlip).toBeDefined();
		});

		it('still returns notReady when no targets exist yet (audit just queued, consumer not started)', async () => {
			const { brandAuditGetReport } = await import('../src/tools/brand-audit-get-report');
			const { db } = makeMockD1({
				audit: { id: 'aud-fresh', owner_id: 'owner-abc', status: 'queued', results_json: null, format: 'json' },
				targets: [],
			});

			const result = await brandAuditGetReport({ auditId: 'aud-fresh' }, 'owner-abc', { db });
			expect(result.findings.find((f) => f.metadata?.notReady === true)).toBeDefined();
		});
	});

	it('owner-scoping: someone else\'s auditId surfaces as notFound', async () => {
		const { brandAuditGetReport } = await import('../src/tools/brand-audit-get-report');
		const { db } = makeMockD1({
			audit: { id: 'aud-2', owner_id: 'owner-other', status: 'completed' },
		});
		const result = await brandAuditGetReport(
			{ auditId: 'aud-2', target: 'apple.com' },
			'owner-abc',
			{ db },
		);
		expect(result.findings.find((f) => f.metadata?.notFound === true)).toBeDefined();
		expect(result.findings.find((f) => f.metadata?.accessDenied === true)).toBeUndefined();
	});
});
