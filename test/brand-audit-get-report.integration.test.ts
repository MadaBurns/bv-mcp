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

	// #1129 — nothing in src/ writes `brand_audits.results_json`, so the audit-level
	// call returned `aggregate: null` with `passed: true, score: 100` on a completed
	// 2/2 audit. The aggregate is now derived from the per-target rows.
	describe('aggregate derived from per-target rows (#1129)', () => {
		type AggregateShape = { targets: Array<Record<string, unknown> & { target: string }> } & Record<string, unknown>;

		function targetResult(target: string, counts: { consolidated: number; shadowIt: number; indeterminate: number; impersonation: number }, score = 100) {
			const total = counts.consolidated + counts.shadowIt + counts.indeterminate + counts.impersonation;
			return JSON.stringify({
				category: 'brand_discovery',
				score,
				passed: score >= 50,
				findings: [
					{ category: 'brand_discovery', title: `summary ${target}`, severity: 'info', detail: '', metadata: { summary: true, target, total, ...counts } },
				],
			});
		}

		it('returns a non-null aggregate with correct counts for a completed 2/2 audit whose results_json is null', async () => {
			const { brandAuditGetReport } = await import('../src/tools/brand-audit-get-report');
			const { db } = makeMockD1({
				audit: { id: 'aud-2of2', owner_id: 'owner-abc', status: 'completed', results_json: null, format: 'both' },
				targets: [
					{
						audit_id: 'aud-2of2',
						target: 'blackveilsecurity.com',
						status: 'completed',
						result_json: targetResult('blackveilsecurity.com', { consolidated: 1, shadowIt: 0, indeterminate: 0, impersonation: 0 }),
						pdf_r2_key: 'k1',
						error: null,
						created_at: 1,
						completed_at: 2,
					},
					{
						audit_id: 'aud-2of2',
						target: 'example.com',
						status: 'completed',
						result_json: targetResult('example.com', { consolidated: 2, shadowIt: 1, indeterminate: 3, impersonation: 1 }, 40),
						pdf_r2_key: null,
						error: null,
						created_at: 1,
						completed_at: 3,
					},
				],
			});

			const result = await brandAuditGetReport({ auditId: 'aud-2of2' }, 'owner-abc', { db });
			const summary = result.findings.find((f) => f.metadata?.summary === true);
			const aggregate = summary?.metadata?.aggregate as AggregateShape | null;
			expect(aggregate).not.toBeNull();
			expect(aggregate).toMatchObject({
				source: 'derived_from_targets',
				totalTargets: 2,
				measuredTargets: 2,
				targetStatusCounts: { queued: 0, running: 0, completed: 2, failed: 0 },
				rollup: { totalCandidates: 8, consolidated: 3, shadowIt: 1, indeterminate: 3, impersonation: 1 },
			});
			expect(aggregate?.targets).toHaveLength(2);
			expect(aggregate?.targets[1]).toMatchObject({ target: 'example.com', status: 'completed', measured: true, total: 7, impersonation: 1, score: 40 });
			// Verdict follows the worst measured target, never a blanket 100.
			expect(result.score).toBe(40);
			expect(result.passed).toBe(false);
			expect(result.checkStatus).toBeUndefined();
		});

		it('excludes failed and unmeasured targets from the rollup', async () => {
			const { brandAuditGetReport } = await import('../src/tools/brand-audit-get-report');
			const { db } = makeMockD1({
				audit: { id: 'aud-mixed', owner_id: 'owner-abc', status: 'completed', results_json: null, format: 'json' },
				targets: [
					{ target: 'a.com', status: 'completed', result_json: targetResult('a.com', { consolidated: 2, shadowIt: 0, indeterminate: 0, impersonation: 0 }), error: null, created_at: 1 },
					{ target: 'b.com', status: 'failed', result_json: null, error: 'boom', created_at: 1 },
					{
						target: 'c.com',
						status: 'completed',
						result_json: JSON.stringify({ category: 'brand_discovery', score: 0, passed: false, checkStatus: 'error', partial: true, findings: [] }),
						error: null,
						created_at: 1,
					},
				],
			});

			const result = await brandAuditGetReport({ auditId: 'aud-mixed' }, 'owner-abc', { db });
			const aggregate = result.findings.find((f) => f.metadata?.summary === true)?.metadata?.aggregate as AggregateShape;
			expect(aggregate).toMatchObject({
				totalTargets: 3,
				measuredTargets: 1,
				targetStatusCounts: { completed: 2, failed: 1 },
				rollup: { totalCandidates: 2, consolidated: 2 },
			});
			expect(aggregate.targets.find((t) => t.target === 'b.com')).toMatchObject({ status: 'failed', measured: false, error: 'boom' });
			expect(aggregate.targets.find((t) => t.target === 'c.com')).toMatchObject({ measured: false });
			expect(result.partial).toBe(true);
		});

		it('abstains (checkStatus error, score 0, passed false) when no target completed with a result', async () => {
			const { brandAuditGetReport } = await import('../src/tools/brand-audit-get-report');
			const { db } = makeMockD1({
				audit: { id: 'aud-none', owner_id: 'owner-abc', status: 'failed', results_json: null, format: 'json' },
				targets: [
					{ target: 'a.com', status: 'failed', result_json: null, error: 'boom', created_at: 1 },
					{ target: 'b.com', status: 'failed', result_json: null, error: 'boom', created_at: 1 },
				],
			});

			const result = await brandAuditGetReport({ auditId: 'aud-none' }, 'owner-abc', { db });
			expect(result.checkStatus).toBe('error');
			expect(result.score).toBe(0);
			expect(result.passed).toBe(false);
			expect(result.partial).toBe(true);
			const summary = result.findings.find((f) => f.metadata?.summary === true);
			expect(summary?.metadata?.aggregateUnavailable).toBe(true);
			expect(summary?.metadata?.aggregate).toBeNull();
			expect(summary?.metadata?.missingControl).toBeUndefined();
		});
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
