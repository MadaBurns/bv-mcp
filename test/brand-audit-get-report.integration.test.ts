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
