// SPDX-License-Identifier: BUSL-1.1

/**
 * Tests for cscComplement surfacing in brand_audit_get_report and
 * CSC stage reporting in brand_audit_status.
 *
 * These features require a `stepStore` dep (operator-deploy only); without it
 * the fields are absent. The memory step store is used here to avoid D1 wiring.
 */

import { describe, it, expect } from 'vitest';
import { createMemoryBrandAuditStepStore } from '../src/lib/brand-audit-step-store';

// Minimal D1 mock: returns a completed audit row + completed target row
// for get-report tests, and a running audit + targets for status tests.
function makeD1ForGetReport(opts: {
	auditStatus?: string;
	targetStatus?: string;
	resultJson?: string | null;
} = {}) {
	const auditStatus = opts.auditStatus ?? 'completed';
	const targetStatus = opts.targetStatus ?? 'completed';
	const resultJson = opts.resultJson !== undefined ? opts.resultJson : JSON.stringify({ category: 'brand_discovery', score: 100, findings: [] });

	const db = {
		prepare(sql: string) {
			let binds: unknown[] = [];
			const stmt = {
				bind(...args: unknown[]) {
					binds = args;
					return stmt;
				},
				async first() {
					void binds;
					if (sql.includes('FROM brand_audits')) {
						return { id: 'a-1', owner_id: 'owner-1', status: auditStatus, results_json: null, format: 'json' };
					}
					if (sql.includes('FROM brand_audit_targets')) {
						return {
							audit_id: 'a-1',
							target: 'ford.com',
							status: targetStatus,
							result_json: resultJson,
							pdf_r2_key: null,
							error: null,
							completed_at: 1_750_000_100_000,
							created_at: 1_750_000_000_000,
						};
					}
					return null;
				},
				async all() {
					return { results: [], success: true, meta: {} };
				},
				async run() {
					return { success: true, meta: {} };
				},
			};
			return stmt;
		},
	} as unknown as D1Database;
	return db;
}

function makeD1ForStatus(opts: { targets?: { target: string }[] } = {}) {
	const targetList = opts.targets ?? [{ target: 'ford.com' }];
	const db = {
		prepare(sql: string) {
			let binds: unknown[] = [];
			const stmt = {
				bind(...args: unknown[]) {
					binds = args;
					return stmt;
				},
				async first() {
					void binds;
					if (sql.includes('FROM brand_audits')) {
						return {
							id: 'a-1',
							owner_id: 'owner-1',
							status: 'running',
							total_targets: targetList.length,
							completed_targets: 0,
							format: 'json',
							created_at: 1_750_000_000_000,
							updated_at: 1_750_000_000_000,
							completed_at: null,
						};
					}
					return null;
				},
				async all() {
					void binds;
					if (sql.includes('FROM brand_audit_targets')) {
						return {
							results: targetList.map((t) => ({
								audit_id: 'a-1',
								target: t.target,
								status: 'completed',
								created_at: 1_750_000_000_000,
								completed_at: 1_750_000_080_000,
								error: null,
								pdf_r2_key: null,
								result_json: JSON.stringify({ category: 'brand_discovery', score: 100, findings: [] }),
							})),
							success: true,
							meta: {},
						};
					}
					return { results: [], success: true, meta: {} };
				},
				async run() {
					return { success: true, meta: {} };
				},
			};
			return stmt;
		},
	} as unknown as D1Database;
	return db;
}

describe('brand_audit_get_report with cscComplement', () => {
	it('attaches cscComplement from csc_complement_full when present', async () => {
		const { brandAuditGetReport } = await import('../src/tools/brand-audit-get-report');
		const stepStore = createMemoryBrandAuditStepStore();
		await stepStore.put({ auditId: 'a-1', target: 'ford.com', step: 'csc_complement_full', status: 'completed', payload: { viewVersion: 1, reportId: 'csc_rpt_full' } });
		await stepStore.put({ auditId: 'a-1', target: 'ford.com', step: 'csc_complement_fast', status: 'completed', payload: { viewVersion: 1, reportId: 'csc_rpt_fast' } });

		const result = await brandAuditGetReport({ auditId: 'a-1', target: 'ford.com' }, 'owner-1', {
			db: makeD1ForGetReport(),
			stepStore,
		});

		const summary = result.findings.find((f) => f.metadata?.summary === true);
		expect(summary?.metadata?.cscComplement).toMatchObject({ reportId: 'csc_rpt_full' });
	});

	it('falls back to csc_complement_fast when full is absent', async () => {
		const { brandAuditGetReport } = await import('../src/tools/brand-audit-get-report');
		const stepStore = createMemoryBrandAuditStepStore();
		await stepStore.put({ auditId: 'a-1', target: 'ford.com', step: 'csc_complement_fast', status: 'completed', payload: { viewVersion: 1, reportId: 'csc_rpt_fast' } });

		const result = await brandAuditGetReport({ auditId: 'a-1', target: 'ford.com' }, 'owner-1', {
			db: makeD1ForGetReport(),
			stepStore,
		});

		const summary = result.findings.find((f) => f.metadata?.summary === true);
		expect(summary?.metadata?.cscComplement).toMatchObject({ reportId: 'csc_rpt_fast' });
	});

	it('does not attach cscComplement when neither step is completed', async () => {
		const { brandAuditGetReport } = await import('../src/tools/brand-audit-get-report');
		const stepStore = createMemoryBrandAuditStepStore();

		const result = await brandAuditGetReport({ auditId: 'a-1', target: 'ford.com' }, 'owner-1', {
			db: makeD1ForGetReport(),
			stepStore,
		});

		const summary = result.findings.find((f) => f.metadata?.summary === true);
		expect(summary?.metadata?.cscComplement).toBeUndefined();
	});

	it('does not attach cscComplement when stepStore is omitted', async () => {
		const { brandAuditGetReport } = await import('../src/tools/brand-audit-get-report');

		const result = await brandAuditGetReport({ auditId: 'a-1', target: 'ford.com' }, 'owner-1', {
			db: makeD1ForGetReport(),
		});

		const summary = result.findings.find((f) => f.metadata?.summary === true);
		expect(summary?.metadata?.cscComplement).toBeUndefined();
	});
});

describe('brand_audit_status CSC stages', () => {
	it('reports fast_ready when csc_complement_fast is completed but full is absent', async () => {
		const { brandAuditStatus } = await import('../src/tools/brand-audit-status');
		const stepStore = createMemoryBrandAuditStepStore();
		await stepStore.put({ auditId: 'a-1', target: 'ford.com', step: 'csc_complement_fast', status: 'completed', payload: {} });

		const result = await brandAuditStatus('a-1', 'owner-1', {
			db: makeD1ForStatus(),
			stepStore,
			now: () => 1_750_000_100_000,
		});

		const summary = result.findings.find((f) => f.metadata?.summary === true);
		expect(summary?.metadata?.stage).toBe('fast_ready');
	});

	it('reports deep_ready when csc_complement_full is completed', async () => {
		const { brandAuditStatus } = await import('../src/tools/brand-audit-status');
		const stepStore = createMemoryBrandAuditStepStore();
		await stepStore.put({ auditId: 'a-1', target: 'ford.com', step: 'csc_complement_full', status: 'completed', payload: {} });
		await stepStore.put({ auditId: 'a-1', target: 'ford.com', step: 'csc_complement_fast', status: 'completed', payload: {} });

		const result = await brandAuditStatus('a-1', 'owner-1', {
			db: makeD1ForStatus(),
			stepStore,
			now: () => 1_750_000_100_000,
		});

		const summary = result.findings.find((f) => f.metadata?.summary === true);
		expect(summary?.metadata?.stage).toBe('deep_ready');
	});

	it('does not report stage when no CSC steps are complete', async () => {
		const { brandAuditStatus } = await import('../src/tools/brand-audit-status');
		const stepStore = createMemoryBrandAuditStepStore();

		const result = await brandAuditStatus('a-1', 'owner-1', {
			db: makeD1ForStatus(),
			stepStore,
			now: () => 1_750_000_100_000,
		});

		const summary = result.findings.find((f) => f.metadata?.summary === true);
		expect(summary?.metadata?.stage).toBeUndefined();
	});

	it('does not report stage when stepStore is omitted', async () => {
		const { brandAuditStatus } = await import('../src/tools/brand-audit-status');

		const result = await brandAuditStatus('a-1', 'owner-1', {
			db: makeD1ForStatus(),
			now: () => 1_750_000_100_000,
		});

		const summary = result.findings.find((f) => f.metadata?.summary === true);
		expect(summary?.metadata?.stage).toBeUndefined();
	});

	it('reports deep_ready if any target has full completed (multi-target audit)', async () => {
		const { brandAuditStatus } = await import('../src/tools/brand-audit-status');
		const stepStore = createMemoryBrandAuditStepStore();
		// target1 has fast only; target2 has full — deep_ready should win
		await stepStore.put({ auditId: 'a-1', target: 'ford.com', step: 'csc_complement_fast', status: 'completed', payload: {} });
		await stepStore.put({ auditId: 'a-1', target: 'lincoln.com', step: 'csc_complement_full', status: 'completed', payload: {} });

		const result = await brandAuditStatus('a-1', 'owner-1', {
			db: makeD1ForStatus({ targets: [{ target: 'ford.com' }, { target: 'lincoln.com' }] }),
			stepStore,
			now: () => 1_750_000_100_000,
		});

		const summary = result.findings.find((f) => f.metadata?.summary === true);
		expect(summary?.metadata?.stage).toBe('deep_ready');
	});
});
