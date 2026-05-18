// SPDX-License-Identifier: BUSL-1.1
/**
 * Contract: brand_audit_status + brand_audit_batch_start + brand_audit_get_report
 * response shapes.
 *
 * Downstream consumers (bv-web polling UI, future PDF renderer in Phase 3, MCP
 * clients building status dashboards) parse these shapes. Locking them here
 * prevents silent drift between producer and consumer.
 *
 * Per testing-methodology.md principle 3: Zod schemas ARE the inter-service contract.
 */

import { describe, it, expect, vi } from 'vitest';
import { z } from 'zod';
import type { BrandAuditStatusDeps } from '../../src/tools/brand-audit-status';
import type { BrandAuditGetReportDeps } from '../../src/tools/brand-audit-get-report';
import type { BrandAuditBatchStartDeps } from '../../src/tools/brand-audit-batch-start';

const StatusEnum = z.enum(['queued', 'running', 'completed', 'failed']);
const SeveritySchema = z.enum(['critical', 'high', 'medium', 'low', 'info']);
const FormatEnum = z.enum(['json', 'markdown', 'both']);

const BatchStartSummarySchema = z.object({
	summary: z.literal(true),
	auditId: z.string().min(1),
	queuedAt: z.number().int().nonnegative(),
	targetCount: z.number().int().positive(),
	etaSeconds: z.number().int().nonnegative(),
	format: FormatEnum,
	targets: z.array(z.string().min(1)),
});

const StatusTargetSchema = z.object({
	target: z.string().min(1),
	status: StatusEnum,
	createdAt: z.number().int().nonnegative(),
	completedAt: z.number().int().nullable(),
	error: z.string().nullable(),
	hasPdf: z.boolean(),
});

const StatusSummarySchema = z.object({
	summary: z.literal(true),
	auditId: z.string().min(1),
	status: StatusEnum,
	progress: z.string().regex(/^\d+\/\d+$/),
	completed: z.number().int().nonnegative(),
	total: z.number().int().positive(),
	format: z.string(),
	createdAt: z.number().int().nonnegative(),
	updatedAt: z.number().int().nonnegative(),
	completedAt: z.number().int().nullable(),
	ageMs: z.number().int().nonnegative(),
	updatedAgeMs: z.number().int().nonnegative(),
	targetStatusCounts: z.object({
		queued: z.number().int().nonnegative(),
		running: z.number().int().nonnegative(),
		completed: z.number().int().nonnegative(),
		failed: z.number().int().nonnegative(),
	}),
	warnings: z.array(z.string()),
	targets: z.array(StatusTargetSchema),
});

const GetReportTargetSummarySchema = z.object({
	summary: z.literal(true),
	auditId: z.string().min(1),
	target: z.string().min(1),
	status: StatusEnum,
	result: z.unknown(),
	error: z.string().nullable(),
	pdfUrl: z.string().nullable(),
	pdfPending: z.boolean(),
});

const GetReportAggregateSummarySchema = z.object({
	summary: z.literal(true),
	auditId: z.string().min(1),
	status: StatusEnum,
	format: z.string(),
	aggregate: z.unknown(),
});

const FindingSchema = z.object({
	category: z.string(),
	title: z.string(),
	severity: SeveritySchema,
	detail: z.string(),
	metadata: z.record(z.string(), z.unknown()).optional(),
});

function makeMockD1(rows: { audit?: unknown; target?: unknown; targets?: unknown[] }) {
	const db = {
		prepare(sql: string) {
			let binds: unknown[] = [];
			const stmt = {
				bind(...args: unknown[]) {
					binds = args;
					void binds;
					return stmt;
				},
				async first() {
					if (sql.includes('FROM brand_audits')) return rows.audit ?? null;
					if (sql.includes('FROM brand_audit_targets')) return rows.target ?? null;
					return null;
				},
				async all() {
					if (sql.includes('FROM brand_audit_targets')) return { results: rows.targets ?? [], success: true, meta: {} };
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

describe('brand_audit_batch_start response contract', () => {
	it('summary metadata matches BatchStartSummarySchema on the happy path', async () => {
		const { brandAuditBatchStart } = await import('../../src/tools/brand-audit-batch-start');
		const db = makeMockD1({});
		const deps: BrandAuditBatchStartDeps = {
			db,
			queue: { send: vi.fn().mockResolvedValue(undefined) },
			enforceQuota: vi.fn().mockResolvedValue({ allowed: true, remaining: 49, limit: 50 }),
			generateId: () => 'aud-contract-1',
			now: () => 1_750_000_000_000,
		};

		const result = await brandAuditBatchStart(['apple.com', 'brand-gamma.com'], { format: 'both' }, 'owner-x', deps);

		for (const f of result.findings) {
			expect(FindingSchema.safeParse(f).success).toBe(true);
		}
		const summary = result.findings.find((f) => f.metadata?.summary === true);
		expect(summary).toBeDefined();
		const parsed = BatchStartSummarySchema.safeParse(summary?.metadata);
		expect(parsed.success, JSON.stringify(parsed.success ? null : parsed.error.issues)).toBe(true);
	});
});

describe('brand_audit_status response contract', () => {
	it('summary metadata matches StatusSummarySchema on the happy path', async () => {
		const { brandAuditStatus } = await import('../../src/tools/brand-audit-status');
		const db = makeMockD1({
			audit: {
				id: 'aud-c',
				owner_id: 'owner-x',
				status: 'running',
				total_targets: 2,
				completed_targets: 1,
				format: 'both',
				created_at: 1, updated_at: 2, completed_at: null,
			},
			targets: [
				{ audit_id: 'aud-c', target: 'apple.com', status: 'completed', created_at: 1, completed_at: 5, error: null, pdf_r2_key: null },
				{ audit_id: 'aud-c', target: 'brand-gamma.com', status: 'running', created_at: 1, completed_at: null, error: null, pdf_r2_key: null },
			],
		});
		const deps: BrandAuditStatusDeps = { db };
		const result = await brandAuditStatus('aud-c', 'owner-x', deps);

		for (const f of result.findings) {
			expect(FindingSchema.safeParse(f).success).toBe(true);
		}
		const summary = result.findings.find((f) => f.metadata?.summary === true);
		const parsed = StatusSummarySchema.safeParse(summary?.metadata);
		expect(parsed.success, JSON.stringify(parsed.success ? null : parsed.error.issues)).toBe(true);
	});
});

describe('brand_audit_get_report response contract', () => {
	it('per-target summary matches GetReportTargetSummarySchema', async () => {
		const { brandAuditGetReport } = await import('../../src/tools/brand-audit-get-report');
		const db = makeMockD1({
			audit: { id: 'aud-c', owner_id: 'owner-x', status: 'completed', format: 'json', results_json: null },
			target: {
				audit_id: 'aud-c',
				target: 'apple.com',
				status: 'completed',
				result_json: JSON.stringify({ category: 'brand_discovery', score: 100, findings: [] }),
				error: null,
				completed_at: 5,
			},
		});
		const deps: BrandAuditGetReportDeps = { db };
		const result = await brandAuditGetReport({ auditId: 'aud-c', target: 'apple.com' }, 'owner-x', deps);
		const summary = result.findings.find((f) => f.metadata?.summary === true);
		const parsed = GetReportTargetSummarySchema.safeParse(summary?.metadata);
		expect(parsed.success, JSON.stringify(parsed.success ? null : parsed.error.issues)).toBe(true);
	});

	it('audit-level aggregate summary matches GetReportAggregateSummarySchema', async () => {
		const { brandAuditGetReport } = await import('../../src/tools/brand-audit-get-report');
		const db = makeMockD1({
			audit: {
				id: 'aud-c',
				owner_id: 'owner-x',
				status: 'completed',
				format: 'json',
				results_json: JSON.stringify({ totalCandidates: 5 }),
			},
		});
		const deps: BrandAuditGetReportDeps = { db };
		const result = await brandAuditGetReport({ auditId: 'aud-c' }, 'owner-x', deps);
		const summary = result.findings.find((f) => f.metadata?.summary === true);
		const parsed = GetReportAggregateSummarySchema.safeParse(summary?.metadata);
		expect(parsed.success, JSON.stringify(parsed.success ? null : parsed.error.issues)).toBe(true);
	});
});
