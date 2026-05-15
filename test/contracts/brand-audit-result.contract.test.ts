// SPDX-License-Identifier: BUSL-1.1
/**
 * Contract: brand_audit_single CheckResult response shape.
 *
 * The orchestrator returns a CheckResult whose findings encode a bucket-labeled
 * candidate list + a summary. Downstream consumers (the markdown formatter,
 * the PDF renderer in Phase 3, the queue consumer in Phase 2, the upcoming
 * bv-web UI) parse this shape — locking it here prevents silent drift.
 *
 * Per testing-methodology.md principle 3: Zod schemas ARE the inter-service contract.
 */

import { describe, it, expect, vi } from 'vitest';
import { z } from 'zod';
import type { BrandAuditSingleDeps } from '../../src/tools/brand-audit-single';
import type { CheckResult, Finding } from '../../src/lib/scoring';

const BucketSchema = z.enum(['consolidated', 'shadowIt', 'indeterminate', 'impersonation']);
const ConfidenceTierSchema = z.enum(['high', 'medium', 'low']);
const RegistrarSourceSchema = z.enum(['rdap', 'whois', 'redacted', 'notfound', 'unknown']);
const SeveritySchema = z.enum(['critical', 'high', 'medium', 'low', 'info']);

const CandidateFindingMetadataSchema = z.object({
	candidate: z.string().min(1),
	bucket: BucketSchema,
	confidenceTier: ConfidenceTierSchema,
	note: z.string().optional(),
	reasons: z.array(z.string()),
	signals: z.array(z.string()),
	combinedConfidence: z.number().min(0).max(1),
	registrar: z.string(),
	registrarSource: RegistrarSourceSchema,
	registrant: z.string().nullable(),
});

const SummaryFindingMetadataSchema = z.object({
	summary: z.literal(true),
	target: z.string().min(1),
	consolidated: z.number().int().nonnegative(),
	shadowIt: z.number().int().nonnegative(),
	indeterminate: z.number().int().nonnegative(),
	impersonation: z.number().int().nonnegative(),
	targetRegistrar: z.string(),
	targetRegistrarSource: RegistrarSourceSchema,
	targetRegistrant: z.string().nullable(),
	total: z.number().int().nonnegative().optional(),
	missingControl: z.boolean().optional(),
});

const FindingSchema = z.object({
	category: z.string(),
	title: z.string(),
	severity: SeveritySchema,
	detail: z.string(),
	metadata: z.record(z.string(), z.unknown()).optional(),
});

function summaryFinding(seed: string, surfaced: number): Finding {
	return {
		category: 'brand_discovery',
		title: `Brand-domain discovery: ${surfaced} candidate(s) at confidence ≥ 0.5`,
		severity: 'info',
		detail: `Seed=${seed}`,
		metadata: { summary: true, signals: ['san'], signalStatus: {}, minConfidence: 0.5, totalAggregated: surfaced, surfaced },
	};
}

function candidateFinding(domain: string, signals: string[], conf: number): Finding {
	return {
		category: 'brand_discovery',
		title: `Discovered candidate: ${domain}`,
		severity: conf >= 0.85 ? 'low' : 'info',
		detail: `Found via ${signals.length} signal(s): ${signals.join(', ')}`,
		metadata: { candidate: domain, signals, combinedConfidence: conf, sources: {} },
	};
}

function rdapResult(registrar: string, source: 'rdap' | 'unknown' | 'notfound' | 'redacted' | 'whois', registrant: string | null = null): CheckResult {
	return {
		category: 'rdap',
		score: 100,
		findings: [
			{
				category: 'rdap',
				title: 'RDAP',
				severity: 'info',
				detail: `${registrar}`,
				metadata: { registrar, registrarSource: source, registrant },
			},
		],
	};
}

function discovery(seed: string, candidates: Array<{ domain: string; signals: string[]; conf: number }>): CheckResult {
	return {
		category: 'brand_discovery',
		score: 100,
		findings: [summaryFinding(seed, candidates.length), ...candidates.map((c) => candidateFinding(c.domain, c.signals, c.conf))],
	};
}

function makeDeps(over: Partial<BrandAuditSingleDeps> = {}): BrandAuditSingleDeps {
	return {
		discoverBrandDomains: vi.fn().mockResolvedValue(discovery('apple.com', [])),
		checkRdapLookup: vi.fn().mockResolvedValue(rdapResult('MarkMonitor Inc.', 'rdap', 'Apple Inc.')),
		enforceQuota: vi.fn().mockResolvedValue({ allowed: true, remaining: 49, limit: 50 }),
		...over,
	};
}

describe('brand_audit_single response contract', () => {
	it('every non-summary finding matches CandidateFindingMetadataSchema', async () => {
		const { brandAuditSingle } = await import('../../src/tools/brand-audit-single');
		const candidates = [
			{ domain: 'apple.net', signals: ['ns'], conf: 0.95 },
			{ domain: 'apple-id.co', signals: ['markov_gen'], conf: 0.45 },
		];
		const deps = makeDeps({
			discoverBrandDomains: vi.fn().mockResolvedValue(discovery('apple.com', candidates)),
			checkRdapLookup: vi.fn().mockResolvedValue(rdapResult('MarkMonitor Inc.', 'rdap', 'Apple Inc.')),
		});
		const result = await brandAuditSingle('apple.com', { min_confidence: 0.4 }, deps);

		for (const f of result.findings) {
			expect(FindingSchema.safeParse(f).success).toBe(true);
			if (f.metadata?.candidate) {
				const parsed = CandidateFindingMetadataSchema.safeParse(f.metadata);
				expect(parsed.success, JSON.stringify(parsed.success ? null : parsed.error.issues)).toBe(true);
			}
		}
	});

	it('exactly one finding has summary=true and matches SummaryFindingMetadataSchema', async () => {
		const { brandAuditSingle } = await import('../../src/tools/brand-audit-single');
		const deps = makeDeps({
			discoverBrandDomains: vi.fn().mockResolvedValue(discovery('apple.com', [{ domain: 'apple.net', signals: ['ns'], conf: 0.95 }])),
		});
		const result = await brandAuditSingle('apple.com', {}, deps);
		const summaries = result.findings.filter((f) => f.metadata?.summary === true);
		expect(summaries).toHaveLength(1);
		const parsed = SummaryFindingMetadataSchema.safeParse(summaries[0].metadata);
		expect(parsed.success, JSON.stringify(parsed.success ? null : parsed.error.issues)).toBe(true);
	});

	it('quota-exceeded result has exactly one error finding with quotaExceeded=true', async () => {
		const { brandAuditSingle } = await import('../../src/tools/brand-audit-single');
		const deps = makeDeps({
			enforceQuota: vi.fn().mockResolvedValue({ allowed: false, remaining: 0, limit: 50 }),
		});
		const result = await brandAuditSingle('apple.com', {}, deps);
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].severity).toBe('high');
		expect(result.findings[0].metadata?.quotaExceeded).toBe(true);
	});

	it('result.category is "brand_discovery" (reuses existing category to avoid scoring-union expansion)', async () => {
		const { brandAuditSingle } = await import('../../src/tools/brand-audit-single');
		const deps = makeDeps();
		const result = await brandAuditSingle('apple.com', {}, deps);
		expect(result.category).toBe('brand_discovery');
	});
});
