// SPDX-License-Identifier: BUSL-1.1
/**
 * Contract: brand-discovery sidecar v3 shape (tiered-mode reports).
 *
 * Brand-discovery task 9 splits the legacy single `buckets` block into
 * `ownedPortfolio` (tier 0/1/2/3 — what the brand owns) + `impersonationSurface`
 * (tier 4 — what's masquerading). The QA script, the Markdown renderer, the
 * PDF renderer, and the bv-web sidecar reader all parse this shape; locking it
 * here prevents silent drift across renderers.
 *
 * Classic-mode reports continue to emit `qaSchemaVersion: 1` with the legacy
 * `buckets` block — pinned by the existing model spec, NOT by this contract.
 *
 * Per testing-methodology.md principle 3: Zod schemas ARE the inter-service
 * contract.
 */

import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import { buildDiscoveryReportModel, buildDiscoveryReportSidecar } from '../helpers/discovery-report-model';
import type { BrandAuditResultLike } from '../helpers/discovery-report-model';

const TierStatusSchema = z.enum(['ok', 'degraded', 'partial', 'timeout', 'skipped']);

const SidecarV3Schema = z.object({
	qaSchemaVersion: z.literal(3),
	discoveryMode: z.literal('tiered'),
	ownedPortfolio: z.object({
		tenantDeclared: z.array(z.string()),
		graphSurfaced: z.array(z.string()),
		declaredEvidence: z.array(z.string()),
		inferred: z.object({
			consolidated: z.array(z.string()),
			shadowIt: z.array(z.string()),
			indeterminate: z.array(z.string()),
		}),
	}),
	impersonationSurface: z.array(
		z.object({
			domain: z.string(),
			lookalikeScore: z.number(),
			livenessSignals: z.array(z.string()),
			scoreAlertContext: z
				.object({
					alertType: z.string(),
					transition: z.string(),
				})
				.optional(),
		}),
	),
	performance: z.object({
		steps: z.array(z.any()),
		stepStatusCounts: z.record(z.string(), z.number()),
		tiers: z.object({
			tier0Count: z.number(),
			tier1Count: z.number(),
			tier2Count: z.number(),
			tier3Count: z.number(),
			tier4Count: z.number(),
			tier0Status: TierStatusSchema,
			tier1Status: TierStatusSchema,
			tier2Status: TierStatusSchema,
			tier3FallbackTriggered: z.number(),
			tier1Freshness: z
				.object({
					overallStaleness: z.enum(['fresh', 'partial', 'stale', 'very_stale']),
				})
				.optional(),
			optOutsFiltered: z.number(),
		}),
	}),
});

function tieredResult(): BrandAuditResultLike {
	return {
		category: 'brand_discovery',
		passed: true,
		score: 100,
		findings: [
			{
				category: 'brand_discovery',
				title: 'Brand audit: classified',
				severity: 'info',
				detail: '',
				metadata: {
					summary: true,
					target: 'example.com',
					total: 6,
					consolidated: 4,
					shadowIt: 1,
					indeterminate: 1,
					impersonation: 0,
					targetRegistrar: 'Example Registrar',
					targetRegistrarSource: 'rdap',
					targetRegistrant: 'Example Inc.',
				},
			},
			// Tier 0 — tenant-declared.
			{
				category: 'brand_discovery',
				title: 'Brand candidate: tenant.example.com',
				severity: 'info',
				detail: '',
				metadata: {
					candidate: 'tenant.example.com',
					bucket: 'consolidated',
					tier: 0,
					confidenceTier: 'high',
					reasons: ['tier 0 (tenant-declared)'],
					signals: ['markov_gen'],
					combinedConfidence: 1.0,
					registrar: 'Example Registrar',
					registrarSource: 'rdap',
				},
			},
			// Tier 1 — graph-surfaced.
			{
				category: 'brand_discovery',
				title: 'Brand candidate: graph-a.example',
				severity: 'low',
				detail: '',
				metadata: {
					candidate: 'graph-a.example',
					bucket: 'consolidated',
					tier: 1,
					confidenceTier: 'high',
					reasons: ['tier 1 (graph-surfaced)'],
					signals: ['ns'],
					combinedConfidence: 0.9,
					registrar: 'Example Registrar',
					registrarSource: 'rdap',
				},
			},
			{
				category: 'brand_discovery',
				title: 'Brand candidate: graph-b.example',
				severity: 'low',
				detail: '',
				metadata: {
					candidate: 'graph-b.example',
					bucket: 'consolidated',
					tier: 1,
					confidenceTier: 'high',
					reasons: ['tier 1 (graph-surfaced)'],
					signals: ['ns'],
					combinedConfidence: 0.9,
					registrar: 'Example Registrar',
					registrarSource: 'rdap',
				},
			},
			// Tier 2 — declared evidence.
			{
				category: 'brand_discovery',
				title: 'Brand candidate: declared.example',
				severity: 'low',
				detail: '',
				metadata: {
					candidate: 'declared.example',
					bucket: 'consolidated',
					tier: 2,
					confidenceTier: 'medium',
					reasons: ['tier 2 (declared/witnessed)'],
					signals: ['dmarc_rua'],
					combinedConfidence: 0.7,
					registrar: 'Example Registrar',
					registrarSource: 'rdap',
				},
			},
			// Tier 3 (inferred) — shadowIt.
			{
				category: 'brand_discovery',
				title: 'Brand candidate: shadow.example',
				severity: 'medium',
				detail: '',
				metadata: {
					candidate: 'shadow.example',
					bucket: 'shadowIt',
					confidenceTier: 'medium',
					reasons: ['different registrar, shared infra'],
					signals: ['san'],
					combinedConfidence: 0.6,
					registrar: 'Other Registrar',
					registrarSource: 'rdap',
				},
			},
			// Tier 3 (inferred) — indeterminate.
			{
				category: 'brand_discovery',
				title: 'Brand candidate: maybe.example',
				severity: 'low',
				detail: '',
				metadata: {
					candidate: 'maybe.example',
					bucket: 'indeterminate',
					confidenceTier: 'low',
					reasons: ['weak signals'],
					signals: ['markov_gen'],
					combinedConfidence: 0.45,
					registrar: 'Unknown',
					registrarSource: 'unknown',
				},
			},
			// Tier 4 — impersonation surface.
			{
				category: 'brand_discovery',
				title: 'Brand candidate: examp1e.com',
				severity: 'high',
				detail: '',
				metadata: {
					candidate: 'examp1e.com',
					bucket: 'impersonationSurface',
					tier: 4,
					confidenceTier: 'low',
					reasons: ['tier 4 (impersonation surface)'],
					signals: ['active_lookalike'],
					combinedConfidence: 0.3,
					registrar: 'Cheap Reg',
					registrarSource: 'rdap',
					lookalikeScore: 0.92,
					scoreAlertContext: { alertType: 'newly_active', transition: 'parked->active' },
				},
			},
		],
	};
}

const TIERED_PERFORMANCE = {
	elapsedMs: 1234,
	steps: [{ name: 'discovery', status: 'completed' as const, startedAtMs: 0, finishedAtMs: 500, elapsedMs: 500 }],
	stepStatusCounts: { completed: 3, partial: 0, failed: 0, skipped: 0 },
	dns: { queries: 10, cacheHits: 5, errors: 0, cacheHitRatio: 0.5 },
	rdap: { queries: 7, cacheHits: 2, errors: 0, cacheHitRatio: 0.29 },
	warnings: [],
};

const TIERED_TIERS = {
	tier0Count: 1,
	tier1Count: 2,
	tier2Count: 1,
	tier3Count: 1,
	tier4Count: 1,
	tier0Status: 'ok' as const,
	tier1Status: 'ok' as const,
	tier2Status: 'ok' as const,
	tier3FallbackTriggered: 0,
	tier1Freshness: { overallStaleness: 'fresh' as const },
	optOutsFiltered: 0,
};

describe('brand-discovery sidecar v3 contract (tiered mode)', () => {
	it('emits v3 shape when discoveryMode === "tiered"', () => {
		const model = buildDiscoveryReportModel({
			target: 'example.com',
			primaryRegistrar: 'Example Registrar',
			result: tieredResult(),
		});
		const sidecar = buildDiscoveryReportSidecar(model, {
			auditId: 'aud-tiered-1',
			generatedAt: '2026-05-20T00:00:00.000Z',
			serverVersion: '2.22.0',
			sourceMode: 'mcp',
			runId: 'run-tiered-1',
			requestedAt: '2026-05-20T00:00:00.000Z',
			depthMode: 'deep',
			discoveryMode: 'tiered',
			performance: TIERED_PERFORMANCE,
			tiers: TIERED_TIERS,
		});

		const parsed = SidecarV3Schema.safeParse(sidecar);
		expect(parsed.success, parsed.success ? '' : JSON.stringify(parsed.error.issues, null, 2)).toBe(true);
	});

	it('routes tier-tagged candidates into the correct ownedPortfolio sub-bucket', () => {
		const model = buildDiscoveryReportModel({
			target: 'example.com',
			primaryRegistrar: 'Example Registrar',
			result: tieredResult(),
		});
		const sidecar = buildDiscoveryReportSidecar(model, {
			auditId: 'aud-tiered-1',
			generatedAt: '2026-05-20T00:00:00.000Z',
			serverVersion: '2.22.0',
			sourceMode: 'mcp',
			runId: 'run-tiered-1',
			requestedAt: '2026-05-20T00:00:00.000Z',
			depthMode: 'deep',
			discoveryMode: 'tiered',
			performance: TIERED_PERFORMANCE,
			tiers: TIERED_TIERS,
		}) as unknown as {
			qaSchemaVersion: 3;
			discoveryMode: 'tiered';
			ownedPortfolio: {
				tenantDeclared: string[];
				graphSurfaced: string[];
				declaredEvidence: string[];
				inferred: { consolidated: string[]; shadowIt: string[]; indeterminate: string[] };
			};
			impersonationSurface: Array<{ domain: string; lookalikeScore: number; scoreAlertContext?: { alertType: string; transition: string } }>;
		};

		expect(sidecar.qaSchemaVersion).toBe(3);
		expect(sidecar.discoveryMode).toBe('tiered');
		expect(sidecar.ownedPortfolio.tenantDeclared).toEqual(['tenant.example.com']);
		expect(sidecar.ownedPortfolio.graphSurfaced.sort()).toEqual(['graph-a.example', 'graph-b.example']);
		expect(sidecar.ownedPortfolio.declaredEvidence).toEqual(['declared.example']);
		expect(sidecar.ownedPortfolio.inferred.shadowIt).toEqual(['shadow.example']);
		expect(sidecar.ownedPortfolio.inferred.indeterminate).toEqual(['maybe.example']);
		// No inferred-consolidated in this fixture (all consolidated have a tier).
		expect(sidecar.ownedPortfolio.inferred.consolidated).toEqual([]);

		expect(sidecar.impersonationSurface).toHaveLength(1);
		expect(sidecar.impersonationSurface[0].domain).toBe('examp1e.com');
		expect(sidecar.impersonationSurface[0].lookalikeScore).toBe(0.92);
		expect(sidecar.impersonationSurface[0].scoreAlertContext).toEqual({ alertType: 'newly_active', transition: 'parked->active' });
	});

	it('preserves tier-1 graph provenance so reports do not show graph evidence as only Markov Variant', () => {
		const model = buildDiscoveryReportModel({
			target: 'brand.example',
			primaryRegistrar: 'Example Registrar',
			result: {
				category: 'brand_discovery',
				findings: [
					{
						category: 'brand_discovery',
						title: 'summary',
						severity: 'info',
						detail: 'summary',
						metadata: { summary: true },
					},
					{
						category: 'brand_discovery',
						title: 'Brand candidate: owned.example',
						severity: 'info',
						detail: 'candidate',
						metadata: {
							candidate: 'owned.example',
							bucket: 'consolidated',
							tier: 1,
							signals: ['markov_gen'],
							combinedConfidence: 0.92,
							registrar: 'Example Registrar',
							registrarSource: 'rdap',
							reasons: ['tier 1 graph evidence'],
							graphEvidence: {
								signalTypes: ['spf_include'],
								numSharedSignals: 1,
								maxSpecificity: 0.7,
								signalType: 'spf_include',
								signalValue: '_spf.brand.example',
							},
						},
					},
				],
			},
		});

		const sidecar = buildDiscoveryReportSidecar(model, {
			sourceMode: 'mcp',
			generatedAt: '2026-05-20T00:00:00.000Z',
			serverVersion: 'test',
			runId: 'quality-test',
			requestedAt: '2026-05-20T00:00:00.000Z',
			depthMode: 'deep',
			discoveryMode: 'tiered',
			tiers: {
				tier0Count: 0,
				tier1Count: 1,
				tier2Count: 0,
				tier3Count: 0,
				tier4Count: 0,
				tier0Status: 'ok',
				tier1Status: 'ok',
				tier2Status: 'ok',
				tier3FallbackTriggered: 0,
				optOutsFiltered: 0,
			},
		});

		expect(sidecar.buckets.consolidated[0]).toMatchObject({
			domain: 'owned.example',
			evidence: 'Tier 1 Graph: SPF Include; specificity 0.70; shared signals 1 (0.92)',
			graphEvidence: {
				signalTypes: ['spf_include'],
				numSharedSignals: 1,
				maxSpecificity: 0.7,
				signalType: 'spf_include',
				signalValue: '_spf.brand.example',
			},
		});
	});

	it('classic mode (default discoveryMode) emits v1 — sidecar is byte-identical to legacy', () => {
		const model = buildDiscoveryReportModel({
			target: 'example.com',
			primaryRegistrar: 'Example Registrar',
			result: {
				category: 'brand_discovery',
				passed: true,
				score: 100,
				findings: [
					{
						category: 'brand_discovery',
						title: 'classic candidate',
						severity: 'low',
						detail: '',
						metadata: {
							candidate: 'classic.example',
							bucket: 'consolidated',
							signals: ['ns'],
							combinedConfidence: 0.9,
							registrar: 'Example Registrar',
							registrarSource: 'rdap',
						},
					},
				],
			},
		});
		const sidecar = buildDiscoveryReportSidecar(model, {
			auditId: 'aud-classic-1',
			generatedAt: '2026-05-20T00:00:00.000Z',
			serverVersion: '2.22.0',
			sourceMode: 'mcp',
			runId: 'run-classic-1',
			requestedAt: '2026-05-20T00:00:00.000Z',
			depthMode: 'standard',
		}) as unknown as Record<string, unknown>;
		// v1 sidecar must NOT have v3 keys — proves classic-mode invariance.
		expect(sidecar.qaSchemaVersion).toBe(1);
		expect(sidecar.ownedPortfolio).toBeUndefined();
		expect(sidecar.impersonationSurface).toBeUndefined();
	});
});
