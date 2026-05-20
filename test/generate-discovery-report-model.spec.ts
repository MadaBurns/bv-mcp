// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import { buildDiscoveryReportModel, buildDiscoveryReportSidecar } from './helpers/discovery-report-model';

describe('discovery report model', () => {
	it('splits authorized vendor dependencies from real Shadow IT ARR opportunities', () => {
		const model = buildDiscoveryReportModel({
			target: 'brand-eta.com',
			primaryRegistrar: 'CSC Corporate Domains, Inc.',
			result: {
				category: 'brand_discovery',
				passed: true,
				score: 100,
				findings: [
					{
						category: 'brand_discovery',
						title: 'Brand candidate: pphosted.com',
						severity: 'low',
						detail: '',
						metadata: {
							candidate: 'pphosted.com',
							bucket: 'indeterminate',
							relationshipType: 'authorized_vendor_dependency',
							signals: ['spf_include_seed'],
							registrar: 'MarkMonitor Inc.',
							registrarSource: 'rdap',
							combinedConfidence: 0.85,
							reasons: ['authorized vendor dependency via seed SPF delegation'],
						},
					},
					{
						category: 'brand_discovery',
						title: 'Brand candidate: bankofamerica.ca',
						severity: 'medium',
						detail: '',
						metadata: {
							candidate: 'bankofamerica.ca',
							bucket: 'shadowIt',
							relationshipType: 'owned_off_primary_registrar',
							signals: ['markov_gen', 'ns', 'spf_include'],
							registrar: 'MarkMonitor International Canada Ltd.',
							registrarSource: 'rdap',
							combinedConfidence: 1,
							reasons: ['brand-owned domain on off-primary registrar'],
						},
					},
				],
			},
		});

		expect(model.buckets.shadowIt.map((c) => c.domain)).toEqual(['bankofamerica.ca']);
		expect(model.buckets.indeterminate.map((c) => c.domain)).toEqual(['pphosted.com']);
		expect((model as { vendorDependencies?: Array<{ domain: string }> }).vendorDependencies?.map((c) => c.domain)).toEqual([
			'pphosted.com',
		]);
		expect(model.arrOpportunity.domainCount).toBe(1);
		expect(model.arrOpportunity.total).toBe(3350);
	});

	it('emits v4 tiered sidecar relationship sections while preserving legacy buckets', () => {
		const model = buildDiscoveryReportModel({
			target: 'brand-eta.com',
			primaryRegistrar: 'CSC Corporate Domains, Inc.',
			result: {
				category: 'brand_discovery',
				passed: true,
				score: 100,
				findings: [
					{
						category: 'brand_discovery',
						title: 'Brand candidate: pphosted.com',
						severity: 'low',
						detail: '',
						metadata: {
							candidate: 'pphosted.com',
							bucket: 'indeterminate',
							relationshipType: 'authorized_vendor_dependency',
							signals: ['spf_include_seed'],
							registrar: 'MarkMonitor Inc.',
							registrarSource: 'rdap',
							combinedConfidence: 0.85,
							reasons: ['authorized vendor dependency via seed SPF delegation'],
						},
					},
					{
						category: 'brand_discovery',
						title: 'Brand candidate: bankofamerica.ca',
						severity: 'medium',
						detail: '',
						metadata: {
							candidate: 'bankofamerica.ca',
							bucket: 'shadowIt',
							relationshipType: 'owned_off_primary_registrar',
							signals: ['markov_gen', 'ns', 'spf_include'],
							registrar: 'MarkMonitor International Canada Ltd.',
							registrarSource: 'rdap',
							combinedConfidence: 1,
							reasons: ['brand-owned domain on off-primary registrar'],
						},
					},
				],
			},
		});

		const sidecar = buildDiscoveryReportSidecar(model, {
			auditId: 'aud-v4-1',
			generatedAt: '2026-05-21T00:00:00.000Z',
			serverVersion: '2.22.0',
			sourceMode: 'mcp',
			runId: 'run-v4-1',
			requestedAt: '2026-05-21T00:00:00.000Z',
			depthMode: 'deep',
			discoveryMode: 'tiered',
			tiers: {
				tier0Count: 0,
				tier1Count: 0,
				tier2Count: 0,
				tier3Count: 2,
				tier4Count: 0,
				tier0Status: 'ok',
				tier1Status: 'ok',
				tier2Status: 'ok',
				tier3FallbackTriggered: 0,
				optOutsFiltered: 0,
			},
		}) as unknown as {
			qaSchemaVersion: number;
			relationshipSchemaVersion?: number;
			vendorDependencies?: Array<{ domain: string; relationshipType: string }>;
			buckets: { shadowIt: Array<{ domain: string }>; indeterminate: Array<{ domain: string }> };
			ownedPortfolio: { inferred: { shadowIt: string[]; indeterminate: string[] } };
		};

		expect(sidecar.qaSchemaVersion).toBe(4);
		expect(sidecar.relationshipSchemaVersion).toBe(1);
		expect(sidecar.vendorDependencies).toEqual([
			expect.objectContaining({ domain: 'pphosted.com', relationshipType: 'authorized_vendor_dependency' }),
		]);
		expect(sidecar.buckets.shadowIt.map((c) => c.domain)).toEqual(['bankofamerica.ca']);
		expect(sidecar.buckets.indeterminate.map((c) => c.domain)).toEqual(['pphosted.com']);
		expect(sidecar.ownedPortfolio.inferred.shadowIt).toEqual(['bankofamerica.ca']);
		expect(sidecar.ownedPortfolio.inferred.indeterminate).toEqual([]);
	});

	it('keeps indeterminate candidates out of Shadow IT revenue counts', () => {
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
						title: 'summary',
						severity: 'info',
						detail: '',
						metadata: { summary: true, target: 'example.com', consolidated: 1, shadowIt: 1, indeterminate: 1, impersonation: 1 },
					},
					{
						category: 'brand_discovery',
						title: 'Brand candidate: core.example',
						severity: 'info',
						detail: '',
						metadata: {
							candidate: 'core.example',
							bucket: 'consolidated',
							signals: ['ns'],
							registrar: 'Example Registrar',
							registrarSource: 'rdap',
							combinedConfidence: 0.91,
							reasons: ['NS overlap'],
						},
					},
					{
						category: 'brand_discovery',
						title: 'Brand candidate: vendor.example',
						severity: 'medium',
						detail: '',
						metadata: {
							candidate: 'vendor.example',
							bucket: 'shadowIt',
							signals: ['dmarc_rua'],
							registrar: 'Vendor Registrar',
							registrarSource: 'rdap',
							combinedConfidence: 0.87,
							reasons: ['DMARC RUA on non-aligned registrar'],
						},
					},
					{
						category: 'brand_discovery',
						title: 'Brand candidate: review.example',
						severity: 'low',
						detail: '',
						metadata: {
							candidate: 'review.example',
							bucket: 'indeterminate',
							signals: ['markov_gen'],
							registrar: 'Unknown',
							registrarSource: 'notfound',
							combinedConfidence: 0.62,
							reasons: ['registrar source: notfound'],
						},
					},
					{
						category: 'brand_discovery',
						title: 'Brand candidate: typo.example',
						severity: 'high',
						detail: '',
						metadata: {
							candidate: 'typo.example',
							bucket: 'impersonation',
							signals: ['markov_gen'],
							registrar: 'Consumer Registrar',
							registrarSource: 'rdap',
							combinedConfidence: 0.44,
							reasons: ['low confidence, no strong infra signal'],
						},
					},
				],
			},
		});

		expect(model.buckets.shadowIt.map((c) => c.domain)).toEqual(['vendor.example']);
		expect(model.buckets.indeterminate.map((c) => c.domain)).toEqual(['review.example']);
		expect(model.counts).toEqual({ consolidated: 1, shadowIt: 1, indeterminate: 1, impersonation: 1 });
		expect(model.arrOpportunity.domainCount).toBe(1);
		expect(model.dataQuality.notFoundRegistrarCandidates).toEqual(['review.example']);
	});

	it('emits an audit sidecar with bucket counts and data-quality gaps', () => {
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
						title: 'Brand candidate: review.example',
						severity: 'low',
						detail: '',
						metadata: {
							candidate: 'review.example',
							bucket: 'indeterminate',
							signals: ['markov_gen'],
							registrar: 'Unknown',
							registrarSource: 'unknown',
							combinedConfidence: 0.62,
							reasons: ['medium confidence, no strong infra signal'],
						},
					},
				],
			},
		});

		const sidecar = buildDiscoveryReportSidecar(model, {
			auditId: 'aud-123',
			generatedAt: '2026-05-18T00:00:00.000Z',
			serverVersion: '2.21.4',
			sourceMode: 'mcp',
			runId: 'run-123',
			requestedAt: '2026-05-18T00:00:00.000Z',
			depthMode: 'deep',
		});

		expect(sidecar.qaSchemaVersion).toBe(1);
		expect(sidecar.target).toBe('example.com');
		expect(sidecar.auditId).toBe('aud-123');
		expect(sidecar.runId).toBe('run-123');
		expect(sidecar.depthMode).toBe('deep');
		expect(sidecar.freshness.sameRun).toBe(true);
		expect(sidecar.counts.indeterminate).toBe(1);
		expect(sidecar.arrOpportunity.domainCount).toBe(0);
		expect(sidecar.dataQuality.unknownRegistrarCount).toBe(1);
		expect(sidecar.dataQuality.registrarSourceCounts).toMatchObject({ unknown: 1 });
		expect(sidecar.buckets.indeterminate[0]).toMatchObject({
			domain: 'review.example',
			registrar: 'Unknown',
			registrarSource: 'unknown',
		});
	});

	it('copies optional performance metrics into the audit sidecar', () => {
		const model = buildDiscoveryReportModel({
			target: 'example.com',
			primaryRegistrar: 'Example Registrar',
			result: {
				category: 'brand_discovery',
				passed: true,
				score: 100,
				findings: [],
			},
		});
		const performance = {
			elapsedMs: 900,
			steps: [],
			stepStatusCounts: { completed: 1, partial: 0, failed: 0, skipped: 0 },
			dns: { queries: 80, cacheHits: 30, errors: 2, cacheHitRatio: 0.38 },
			rdap: { queries: 20, cacheHits: 5, errors: 1, cacheHitRatio: 0.25 },
			warnings: [],
		};

		const sidecar = buildDiscoveryReportSidecar(model, {
			auditId: null,
			generatedAt: '2026-05-18T00:00:00.000Z',
			serverVersion: '2.21.4',
			sourceMode: 'local',
			runId: 'run-123',
			requestedAt: '2026-05-18T00:00:00.000Z',
			depthMode: 'standard',
			performance,
		});

		expect(sidecar.performance).toEqual(performance);
	});

	it('preserves discovery depth warnings in the audit sidecar', () => {
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
						title: 'summary',
						severity: 'info',
						detail: '',
						metadata: {
							summary: true,
							depth: {
								candidateUniverse: {
									seeded: 12,
									probed: 10,
									surfaced: 0,
									dropped: { corroborationGate: 8 },
									sources: { tld_sweep: 12 },
								},
								signalCoverage: { requested: 3, ok: 2, failed: 0, partial: 0, timeout: 1, skipped: 0 },
								registrarCoverage: { total: 1, rdap: 0, whois: 0, redacted: 0, notfound: 0, unknown: 1, knownRatio: 0 },
								warnings: ['Registrar coverage is 0; ownership classification may require manual review.'],
							},
						},
					},
				],
			},
		});

		const sidecar = buildDiscoveryReportSidecar(model, {
			auditId: 'aud-123',
			generatedAt: '2026-05-18T00:00:00.000Z',
			serverVersion: '2.21.4',
			sourceMode: 'mcp',
			runId: 'run-123',
			requestedAt: '2026-05-18T00:00:00.000Z',
			depthMode: 'standard',
		});

		expect(sidecar.depth?.warnings).toEqual([
			'Registrar coverage is 0; ownership classification may require manual review.',
		]);
		expect(sidecar.depth?.candidateUniverse).toMatchObject({ seeded: 12, surfaced: 0 });
	});
});
