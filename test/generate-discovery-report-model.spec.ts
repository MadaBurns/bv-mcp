// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import { buildDiscoveryReportModel, buildDiscoveryReportSidecar } from './helpers/discovery-report-model';

describe('discovery report model', () => {
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
