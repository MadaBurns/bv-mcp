// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import { buildBrandAuditDepthSummary } from '../src/lib/brand-audit-depth';

describe('buildBrandAuditDepthSummary', () => {
	it('summarizes candidate, signal, and registrar coverage without brand-specific fixtures', () => {
		const summary = buildBrandAuditDepthSummary({
			candidateUniverse: {
				seeded: 12,
				probed: 10,
				surfaced: 3,
				dropped: {
					belowConfidence: 4,
					corroborationGate: 2,
					invalidDomain: 1,
				},
				sources: {
					tld_sweep: 6,
					alias_tld_sweep: 2,
					markov: 2,
					active_lookalike: 2,
				},
			},
			signalStatus: {
				ns: { status: 'ok' },
				san: { status: 'partial' },
				txt_verification: { status: 'ok' },
			},
			registrarSources: ['rdap', 'rdap', 'whois', 'unknown'],
		});

		expect(summary.candidateUniverse).toEqual({
			seeded: 12,
			probed: 10,
			surfaced: 3,
			dropped: {
				belowConfidence: 4,
				corroborationGate: 2,
				invalidDomain: 1,
			},
			sources: {
				tld_sweep: 6,
				alias_tld_sweep: 2,
				markov: 2,
				active_lookalike: 2,
			},
		});
		expect(summary.signalCoverage).toEqual({
			requested: 3,
			ok: 2,
			failed: 0,
			partial: 1,
			timeout: 0,
			skipped: 0,
		});
		expect(summary.registrarCoverage).toEqual({
			total: 4,
			rdap: 2,
			whois: 1,
			redacted: 0,
			notfound: 0,
			unknown: 1,
			knownRatio: 0.75,
		});
		expect(summary.warnings).toContain('SAN signal returned partial results; certificate-derived sibling coverage is incomplete.');
	});

	it('warns when registrar enrichment only completed partially', () => {
		const summary = buildBrandAuditDepthSummary({
			candidateUniverse: { seeded: 2, probed: 2, surfaced: 2, dropped: {}, sources: {} },
			signalStatus: {},
			registrarSources: ['rdap', 'unknown'],
			performance: {
				stepStatusCounts: { completed: 2, partial: 1, failed: 0, skipped: 0 },
				steps: [
					{ name: 'registrar_enrichment', status: 'partial', startedAtMs: 1000, finishedAtMs: 1100, elapsedMs: 100 },
				],
			},
		});

		expect(summary.warnings).toContain('Registrar enrichment completed partially; ownership classification may require manual review.');
	});

	it('warns when recursive SAN completed partially', () => {
		const summary = buildBrandAuditDepthSummary({
			candidateUniverse: { seeded: 2, probed: 2, surfaced: 1, dropped: {}, sources: {} },
			signalStatus: {
				san: { status: 'ok' },
				san_recursive: { status: 'partial', error: 'budget_exceeded' },
			},
			registrarSources: ['rdap'],
		});

		expect(summary.signalCoverage.partial).toBe(1);
		expect(summary.warnings).toContain('Recursive SAN signal returned partial results; mutual certificate confirmation coverage is incomplete.');
	});
});
