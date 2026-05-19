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
			lookup_failed: 0,
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

	it('warns when the candidate universe was truncated by the cap', () => {
		const summary = buildBrandAuditDepthSummary({
			candidateUniverse: {
				seeded: 150,
				probed: 150,
				surfaced: 8,
				dropped: { cap: 154, corroborationGate: 142 },
				sources: { tld_sweep: 28, enterprise_affix: 112, active_lookalike: 10 },
			},
			signalStatus: { ns: { status: 'ok' } },
			registrarSources: ['rdap', 'rdap'],
		});

		expect(summary.warnings).toContain(
			'Candidate universe was truncated by cap (154 candidate(s) dropped); discovery coverage is incomplete.',
		);
	});

	it('warns when planner enforcement drops most candidate-backed probes', () => {
		const summary = buildBrandAuditDepthSummary({
			candidateUniverse: {
				seeded: 150,
				probed: 150,
				surfaced: 2,
				dropped: { cap: 154, seedOrSubdomain: 0, infrastructureProvider: 0, corroborationGate: 148, belowConfidence: 0 },
				sources: { caller_candidate: 0, tld_sweep: 88, alias_tld_sweep: 0, enterprise_affix: 26, markov: 0, active_lookalike: 39 },
			},
			signalStatus: { ns: { status: 'ok' }, dkim_key_reuse: { status: 'partial' } },
			registrarSources: ['rdap', 'rdap'],
			plannerEfficiency: { mode: 'enforce', candidateSignalProbes: 220, baselineCandidateSignalProbes: 900, surfacedCandidates: 2 },
		});

		expect(summary.warnings).toContain(
			'Discovery planner reduced candidate-backed probes by 75.6%; review recall guard metrics before treating coverage as exhaustive.',
		);
	});

	it('passes per-signal would-probe / would-drop counts through to the depth summary', () => {
		const summary = buildBrandAuditDepthSummary({
			candidateUniverse: { seeded: 150, probed: 150, surfaced: 2, dropped: {}, sources: {} },
			signalStatus: { ns: { status: 'ok' } },
			registrarSources: ['rdap'],
			plannerEfficiency: {
				mode: 'enforce',
				candidateSignalProbes: 580,
				baselineCandidateSignalProbes: 1050,
				surfacedCandidates: 2,
				wouldProbeBySignal: { ns: 150, dkim_key_reuse: 30, mx_overlap: 40 },
				wouldDropBySignal: { dkim_key_reuse: 120, mx_overlap: 110 },
			},
		});

		expect(summary.plannerEfficiency?.wouldProbeBySignal).toEqual({ ns: 150, dkim_key_reuse: 30, mx_overlap: 40 });
		expect(summary.plannerEfficiency?.wouldDropBySignal).toEqual({ dkim_key_reuse: 120, mx_overlap: 110 });
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

	it('warns when recursive SAN is skipped to preserve audit deadline headroom', () => {
		const summary = buildBrandAuditDepthSummary({
			candidateUniverse: { seeded: 150, probed: 150, surfaced: 2, dropped: { cap: 154 }, sources: {} },
			signalStatus: {
				san: { status: 'ok' },
				san_recursive: { status: 'skipped_deadline' },
			},
			registrarSources: ['rdap'],
		});

		expect(summary.signalCoverage.skipped).toBe(1);
		expect(summary.warnings).toContain('Recursive SAN signal skipped to preserve audit deadline headroom; mutual certificate confirmation coverage is incomplete.');
	});

	it('surfaces non-SAN signal missingness as a coverage warning', () => {
		const summary = buildBrandAuditDepthSummary({
			candidateUniverse: { seeded: 150, probed: 150, surfaced: 8, dropped: { corroborationGate: 142 }, sources: {} },
			signalStatus: {
				san: { status: 'rate_limited' },
				dkim_key_reuse: { status: 'partial', error: 'budget_exceeded' },
				txt_verification: { status: 'partial' },
				bounty_scope: { status: 'failed' },
				dmarc_rua: { status: 'no_dmarc' },
			},
			registrarSources: ['rdap', 'rdap'],
		});

		expect(summary.signalCoverage).toEqual({
			requested: 5,
			ok: 1,
			failed: 1,
			partial: 3,
			timeout: 0,
			skipped: 0,
		});
		expect(summary.warnings).toContain('SAN signal was rate limited; certificate-derived sibling coverage is incomplete.');
		expect(summary.warnings).toContain(
			'Discovery signals returned incomplete results (partial: dkim_key_reuse, san, txt_verification; failed: bounty_scope); finding coverage is incomplete.',
		);
	});
});
