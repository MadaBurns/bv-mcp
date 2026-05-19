// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import { formatAcceptanceSummary, summarizeBenchmark } from '../scripts/brand-audit-planner-benchmark-summary.mjs';

function row(overrides) {
	const metrics = {
		candidateSignalProbes: 1050,
		baselineCandidateSignalProbes: 1050,
		plannerEfficiency: { mode: 'observe', candidateSignalProbes: 1050, baselineCandidateSignalProbes: 1050, surfacedCandidates: 2 },
		signalCoverage: { requested: 15, ok: 13, failed: 1, partial: 0, timeout: 0, skipped: 1 },
		candidateUniverse: {
			seeded: 150,
			probed: 150,
			surfaced: 2,
			dropped: { cap: 0, seedOrSubdomain: 0, infrastructureProvider: 0, corroborationGate: 148, belowConfidence: 0 },
			sources: { caller_candidate: 0, tld_sweep: 88, alias_tld_sweep: 0, enterprise_affix: 26, markov: 0, active_lookalike: 39 },
		},
		counts: { consolidated: 1, shadowIt: 1, indeterminate: 0, impersonation: 0 },
		warnings: [],
		...overrides?.metrics,
	};
	return {
		domain: 'example.com',
		mode: 'observe',
		exitCode: 0,
		elapsedMs: 50000,
		artifactJsonPath: '.reports/brand-audit-planner-benchmark/example.com-observe.json',
		artifactPdfPath: '.reports/brand-audit-planner-benchmark/example.com-observe.pdf',
		...overrides,
		metrics,
	};
}

describe('summarizeBenchmark', () => {
	it('pairs observe/enforce rows by domain and computes reduction and surfaced delta', () => {
		const summary = summarizeBenchmark({
			rows: [
				row({ domain: 'brand-alpha.com', mode: 'observe' }),
				row({
					domain: 'brand-alpha.com',
					mode: 'enforce',
					elapsedMs: 40000,
					metrics: {
						candidateSignalProbes: 580,
						plannerEfficiency: { mode: 'enforce', candidateSignalProbes: 580, baselineCandidateSignalProbes: 1050, surfacedCandidates: 2 },
					},
				}),
			],
		});

		expect(summary.pairs).toHaveLength(1);
		const pair = summary.pairs[0];
		expect(pair.domain).toBe('brand-alpha.com');
		expect(pair.reductionPct).toBeCloseTo(44.76, 1);
		expect(pair.reductionMeets40).toBe(true);
		expect(pair.surfacedDelta).toBe(0);
		expect(pair.surfacedUnchanged).toBe(true);
		expect(pair.bucketCountsUnchanged).toBe(true);
		expect(pair.elapsedDeltaMs).toBe(-10000);
		expect(pair.artifactsGenerated).toBe(true);
		expect(pair.pdfsGenerated).toBe(true);
	});

	it('flags missing reduction and surfaced regressions', () => {
		const summary = summarizeBenchmark({
			rows: [
				row({ domain: 'd.com', mode: 'observe', metrics: { plannerEfficiency: { mode: 'observe', candidateSignalProbes: 1050, baselineCandidateSignalProbes: 1050, surfacedCandidates: 3 } } }),
				row({
					domain: 'd.com',
					mode: 'enforce',
					metrics: {
						candidateSignalProbes: 900,
						plannerEfficiency: { mode: 'enforce', candidateSignalProbes: 900, baselineCandidateSignalProbes: 1050, surfacedCandidates: 2 },
						counts: { consolidated: 1, shadowIt: 0, indeterminate: 0, impersonation: 0 },
					},
				}),
			],
		});

		const pair = summary.pairs[0];
		expect(pair.reductionPct).toBeCloseTo(14.29, 1);
		expect(pair.reductionMeets40).toBe(false);
		expect(pair.surfacedDelta).toBe(-1);
		expect(pair.surfacedUnchanged).toBe(false);
		expect(pair.bucketCountsUnchanged).toBe(false);
	});

	it('aggregates pass counts across multiple domain pairs', () => {
		const summary = summarizeBenchmark({
			rows: [
				row({ domain: 'brand-alpha.com', mode: 'observe' }),
				row({ domain: 'brand-alpha.com', mode: 'enforce', metrics: { candidateSignalProbes: 580, plannerEfficiency: { mode: 'enforce', candidateSignalProbes: 580, baselineCandidateSignalProbes: 1050, surfacedCandidates: 2 } } }),
				row({ domain: 'brand-eta.com', mode: 'observe', metrics: { plannerEfficiency: { mode: 'observe', candidateSignalProbes: 1050, baselineCandidateSignalProbes: 1050, surfacedCandidates: 3 } } }),
				row({ domain: 'brand-eta.com', mode: 'enforce', metrics: { candidateSignalProbes: 580, plannerEfficiency: { mode: 'enforce', candidateSignalProbes: 580, baselineCandidateSignalProbes: 1050, surfacedCandidates: 3 } } }),
				row({ domain: 'brand-kappa.com', mode: 'observe', metrics: { plannerEfficiency: { mode: 'observe', candidateSignalProbes: 1050, baselineCandidateSignalProbes: 1050, surfacedCandidates: 8 } } }),
				row({ domain: 'brand-kappa.com', mode: 'enforce', metrics: { candidateSignalProbes: 700, plannerEfficiency: { mode: 'enforce', candidateSignalProbes: 700, baselineCandidateSignalProbes: 1050, surfacedCandidates: 8 } } }),
			],
		});

		expect(summary.overall.domainsTested).toBe(3);
		expect(summary.overall.pairsHittingReductionTarget).toBe(2);
		expect(summary.overall.pairsWithSurfacedUnchanged).toBe(3);
		expect(summary.overall.pairsWithAllArtifacts).toBe(3);
	});

	it('returns null reductionPct when baseline probes are missing', () => {
		const summary = summarizeBenchmark({
			rows: [
				row({ domain: 'd.com', mode: 'observe', metrics: { candidateSignalProbes: null, plannerEfficiency: null } }),
				row({ domain: 'd.com', mode: 'enforce', metrics: { candidateSignalProbes: null, plannerEfficiency: null } }),
			],
		});
		expect(summary.pairs[0].reductionPct).toBeNull();
		expect(summary.pairs[0].reductionMeets40).toBe(false);
	});

	it('handles single-mode rows (observe only) gracefully', () => {
		const summary = summarizeBenchmark({
			rows: [row({ domain: 'd.com', mode: 'observe' })],
		});
		expect(summary.pairs).toHaveLength(1);
		expect(summary.pairs[0].enforce).toBeNull();
		expect(summary.pairs[0].reductionPct).toBeNull();
	});
});

describe('formatAcceptanceSummary', () => {
	it('renders a per-domain table and overall acceptance verdict', () => {
		const summary = summarizeBenchmark({
			rows: [
				row({ domain: 'brand-alpha.com', mode: 'observe' }),
				row({ domain: 'brand-alpha.com', mode: 'enforce', metrics: { candidateSignalProbes: 580, plannerEfficiency: { mode: 'enforce', candidateSignalProbes: 580, baselineCandidateSignalProbes: 1050, surfacedCandidates: 2 } } }),
			],
		});
		const output = formatAcceptanceSummary(summary);

		expect(output).toContain('Acceptance Summary');
		expect(output).toContain('brand-alpha.com');
		expect(output).toContain('reduction');
		expect(output).toContain('44.8%');
		expect(output).toMatch(/surfacedDelta/i);
		expect(output).toMatch(/PASS|FAIL/);
	});
});
