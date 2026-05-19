// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import { planBrandDiscoverySignals } from '../src/lib/brand-discovery-planner';

describe('planBrandDiscoverySignals', () => {
	it('keeps caller-asserted candidates in every candidate-backed signal', () => {
		const plan = planBrandDiscoverySignals({
			depth: 'deep',
			candidates: [
				{ domain: 'pay.example.net', sources: ['caller_candidate'], reasons: ['caller supplied candidate'] },
				{ domain: 'random-example.net', sources: ['markov'], reasons: ['markov candidate'] },
			],
			signals: ['ns', 'dkim_key_reuse', 'mx_platform'],
		});

		expect(plan.candidatesBySignal.ns).toContain('pay.example.net');
		expect(plan.candidatesBySignal.dkim_key_reuse).toContain('pay.example.net');
		expect(plan.candidatesBySignal.mx_platform).toContain('pay.example.net');
	});

	it('caps expensive DKIM candidates while preserving highest priority candidates first', () => {
		const plan = planBrandDiscoverySignals({
			depth: 'deep',
			candidates: [
				{ domain: 'example.ca', sources: ['tld_sweep'], reasons: ['seed label across .ca'] },
				{ domain: 'examp1e.com', sources: ['active_lookalike'], reasons: ['active lookalike candidate'] },
				{ domain: 'example-support.net', sources: ['enterprise_affix'], reasons: ['enterprise support affix'] },
				{ domain: 'noise-1.net', sources: ['markov'], reasons: ['markov candidate'] },
				{ domain: 'noise-2.net', sources: ['markov'], reasons: ['markov candidate'] },
			],
			signals: ['dkim_key_reuse'],
			caps: { dkim_key_reuse: 3 },
		});

		expect(plan.candidatesBySignal.dkim_key_reuse).toEqual(['example.ca', 'examp1e.com', 'example-support.net']);
		expect(plan.droppedBySignal.dkim_key_reuse).toEqual([
			{ domain: 'noise-1.net', reason: 'signal_cap' },
			{ domain: 'noise-2.net', reason: 'signal_cap' },
		]);
	});

	it('keeps standard mode conservative and deep mode broader', () => {
		const candidates = [
			{ domain: 'example.ca', sources: ['tld_sweep'], reasons: ['seed label across .ca'] },
			{ domain: 'example-support.net', sources: ['enterprise_affix'], reasons: ['enterprise support affix'] },
			{ domain: 'noise-1.net', sources: ['markov'], reasons: ['markov candidate'] },
		];

		const standard = planBrandDiscoverySignals({ depth: 'standard', candidates, signals: ['ns'] });
		const deep = planBrandDiscoverySignals({ depth: 'deep', candidates, signals: ['ns'] });

		expect(standard.candidatesBySignal.ns.length).toBeLessThan(deep.candidatesBySignal.ns.length);
		expect(deep.candidatesBySignal.ns).toContain('example-support.net');
	});

	it('keeps full coverage on high-yield signals (ns/mx_platform/spf_include) while tightening low-yield candidate-backed signals', () => {
		// Empirical observation from production benchmarks on walmart/bankofamerica/marriott:
		// surfaced candidates were only ever corroborated by ns / mx_platform / spf_include.
		// dkim_key_reuse / mx_overlap / txt_verification / cname_alignment contributed zero
		// surfaced findings. Default deep caps should reflect that asymmetry.
		const candidates = [
			...Array.from({ length: 88 }, (_, i) => ({
				domain: `tld-${i}.example`,
				sources: ['tld_sweep'] as const,
				reasons: ['seed label across .ca'],
			})),
			...Array.from({ length: 39 }, (_, i) => ({
				domain: `active-${i}.example`,
				sources: ['active_lookalike'] as const,
				reasons: ['active lookalike candidate'],
			})),
			...Array.from({ length: 26 }, (_, i) => ({
				domain: `enterprise-${i}.example`,
				sources: ['enterprise_affix'] as const,
				reasons: ['enterprise support affix'],
			})),
		];
		const signals = ['dkim_key_reuse', 'ns', 'mx_platform', 'mx_overlap', 'txt_verification', 'spf_include', 'cname_alignment'] as const;

		const plan = planBrandDiscoverySignals({
			depth: 'deep',
			candidates,
			signals: [...signals],
		});

		// High-yield signals stay roomy: full coverage of every candidate.
		expect(plan.candidatesBySignal.ns?.length).toBe(candidates.length);
		expect(plan.candidatesBySignal.mx_platform?.length).toBe(candidates.length);
		expect(plan.candidatesBySignal.spf_include?.length).toBe(candidates.length);

		// Low-yield signals are tightened versus the prior 40/120/90/90 baseline.
		expect(plan.candidatesBySignal.dkim_key_reuse?.length ?? Infinity).toBeLessThanOrEqual(30);
		expect(plan.candidatesBySignal.mx_overlap?.length ?? Infinity).toBeLessThanOrEqual(40);
		expect(plan.candidatesBySignal.txt_verification?.length ?? Infinity).toBeLessThanOrEqual(30);
		expect(plan.candidatesBySignal.cname_alignment?.length ?? Infinity).toBeLessThanOrEqual(30);

		const probes = signals.reduce((sum, signal) => sum + (plan.candidatesBySignal[signal]?.length ?? 0), 0);
		const baseline = candidates.length * signals.length;
		expect(1 - probes / baseline).toBeGreaterThanOrEqual(0.4);
	});

	it('keeps every guarded (caller/app_links/bounty_scope) candidate in low-yield signals even when there are more guarded candidates than the signal cap', () => {
		// A caller asserting 35 candidate_domains exercises this: cap=30 for
		// dkim_key_reuse must not drop 5 caller-asserted candidates.
		const guarded = Array.from({ length: 35 }, (_, i) => ({
			domain: `asserted-${i}.example`,
			sources: ['caller_candidate'] as const,
			reasons: ['caller supplied candidate'],
		}));
		const noise = Array.from({ length: 20 }, (_, i) => ({
			domain: `noise-${i}.example`,
			sources: ['markov'] as const,
			reasons: ['markov candidate'],
		}));
		const plan = planBrandDiscoverySignals({
			depth: 'deep',
			candidates: [...guarded, ...noise],
			signals: ['dkim_key_reuse'],
			caps: { dkim_key_reuse: 30 },
		});

		for (const c of guarded) {
			expect(plan.candidatesBySignal.dkim_key_reuse).toContain(c.domain);
		}
		// Markov noise is dropped — guarded candidates take precedence over cap.
		expect(plan.candidatesBySignal.dkim_key_reuse).not.toContain('noise-0.example');
	});

	it('reports why high-trust candidates are guarded from low-priority pruning', () => {
		const plan = planBrandDiscoverySignals({
			depth: 'deep',
			candidates: [
				{ domain: 'noise-1.net', sources: ['markov'], reasons: ['markov candidate'] },
				{ domain: 'declared.example.net', sources: ['app_links'], reasons: ['android asset links declaration'] },
				{ domain: 'noise-2.net', sources: ['markov'], reasons: ['markov candidate'] },
			],
			signals: ['dkim_key_reuse'],
			caps: { dkim_key_reuse: 1 },
		});

		expect(plan.candidatesBySignal.dkim_key_reuse).toEqual(['declared.example.net']);
		expect(plan.guardedByDomain).toEqual({ 'declared.example.net': 'app_links' });
		expect(plan.priorityByDomain['declared.example.net']).toBeGreaterThan(plan.priorityByDomain['noise-1.net']);
	});
});
