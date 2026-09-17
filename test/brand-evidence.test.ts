// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import { clearsOwnershipGate, evidenceTier, type BrandEvidenceObservation, type BrandEvidenceSignal } from '../src/lib/brand-evidence';

describe('brand evidence tier policy', () => {
	it('treats broad shared MX platforms as weak evidence', () => {
		expect(evidenceTier('mx_platform', { sharedMxPlatform: 'm365' })).toBe('weak');
		expect(evidenceTier('mx_platform', { sharedMxPlatform: 'google_workspace' })).toBe('weak');
	});

	it('treats an in-bailiwick NS match as strong evidence, clearing ownership alone', () => {
		expect(evidenceTier('ns', { matchType: 'in_bailiwick' })).toBe('strong');
		expect(clearsOwnershipGate([{ signal: 'ns', confidence: 1, metadata: { matchType: 'in_bailiwick' } }])).toBe(true);
	});

	it('keeps a plain NS set-overlap match at medium — needs a second signal to clear ownership', () => {
		expect(evidenceTier('ns', { matchType: 'set_overlap' })).toBe('medium');
		expect(evidenceTier('ns')).toBe('medium');
		expect(clearsOwnershipGate([{ signal: 'ns', confidence: 0.5, metadata: { matchType: 'set_overlap' } }])).toBe(false);
	});

	it('does not let markov generation plus broad MX platform clear ownership', () => {
		expect(
			clearsOwnershipGate(
				[
					{ signal: 'markov_gen' },
					{ signal: 'mx_platform', metadata: { sharedMxPlatform: 'm365' } },
				],
				{ callerAsserted: false },
			),
		).toBe(false);
	});

	it('does not let generated lookalike seeds corroborate a single medium ownership signal', () => {
		expect(
			clearsOwnershipGate(
				[
					{ signal: 'markov_gen' },
					{ signal: 'ns' },
				],
				{ callerAsserted: false },
			),
		).toBe(false);
		expect(
			clearsOwnershipGate(
				[
					{ signal: 'active_lookalike' },
					{ signal: 'ns' },
				],
				{ callerAsserted: false },
			),
		).toBe(false);
	});

	it('lets deterministic TXT verification clear ownership alone', () => {
		expect(evidenceTier('txt_verification')).toBe('strong');
		expect(clearsOwnershipGate([{ signal: 'txt_verification' }], { callerAsserted: false })).toBe(true);
	});

	it('lets DKIM key reuse clear ownership alone', () => {
		expect(evidenceTier('dkim_key_reuse')).toBe('strong');
		expect(clearsOwnershipGate([{ signal: 'dkim_key_reuse' }], { callerAsserted: false })).toBe(true);
	});

	it('does not let one medium signal plus broad weak MX platform clear ownership', () => {
		expect(
			clearsOwnershipGate(
				[
					{ signal: 'mx_platform', metadata: { sharedMxPlatform: 'm365' } },
					{ signal: 'ns' },
				],
				{ callerAsserted: false },
			),
		).toBe(false);
		expect(
			clearsOwnershipGate(
				[
					{ signal: 'mx_platform', metadata: { sharedMxPlatform: 'm365' } },
					{ signal: 'active_lookalike' },
				],
				{ callerAsserted: false },
			),
		).toBe(false);
	});

	it('lets two medium non-seed signals clear ownership', () => {
		expect(
			clearsOwnershipGate(
				[
					{ signal: 'mx_platform', metadata: { sharedMxPlatform: 'proofpoint' } },
					{ signal: 'ns' },
				],
				{ callerAsserted: false },
			),
		).toBe(true);
	});

	it('lets caller asserted candidates clear when any real observation exists', () => {
		expect(clearsOwnershipGate([{ signal: 'ns' }], { callerAsserted: true })).toBe(true);
		expect(clearsOwnershipGate([{ signal: 'mx_platform', metadata: { sharedMxPlatform: 'm365' } }], { callerAsserted: true })).toBe(true);
		expect(clearsOwnershipGate([{ signal: 'markov_gen' }], { callerAsserted: true })).toBe(false);
	});

	it('does not let speculative lookalike or markov seeds clear alone', () => {
		expect(clearsOwnershipGate([{ signal: 'active_lookalike' }], { callerAsserted: false })).toBe(false);
		expect(clearsOwnershipGate([{ signal: 'markov_gen' }], { callerAsserted: false })).toBe(false);
	});

	// T6: tier-aware bypass of N-of-M corroboration. Tier 0/1/2 carry enough
	// source-side confidence to short-circuit the gate; Tier 3 stays on the
	// legacy live-signal sweep path.
	describe('tier-aware ownership gate (T6)', () => {
		it('returns true for a single tier-0 observation', () => {
			// Tier 0 = tenant-declared (gold standard). A weak signal name should
			// not matter — provenance dominates.
			expect(
				clearsOwnershipGate(
					[{ signal: 'mx_platform', confidence: 1.0, tier: 0, metadata: { sharedMxPlatform: 'm365' } }],
					{ callerAsserted: false },
				),
			).toBe(true);
		});

		it('returns true for a tier-1 observation with deterministic graph provenance and specificityScore >= 0.5', () => {
			expect(
				clearsOwnershipGate(
					[
						{
							signal: 'markov_gen',
							confidence: 0.7,
							tier: 1,
							specificityScore: 0.7,
							metadata: { source: 'infra_graph_signal', signalTypes: ['ns'], numSharedSignals: 1 },
						},
					],
					{ callerAsserted: false },
				),
			).toBe(true);
		});

		it('does NOT auto-clear tier-1 graph observations when the only reportable signal is generated seed metadata', () => {
			expect(
				clearsOwnershipGate(
					[
						{
							signal: 'markov_gen',
							confidence: 0.92,
							tier: 1,
							specificityScore: 0.63,
							metadata: {
								source: 'infra_graph_signal',
								numSharedSignals: 1,
								signalTypes: ['soa_admin'],
							},
						},
					],
					{ callerAsserted: false },
				),
			).toBe(false);
		});

		it('auto-clears tier-1 graph observations with deterministic graph signal provenance', () => {
			expect(
				clearsOwnershipGate(
					[
						{
							signal: 'markov_gen',
							confidence: 0.92,
							tier: 1,
							specificityScore: 0.7,
							metadata: {
								source: 'infra_graph_signal',
								numSharedSignals: 1,
								signalTypes: ['spf_include'],
							},
						},
					],
					{ callerAsserted: false },
				),
			).toBe(true);
		});

		it('auto-clears tier-1 graph observations with multiple independent graph signal types and high specificity', () => {
			expect(
				clearsOwnershipGate(
					[
						{
							signal: 'markov_gen',
							confidence: 0.88,
							tier: 1,
							specificityScore: 0.82,
							metadata: {
								source: 'infra_graph_signal',
								numSharedSignals: 2,
								signalTypes: ['soa_admin', 'mx_platform'],
							},
						},
					],
					{ callerAsserted: false },
				),
			).toBe(true);
		});

		it('does NOT auto-clear for tier-1 with specificityScore < 0.5', () => {
			// e.g. shared gmail MX, low signal-graph specificity.
			expect(
				clearsOwnershipGate(
					[{ signal: 'mx_platform', confidence: 0.1, tier: 1, specificityScore: 0.1, metadata: { sharedMxPlatform: 'gmail' } }],
					{ callerAsserted: false },
				),
			).toBe(false);
		});

		it('does NOT auto-clear for tier-1 with missing specificityScore', () => {
			// Tier 1 requires the specificity threshold to be met explicitly.
			expect(
				clearsOwnershipGate(
					[{ signal: 'mx_platform', confidence: 0.4, tier: 1, metadata: { sharedMxPlatform: 'gmail' } }],
					{ callerAsserted: false },
				),
			).toBe(false);
		});

		it('returns true for a single tier-2 observation', () => {
			// Tier 2 = declared/witnessed (e.g. RDAP registrant match). Specificity
			// is not required.
			expect(
				clearsOwnershipGate(
					[{ signal: 'ns', confidence: 0.95, tier: 2 }],
					{ callerAsserted: false },
				),
			).toBe(true);
		});

		it('legacy N-of-M gate still applies when observations carry no tier (Tier 3 fallback)', () => {
			// Two medium non-seed signals without tier metadata should still clear
			// via the existing rule.
			expect(
				clearsOwnershipGate(
					[
						{ signal: 'ns' },
						{ signal: 'mx_overlap' },
					],
					{ callerAsserted: false },
				),
			).toBe(true);
		});

		it('legacy N-of-M gate still rejects under-corroborated tierless observations', () => {
			// A single medium tierless signal should still fail the gate.
			expect(
				clearsOwnershipGate(
					[{ signal: 'ns' }],
					{ callerAsserted: false },
				),
			).toBe(false);
		});
	});
});

// #1041 — a tier-1 graph observation whose strongest `signalType` has no supported
// `DiscoverSignal` mapping degrades to the weak seed signal `markov_gen` in
// `tieredObservationEvidence()`. The degrade used to be INERT: the ownership gate reads the
// raw graph claim (`specificityScore`, `signalTypes`, `numSharedSignals`), never
// `observation.signal`, so the degraded candidate bypassed corroboration anyway.
describe('#1041 degraded tier-1 graph observations surrender their ownership claim', () => {
	/**
	 * Mirrors `buildEvidenceObservations()` in src/tools/discover-brand-domains.ts: the
	 * aggregator's per-signal source note IS the observation metadata, with `tier` and
	 * `specificityScore` lifted off it onto the observation itself.
	 */
	function observationFromAggregatorNote(signal: BrandEvidenceSignal, note: Record<string, unknown>): BrandEvidenceObservation {
		const tier = note.tier;
		const specificityScore = note.specificityScore;
		return {
			signal,
			confidence: 0.8,
			metadata: note,
			...(tier === 0 || tier === 1 || tier === 2 || tier === 3 || tier === 4 ? { tier } : {}),
			...(typeof specificityScore === 'number' ? { specificityScore } : {}),
		};
	}

	/** The Tier-1 observation shape `tier1Lookup` hands the discovery pipeline. */
	function tier1GraphObservation(signalType: string): { tier: 1; metadata: Record<string, unknown> } {
		return {
			tier: 1,
			metadata: {
				tier: 1,
				source: 'infra_graph_signal',
				specificityScore: 0.9,
				signalType,
				signalValue: `${signalType}:synthetic`,
				numSharedSignals: 1,
				maxSpecificity: 0.9,
				signalTypes: [signalType],
			},
		};
	}

	it('does NOT clear the ownership gate when an unmapped tier-1 signalType degrades to the seed signal', async () => {
		const { tieredObservationEvidence } = await import('../src/tools/discover-brand-domains');
		// `cert_fingerprint` is deterministic AT THE GATE but absent from
		// TIER1_GRAPH_SIGNAL_MAP, so it is exactly the shape that made the degrade inert.
		const resolved = tieredObservationEvidence(tier1GraphObservation('cert_fingerprint'));

		expect(resolved.signal).toBe('markov_gen');
		expect(resolved.metadata.signalTypes).toBeUndefined();
		expect(resolved.metadata.signalType).toBeUndefined();
		expect(resolved.metadata.specificityScore).toBeUndefined();
		expect(resolved.metadata.numSharedSignals).toBeUndefined();
		// Provenance is retained, just out of the gate's reach.
		expect(resolved.metadata.degradedGraphSignal).toEqual({
			specificityScore: 0.9,
			signalType: 'cert_fingerprint',
			signalTypes: ['cert_fingerprint'],
			numSharedSignals: 1,
			maxSpecificity: 0.9,
		});
		expect(resolved.metadata.tier).toBe(1);
		expect(clearsOwnershipGate([observationFromAggregatorNote('markov_gen', resolved.metadata)], { callerAsserted: false })).toBe(false);
	});

	it('leaves a mapped tier-1 signalType — signal and graph claim both intact — clearing the gate', async () => {
		const { tieredObservationEvidence } = await import('../src/tools/discover-brand-domains');
		const resolved = tieredObservationEvidence(tier1GraphObservation('spf_include'));

		expect(resolved.signal).toBe('spf_include');
		expect(resolved.metadata.signalTypes).toEqual(['spf_include']);
		expect(resolved.metadata.specificityScore).toBe(0.9);
		expect(resolved.metadata.degradedGraphSignal).toBeUndefined();
		expect(clearsOwnershipGate([observationFromAggregatorNote('spf_include', resolved.metadata)], { callerAsserted: false })).toBe(true);
	});

	it('still clears the gate for a LEGITIMATE deterministic tier-1 observation stored under the seed signal', () => {
		// The gate must not key on `observation.signal`: this legitimate observation is
		// byte-identical to a degraded one in that field. PR #1045 keyed on it
		// (`isSeedObservation(observation)`) and broke deterministic tier-1 routing.
		expect(
			clearsOwnershipGate(
				[
					{
						signal: 'markov_gen',
						confidence: 0.8,
						tier: 1,
						specificityScore: 0.7,
						metadata: { source: 'infra_graph_signal', numSharedSignals: 1, signalTypes: ['spf_include'] },
					},
				],
				{ callerAsserted: false },
			),
		).toBe(true);
	});
});
