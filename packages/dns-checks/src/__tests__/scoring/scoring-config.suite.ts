// SPDX-License-Identifier: BUSL-1.1

/**
 * Shared scoring-config test suite — the single source of truth for these tests.
 *
 * Run against BOTH import surfaces so source↔built (dist/DTS) drift is caught:
 *   - packages/dns-checks/src/__tests__/scoring/scoring-config.spec.ts → source (`../../scoring`)
 *   - test/scoring-config.spec.ts → built package (`@blackveil/dns-checks/scoring`)
 *
 * The two thin spec files inject their respective module; the assertions live
 * here once, so the trees can't drift apart. NOT a `.spec.ts`/`.test.ts`, so
 * neither vitest run collects it directly.
 */

import { describe, expect, it } from 'vitest';

/** The scoring module under test — source or built package, injected by the caller. */
type ScoringModule = typeof import('../../scoring');

export function defineScoringConfigSuite(s: ScoringModule): void {
	const { parseScoringConfig, DEFAULT_SCORING_CONFIG, toImportanceRecord, PROFILE_WEIGHTS } = s;

	describe('parseScoringConfig', () => {
		it('returns defaults when input is undefined', () => {
			const config = parseScoringConfig(undefined);
			expect(config).toEqual(DEFAULT_SCORING_CONFIG);
		});

		it('returns defaults when input is empty string', () => {
			const config = parseScoringConfig('');
			expect(config).toEqual(DEFAULT_SCORING_CONFIG);
		});

		it('returns defaults when input is invalid JSON', () => {
			const config = parseScoringConfig('not json');
			expect(config).toEqual(DEFAULT_SCORING_CONFIG);
		});

		it('returns defaults when input is a JSON array', () => {
			const config = parseScoringConfig('[1, 2, 3]');
			expect(config).toEqual(DEFAULT_SCORING_CONFIG);
		});

		it('merges partial weight overrides with defaults', () => {
			const config = parseScoringConfig(
				JSON.stringify({
					weights: { spf: 15, dmarc: 30 },
				}),
			);
			expect(config.weights.spf).toBe(15);
			expect(config.weights.dmarc).toBe(30);
			expect(config.weights.dkim).toBe(DEFAULT_SCORING_CONFIG.weights.dkim);
		});

		it('merges partial profile weight overrides', () => {
			const config = parseScoringConfig(
				JSON.stringify({
					profileWeights: {
						enterprise_mail: { dmarc: 30 },
					},
				}),
			);
			expect(config.profileWeights.enterprise_mail.dmarc).toBe(30);
			expect(config.profileWeights.enterprise_mail.dkim).toBe(DEFAULT_SCORING_CONFIG.profileWeights.enterprise_mail.dkim);
			expect(config.profileWeights.mail_enabled).toEqual(DEFAULT_SCORING_CONFIG.profileWeights.mail_enabled);
		});

		it('merges threshold overrides', () => {
			const config = parseScoringConfig(
				JSON.stringify({
					thresholds: { emailBonusImportance: 10, criticalGapCeiling: 70 },
				}),
			);
			expect(config.thresholds.emailBonusImportance).toBe(10);
			expect(config.thresholds.criticalGapCeiling).toBe(70);
			expect(config.thresholds.spfStrongThreshold).toBe(DEFAULT_SCORING_CONFIG.thresholds.spfStrongThreshold);
		});

		it('merges an evidenceSufficiency override numerically, like any other threshold', () => {
			const config = parseScoringConfig(
				JSON.stringify({
					thresholds: { evidenceSufficiency: 0.8 },
				}),
			);
			expect(config.thresholds.evidenceSufficiency).toBe(0.8);
			// Untouched siblings stay at their defaults.
			expect(config.thresholds.spfStrongThreshold).toBe(DEFAULT_SCORING_CONFIG.thresholds.spfStrongThreshold);
		});

		it('clamps an evidenceSufficiency override to [0, 1] — a percent-not-ratio typo must not ungrade the fleet', () => {
			// An operator writing `60` meaning "60%" instead of the ratio `0.6` must not silently
			// set the bar to "60 attempted checks must complete" (impossible — no scan attempts
			// anywhere near that many categories), which would ungrade every scan in production.
			// Clamping to 1 makes the mistake merely maximally strict, not catastrophic.
			const tooHigh = parseScoringConfig(
				JSON.stringify({
					thresholds: { evidenceSufficiency: 60 },
				}),
			);
			expect(tooHigh.thresholds.evidenceSufficiency).toBe(1);

			// A negative override (typo, bad config generation) must not disable the gate below 0.
			const tooLow = parseScoringConfig(
				JSON.stringify({
					thresholds: { evidenceSufficiency: -1 },
				}),
			);
			expect(tooLow.thresholds.evidenceSufficiency).toBe(0);
		});

		it('merges grade overrides', () => {
			const config = parseScoringConfig(
				JSON.stringify({
					grades: { aPlus: 95 },
				}),
			);
			expect(config.grades.aPlus).toBe(95);
			expect(config.grades.a).toBe(DEFAULT_SCORING_CONFIG.grades.a);
		});

		it('merges baseline failure rate overrides', () => {
			const config = parseScoringConfig(
				JSON.stringify({
					baselineFailureRates: { dmarc: 0.5, spf: 0.3 },
				}),
			);
			expect(config.baselineFailureRates.dmarc).toBe(0.5);
			expect(config.baselineFailureRates.spf).toBe(0.3);
			expect(config.baselineFailureRates.ssl).toBe(DEFAULT_SCORING_CONFIG.baselineFailureRates.ssl);
		});

		it('ignores unknown top-level keys', () => {
			const config = parseScoringConfig(
				JSON.stringify({
					unknownKey: 'value',
					weights: { spf: 15 },
				}),
			);
			expect(config.weights.spf).toBe(15);
			expect(config).not.toHaveProperty('unknownKey');
		});

		it('clamps negative weights to 0', () => {
			const config = parseScoringConfig(
				JSON.stringify({
					weights: { spf: -5 },
				}),
			);
			expect(config.weights.spf).toBe(0);
		});

		it('ignores non-numeric weight values', () => {
			const config = parseScoringConfig(
				JSON.stringify({
					weights: { spf: 'high' },
				}),
			);
			expect(config.weights.spf).toBe(DEFAULT_SCORING_CONFIG.weights.spf);
		});

		it('ignores non-numeric threshold values', () => {
			const config = parseScoringConfig(
				JSON.stringify({
					thresholds: { emailBonusImportance: true },
				}),
			);
			expect(config.thresholds.emailBonusImportance).toBe(DEFAULT_SCORING_CONFIG.thresholds.emailBonusImportance);
		});

		it('ignores Infinity and NaN weights', () => {
			const config = parseScoringConfig(
				JSON.stringify({
					weights: { spf: null },
				}),
			);
			expect(config.weights.spf).toBe(DEFAULT_SCORING_CONFIG.weights.spf);
		});

		it('ignores unknown weight categories', () => {
			const config = parseScoringConfig(
				JSON.stringify({
					weights: { unknown_check: 99, spf: 15 },
				}),
			);
			expect(config.weights.spf).toBe(15);
			expect(config.weights).not.toHaveProperty('unknown_check');
		});
	});

	describe('scoring v2 config', () => {
		it('DEFAULT_SCORING_CONFIG has tierSplit summing to 100', () => {
			const { tierSplit } = DEFAULT_SCORING_CONFIG;
			expect(tierSplit.core + tierSplit.protective + tierSplit.hardening).toBe(100);
		});

		it('DEFAULT_SCORING_CONFIG has coreWeights', () => {
			expect(DEFAULT_SCORING_CONFIG.coreWeights).toEqual({
				dmarc: 16,
				dkim: 10,
				spf: 10,
				dnssec: 10,
				ssl: 8,
				authoritative_dns_infra: 0,
			});
		});

		it('DEFAULT_SCORING_CONFIG has protectiveWeights', () => {
			expect(DEFAULT_SCORING_CONFIG.protectiveWeights.subdomain_takeover).toBe(4);
			expect(Object.values(DEFAULT_SCORING_CONFIG.protectiveWeights).reduce((a, b) => a + b, 0)).toBe(23);
		});

		it('DEFAULT_SCORING_CONFIG has emailBonusFull/Mid/Partial', () => {
			expect(DEFAULT_SCORING_CONFIG.thresholds.emailBonusFull).toBe(5);
			expect(DEFAULT_SCORING_CONFIG.thresholds.emailBonusMid).toBe(3);
			expect(DEFAULT_SCORING_CONFIG.thresholds.emailBonusPartial).toBe(2);
		});

		it('DEFAULT_SCORING_CONFIG has no E grade', () => {
			expect(DEFAULT_SCORING_CONFIG.grades).not.toHaveProperty('e');
		});

		it('DEFAULT_SCORING_CONFIG has providerDkimConfidence', () => {
			expect(DEFAULT_SCORING_CONFIG.providerDkimConfidence.amazonses).toBe(0.8);
			expect(DEFAULT_SCORING_CONFIG.providerDkimConfidence.google).toBe(0.9);
		});

		it('parseScoringConfig migrates legacy weights to coreWeights/protectiveWeights', () => {
			const legacy = JSON.stringify({ weights: { dmarc: 30, spf: 15 } });
			const config = parseScoringConfig(legacy);
			expect(config.coreWeights.dmarc).toBe(30);
			expect(config.coreWeights.spf).toBe(15);
		});

		it('parseScoringConfig migrates emailBonusImportance to three fields', () => {
			const legacy = JSON.stringify({ thresholds: { emailBonusImportance: 10 } });
			const config = parseScoringConfig(legacy);
			expect(config.thresholds.emailBonusFull).toBe(10);
			expect(config.thresholds.emailBonusMid).toBe(6);
			expect(config.thresholds.emailBonusPartial).toBe(4);
		});

		it('parseScoringConfig rejects tierSplit not summing to 100', () => {
			const bad = JSON.stringify({ tierSplit: { core: 80, protective: 20, hardening: 10 } });
			const config = parseScoringConfig(bad);
			expect(config.tierSplit.core).toBe(70);
		});
	});

	describe('toImportanceRecord', () => {
		it('wraps flat numbers in { importance } objects', () => {
			const result = toImportanceRecord({ spf: 10, dmarc: 22 });
			expect(result.spf).toEqual({ importance: 10 });
			expect(result.dmarc).toEqual({ importance: 22 });
		});
	});

	describe('config profileWeights derive from PROFILE_WEIGHTS', () => {
		// The values used to be restated as 324 literals in config.ts and hand-synced with
		// profiles.ts; `DEFAULT_SCORING_CONFIG.profileWeights` now DERIVES from PROFILE_WEIGHTS,
		// so drift is unrepresentable. These value assertions stay anyway — they are what proves
		// the derivation actually produces the same numbers, and they are the dual-surface
		// (source vs. built dist) check that a stale `dist/` can't slip past. The structural
		// "no literals may come back" half lives in scoring-profile-weights-ssot.audit.test.ts.

		it('is value-identical to PROFILE_WEIGHTS in BOTH directions for every profile', () => {
			const profiles = Object.keys(PROFILE_WEIGHTS) as Array<keyof typeof PROFILE_WEIGHTS>;
			expect(profiles.length).toBe(6);

			for (const profile of profiles) {
				const configWeights = DEFAULT_SCORING_CONFIG.profileWeights[profile];
				const profileWeights = PROFILE_WEIGHTS[profile];

				// Same key SET — a one-directional value loop would miss an extra/absent category.
				expect(Object.keys(configWeights).sort(), `${profile}: key sets differ`).toEqual(Object.keys(profileWeights).sort());

				for (const [key, value] of Object.entries(profileWeights)) {
					expect(
						configWeights[key as keyof typeof configWeights],
						`${profile}.${key}: config=${configWeights[key as keyof typeof configWeights]}, profiles=${value.importance}`,
					).toBe(value.importance);
				}
			}
		});

		it('survives a profileWeights override without mutating the shared default table', () => {
			// The derived tables are built once at module load, so an override that merged
			// in-place would silently repoint every later scan's weights.
			const before = { ...DEFAULT_SCORING_CONFIG.profileWeights.mail_enabled };
			parseScoringConfig(JSON.stringify({ profileWeights: { mail_enabled: { dnssec: 1 } } }));
			expect(DEFAULT_SCORING_CONFIG.profileWeights.mail_enabled).toEqual(before);
			expect(DEFAULT_SCORING_CONFIG.profileWeights.mail_enabled.dnssec).toBe(PROFILE_WEIGHTS.mail_enabled.dnssec.importance);
		});
	});

	describe('inert SCORING_CONFIG keys are surfaced, not silently ignored', () => {
		// Production ran a live SCORING_CONFIG that set only `coreWeights` — a key no
		// profile-aware scan reads — and it changed nothing, undetectably, because the parse
		// succeeded and the returned config really did carry the new numbers. The warning
		// exists to make that class of no-op loud. It must never throw and never change what
		// the config resolves to (fail-open is the doctrine for config here).

		/** Collect warnings without touching console, so the assertion can't race a spy. */
		function parseCapturingWarnings(json: string): { warnings: string[]; config: ReturnType<typeof parseScoringConfig> } {
			const warnings: string[] = [];
			const config = parseScoringConfig(json, { onWarn: (m) => warnings.push(m) });
			return { warnings, config };
		}

		it('warns for a coreWeights-only config, naming the key AND profileWeights', () => {
			const { warnings, config } = parseCapturingWarnings(JSON.stringify({ coreWeights: { dnssec: 7 } }));

			expect(warnings).toHaveLength(1);
			expect(warnings[0]).toContain('coreWeights');
			expect(warnings[0]).toContain('profileWeights');

			// Advisory only — the resolved config is unchanged by the warning.
			expect(config.coreWeights.dnssec).toBe(7);
		});

		it('does NOT warn for a profileWeights config', () => {
			const { warnings, config } = parseCapturingWarnings(JSON.stringify({ profileWeights: { mail_enabled: { dnssec: 7 } } }));

			expect(warnings).toEqual([]);
			expect(config.profileWeights.mail_enabled.dnssec).toBe(7);
		});

		it('does NOT warn for configs built only from keys the scan path DOES read', () => {
			for (const effective of [
				{ tierSplit: { core: 60, protective: 30, hardening: 10 } },
				{ thresholds: { criticalGapCeiling: 70 } },
				{ grades: { aPlus: 95 } },
				{ baselineFailureRates: { dmarc: 0.5 } },
			]) {
				const { warnings } = parseCapturingWarnings(JSON.stringify(effective));
				expect(warnings, `unexpected warning for ${JSON.stringify(effective)}`).toEqual([]);
			}
		});

		it('names every inert key present, not just the first', () => {
			const { warnings } = parseCapturingWarnings(
				JSON.stringify({
					weights: { spf: 15 },
					coreWeights: { dnssec: 7 },
					protectiveWeights: { mx: 5 },
					providerDkimConfidence: { google: 0.5 },
				}),
			);
			expect(warnings).toHaveLength(1);
			for (const key of ['weights', 'coreWeights', 'protectiveWeights', 'providerDkimConfidence']) {
				expect(warnings[0]).toContain(key);
			}
		});

		it('is silent on the paths that return defaults outright', () => {
			for (const raw of [undefined, '', '   ', 'not json', '[1,2,3]']) {
				const warnings: string[] = [];
				parseScoringConfig(raw as string | undefined, { onWarn: (m) => warnings.push(m) });
				expect(warnings, `unexpected warning for ${JSON.stringify(raw)}`).toEqual([]);
			}
		});

		it('never throws when no onWarn sink is supplied', () => {
			expect(() => parseScoringConfig(JSON.stringify({ coreWeights: { dnssec: 7 } }))).not.toThrow();
		});
	});
}
