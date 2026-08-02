// SPDX-License-Identifier: BUSL-1.1

/**
 * Shared scoring-profiles test suite — the single source of truth for these tests.
 *
 * Run against BOTH import surfaces so source↔built (dist/DTS) drift is caught:
 *   - packages/dns-checks/src/__tests__/scoring/scoring-profiles.spec.ts → source (`../../scoring`)
 *   - test/scoring-profiles.spec.ts → built package (`@blackveil/dns-checks/scoring`)
 *
 * The two thin spec files inject their respective module; the assertions and the
 * expected score/grade values live here once, so the trees can't drift apart.
 * NOT a `.spec.ts`/`.test.ts`, so neither vitest run collects it directly.
 */

import { describe, expect, it } from 'vitest';
import type { CheckCategory, CheckResult, DomainContext } from '../../scoring';

/** The scoring module under test — source or built package, injected by the caller. */
type ScoringModule = typeof import('../../scoring');

export function defineScoringProfilesSuite(s: ScoringModule): void {
	const {
		computeScanScore,
		computeProfileAwareScanScore,
		buildCheckResult,
		createFinding,
		getProfileWeights,
		PROFILE_WEIGHTS,
		PROFILE_CRITICAL_CATEGORIES,
		detectDomainContext,
	} = s;

	function makeResult(
		category: CheckCategory,
		score: number,
		title?: string,
		severity?: 'info' | 'low' | 'medium' | 'high' | 'critical',
	): CheckResult {
		const findings = [];
		if (score === 100) {
			findings.push(createFinding(category, title ?? `${category} OK`, 'info', 'Check passed'));
		} else if (score === 0) {
			findings.push(createFinding(category, title ?? `No ${category} record found`, severity ?? 'critical', `Missing ${category} record`));
			findings.push(createFinding(category, `${category} required`, severity ?? 'high', `${category} is required but not found`));
		} else {
			findings.push(createFinding(category, title ?? `${category} issue`, severity ?? 'medium', 'Issue detected'));
		}
		// Synthetic controlPresent for profile detection: a full-score check expresses an active control;
		// a zeroed one expresses an absent control. Mid-scores leave it undefined (scoring ignores it).
		const controlPresent = score === 100 ? true : score === 0 ? false : undefined;
		return buildCheckResult(category, findings, controlPresent);
	}

	function buildFullResults(overrides: Partial<Record<CheckCategory, CheckResult>> = {}): CheckResult[] {
		// Representative (not exhaustive) result set — Record<string, …> mirrors buildPartialResults
		// and avoids requiring every CheckCategory member; the exact set here is behavior-load-bearing
		// for the context tests below, so do not add/remove categories without re-checking scores.
		const defaults: Record<string, CheckResult> = {
			spf: makeResult('spf', 100),
			dmarc: makeResult('dmarc', 100),
			dkim: makeResult('dkim', 100),
			dnssec: makeResult('dnssec', 100),
			ssl: makeResult('ssl', 100),
			mta_sts: makeResult('mta_sts', 100),
			ns: makeResult('ns', 100),
			caa: makeResult('caa', 100),
			bimi: makeResult('bimi', 100),
			tlsrpt: makeResult('tlsrpt', 100),
			subdomain_takeover: makeResult('subdomain_takeover', 100),
			mx: makeResult('mx', 100),
			lookalikes: makeResult('lookalikes', 100),
			// Required by CheckResult record but not in original — add with 100
			shadow_domains: makeResult('shadow_domains', 100),
			txt_hygiene: makeResult('txt_hygiene', 100),
			http_security: makeResult('http_security', 100),
			dane: makeResult('dane', 100),
			mx_reputation: makeResult('mx_reputation', 100),
			srv: makeResult('srv', 100),
			zone_hygiene: makeResult('zone_hygiene', 100),
			dane_https: makeResult('dane_https', 100),
			svcb_https: makeResult('svcb_https', 100),
		};
		return Object.values({ ...defaults, ...overrides });
	}

	function makeNonMailContext(): DomainContext {
		return {
			profile: 'non_mail',
			signals: ['No MX records'],
			weights: getProfileWeights('non_mail'),
			detectedProvider: null,
		};
	}

	function makeEnterpriseContext(): DomainContext {
		return {
			profile: 'enterprise_mail',
			signals: ['MX present', 'google workspace provider', 'DKIM present'],
			weights: getProfileWeights('enterprise_mail'),
			detectedProvider: 'google workspace',
		};
	}

	describe('scoring-profiles', () => {
		describe('profile selection ignores UNMEASURED checks', () => {
			// Located 2026-08-02 as the mechanism behind a fabricated 88 on a domain that
			// does not exist. Profile detection reads `controlPresent` to decide whether a
			// domain is a web-only (non-mail) domain:
			//
			//     if (hasNoMx) { if (caaPass || sslPass) profile = 'web_only'; else 'non_mail'; }
			//
			// `sslPass`/`caaPass` consulted `controlPresent` WITHOUT checking `checkStatus`,
			// so a check that errored could still supply the positive evidence that selects
			// `web_only` — the one profile that weights spf/dmarc/dkim/mx at ZERO. The four
			// checks that correctly detected total failure were then weighted out of the
			// score entirely, and a dead domain graded ~88.
			//
			// The engine already knew better one screen down: `measuredChecks` filters BOTH
			// 'timeout' and 'error' before computing the failure-ratio signal. Only the
			// controlPresent reads were status-blind.
			function unmeasured(result: CheckResult, checkStatus: 'timeout' | 'error' = 'error'): CheckResult {
				return { ...result, checkStatus };
			}

			/** No MX, plus whatever ssl/caa evidence the caller wants to supply. */
			function noMxWith(overrides: Partial<Record<CheckCategory, CheckResult>>): CheckResult[] {
				return buildFullResults({
					spf: makeResult('spf', 0),
					dmarc: makeResult('dmarc', 0),
					dkim: makeResult('dkim', 0),
					mx: makeResult('mx', 0, 'No MX records found', 'info'),
					...overrides,
				});
			}

			it('an ERRORED ssl check cannot select the web_only profile', () => {
				const ctx = detectDomainContext(
					noMxWith({ ssl: unmeasured(makeResult('ssl', 100)), caa: makeResult('caa', 0) }),
				);
				expect(ctx.profile).not.toBe('web_only');
			});

			it('an ERRORED caa check cannot select the web_only profile either', () => {
				// Both reads are status-blind, so fixing only `sslPass` would leave the same
				// path open through CAA.
				const ctx = detectDomainContext(
					noMxWith({ ssl: makeResult('ssl', 0), caa: unmeasured(makeResult('caa', 100)) }),
				);
				expect(ctx.profile).not.toBe('web_only');
			});

			it('a TIMED-OUT check is treated the same as an errored one', () => {
				const ctx = detectDomainContext(
					noMxWith({ ssl: unmeasured(makeResult('ssl', 100), 'timeout'), caa: makeResult('caa', 0) }),
				);
				expect(ctx.profile).not.toBe('web_only');
			});

			it('an unmeasured MX check cannot assert "no MX" and downgrade the profile', () => {
				// `hasNoMx` is the gate in front of both non-mail profiles. An MX lookup that
				// FAILED must fall back to mail_enabled, never assert absence.
				const ctx = detectDomainContext(
					noMxWith({ mx: unmeasured(makeResult('mx', 0, 'No MX records found', 'info')), ssl: makeResult('ssl', 100) }),
				);
				expect(ctx.profile).toBe('mail_enabled');
			});

			it('DISCRIMINATES: a MEASURED ssl/caa pass still selects web_only', () => {
				// Without this the suite would also pass against an implementation that simply
				// never selects web_only. Genuine web-only domains must keep their profile.
				const ctx = detectDomainContext(noMxWith({ ssl: makeResult('ssl', 100), caa: makeResult('caa', 100) }));
				expect(ctx.profile).toBe('web_only');
			});
		});

		describe('profile-aware auto scoring', () => {
			it('auto-detects web_only context and matches explicit web_only scoring', () => {
				const results = buildFullResults({
					spf: makeResult('spf', 0, 'No SPF record found', 'critical'),
					dmarc: makeResult('dmarc', 0, 'No DMARC record found', 'critical'),
					dkim: makeResult('dkim', 0, 'No DKIM record found', 'critical'),
					mx: makeResult('mx', 0, 'No MX records found', 'info'),
					ssl: makeResult('ssl', 100),
					caa: makeResult('caa', 100),
					http_security: makeResult('http_security', 95, 'HTTP headers configured', 'info'),
				});
				const explicitWebOnly: DomainContext = {
					profile: 'web_only',
					signals: ['No MX records', 'SSL valid', 'CAA present'],
					weights: getProfileWeights('web_only'),
					detectedProvider: null,
				};

				const auto = computeProfileAwareScanScore(results);
				const explicit = computeScanScore(results, explicitWebOnly);
				const legacy = computeScanScore(results);

				expect(auto.profile).toBe('web_only');
				expect(auto.score.overall).toBe(explicit.overall);
				expect(auto.score.overall).toBeGreaterThan(legacy.overall);
			});

			it('allows explicit profile override while still returning detected signals', () => {
				const results = buildFullResults({
					spf: makeResult('spf', 0, 'No SPF record found', 'critical'),
					dmarc: makeResult('dmarc', 0, 'No DMARC record found', 'critical'),
					mx: makeResult('mx', 0, 'No MX records found', 'info'),
					ssl: makeResult('ssl', 100),
					caa: makeResult('caa', 100),
				});

				const scored = computeProfileAwareScanScore(results, { profile: 'mail_enabled' });

				expect(scored.detectedProfile).toBe('web_only');
				expect(scored.profile).toBe('mail_enabled');
				expect(scored.context.signals).toContain('explicit profile override: mail_enabled');
				expect(scored.score.overall).toBe(
					computeScanScore(results, {
						profile: 'mail_enabled',
						signals: ['No MX records', 'SSL valid', 'CAA present', 'explicit profile override: mail_enabled'],
						weights: getProfileWeights('mail_enabled'),
						detectedProvider: null,
					}).overall,
				);
			});
		});

		describe('regression: computeScanScore without context', () => {
			it('returns identical results to pre-profile behavior', () => {
				const results = buildFullResults();
				const withoutContext = computeScanScore(results);
				const withUndefined = computeScanScore(results, undefined);
				expect(withoutContext.overall).toBe(withUndefined.overall);
				expect(withoutContext.grade).toBe(withUndefined.grade);
			});

			it('empty results are ungraded, not context-dependent (evidence gate fires before profile logic)', () => {
				// Was: "empty results still return 100" — pinning that the no-context path
				// behaves the same regardless of profile context. That intent survives: the
				// evidence gate fires uniformly for both, before any profile weighting runs.
				const score = computeScanScore([]);
				expect(score.overall).toBeNull();
				expect(score.evidenceInsufficient).toBe(true);
			});
		});

		describe('non_mail context', () => {
			it('does NOT cap score at 64 when SPF/DMARC are missing', () => {
				const results = buildFullResults({
					spf: makeResult('spf', 0, 'No SPF record found', 'critical'),
					dmarc: makeResult('dmarc', 0, 'No DMARC record found', 'critical'),
				});
				const nonMailCtx = makeNonMailContext();
				const withContext = computeScanScore(results, nonMailCtx);
				// SPF/DMARC are NOT in non_mail critical categories, so no ceiling
				expect(withContext.overall).toBeGreaterThan(64);
			});

			it('DOES cap score at 64 when SSL is missing (critical for non_mail)', () => {
				const results = buildFullResults({
					ssl: makeResult('ssl', 0, 'No valid certificate found', 'critical'),
				});
				const nonMailCtx = makeNonMailContext();
				const withContext = computeScanScore(results, nonMailCtx);
				expect(withContext.overall).toBeLessThanOrEqual(64);
			});

			it('does NOT award email bonus', () => {
				// All email checks pass — but non_mail profile should skip bonus
				const results = buildFullResults();
				const nonMailCtx = makeNonMailContext();
				const withContext = computeScanScore(results, nonMailCtx);
				const withoutContext = computeScanScore(results);
				// Without context, email bonus applies. With non_mail, it doesn't.
				// Both should be high scores but may differ slightly due to bonus
				expect(withContext.overall).toBeLessThanOrEqual(withoutContext.overall);
			});
		});

		describe('enterprise_mail context', () => {
			it('elevates MTA-STS importance', () => {
				// With enterprise profile, MTA-STS weight is 4 vs 3 for mail_enabled.
				// Both produce the same integer score because the tier budget is fixed
				// and rounding absorbs the difference. Verify enterprise penalizes at least
				// as much as default.
				const results = buildFullResults({
					mta_sts: makeResult('mta_sts', 0, 'No MTA-STS record found', 'high'),
				});
				const enterpriseCtx = makeEnterpriseContext();
				const withEnterprise = computeScanScore(results, enterpriseCtx);
				const withoutContext = computeScanScore(results);
				// Enterprise MTA-STS weight (4/22 of protective budget) >= default (3/20)
				expect(withEnterprise.overall).toBeLessThanOrEqual(withoutContext.overall);
			});

			it('awards email bonus when eligible', () => {
				const results = buildFullResults();
				const enterpriseCtx = makeEnterpriseContext();
				const score = computeScanScore(results, enterpriseCtx);
				// With all checks passing, email bonus should be awarded
				expect(score.overall).toBeGreaterThanOrEqual(90);
			});
		});

		describe('snapshot: known result sets with expected scores per profile', () => {
			// Limit to core+partial set matching original test (no extra hardening noise)
			function buildPartialResults(overrides: Partial<Record<CheckCategory, CheckResult>> = {}): CheckResult[] {
				const defaults: Record<string, CheckResult> = {
					spf: makeResult('spf', 100),
					dmarc: makeResult('dmarc', 100),
					dkim: makeResult('dkim', 100),
					dnssec: makeResult('dnssec', 100),
					ssl: makeResult('ssl', 100),
					mta_sts: makeResult('mta_sts', 100),
					ns: makeResult('ns', 100),
					caa: makeResult('caa', 100),
					bimi: makeResult('bimi', 100),
					tlsrpt: makeResult('tlsrpt', 100),
					subdomain_takeover: makeResult('subdomain_takeover', 100),
					mx: makeResult('mx', 100),
					lookalikes: makeResult('lookalikes', 100),
				};
				return Object.values({ ...defaults, ...overrides });
			}

			const allPassing = buildPartialResults();

			it('all passing with mail_enabled (default) profile', () => {
				const score = computeScanScore(allPassing);
				// Three-tier: core=70, protective=20, hardening=2/10*10=2.0 → base≈92 + email bonus 5 = 97
				// (only bimi + tlsrpt have results in hardening tier out of 10 hardening categories)
				expect(score.overall).toBe(97);
				expect(score.grade).toBe('A+');
			});

			it('all passing with enterprise_mail profile', () => {
				const score = computeScanScore(allPassing, makeEnterpriseContext());
				// Same hardening gap as mail_enabled → 97
				expect(score.overall).toBe(97);
				expect(score.grade).toBe('A+');
			});

			it('all passing with non_mail profile', () => {
				const score = computeScanScore(allPassing, makeNonMailContext());
				// No email bonus for non_mail → base ≈ 92
				expect(score.overall).toBe(92);
				expect(score.grade).toBe('A+');
			});

			it('missing SPF+DMARC: non_mail scores higher than default', () => {
				const results = buildPartialResults({
					spf: makeResult('spf', 0, 'No SPF record found', 'critical'),
					dmarc: makeResult('dmarc', 0, 'No DMARC record found', 'critical'),
				});
				const defaultScore = computeScanScore(results);
				const nonMailScore = computeScanScore(results, makeNonMailContext());
				expect(nonMailScore.overall).toBeGreaterThan(defaultScore.overall);
			});
		});

		describe('failureRatio counts only MEASURED checks', () => {
			/** A check that ran and passed. */
			function ok(category: CheckCategory): CheckResult {
				return {
					...buildCheckResult(category, [createFinding(category, `${category} OK`, 'info', 'Check passed')], true),
					checkStatus: 'completed',
				};
			}
			/** A check that ran and genuinely failed. */
			function failed(category: CheckCategory): CheckResult {
				return {
					...buildCheckResult(category, [createFinding(category, `No ${category} record found`, 'critical', 'Missing record')], false),
					score: 0,
					passed: false,
					checkStatus: 'completed' as const,
				};
			}
			/** A check that never ran — exactly the shape scan-domain.ts:671 produces on a per-check timeout. */
			function unmeasured(category: CheckCategory): CheckResult {
				return {
					...buildCheckResult(category, [createFinding(category, `${category.toUpperCase()} check timed out`, 'low', 'Did not complete')]),
					score: 0,
					passed: false,
					checkStatus: 'timeout' as const,
				};
			}
			/** A check that ran and passed but predates the `checkStatus` field (absent checkStatus) —
			 * a legacy CheckResult shape that must still count as measured, not be silently excluded. */
			function legacy(category: CheckCategory): CheckResult {
				return buildCheckResult(category, [createFinding(category, `${category} OK`, 'info', 'Check passed')], true);
			}
			/** A check whose `checkStatus` is OUTSIDE the closed CheckStatus union — reachable at
			 * runtime via an unvalidated re-read of a cached CheckResult (e.g. a version-skewed
			 * deploy), never constructible through the typed CheckResult surface. Must NOT count as
			 * measured: a denylist predicate (`!== 'timeout' && !== 'error'`) would let it through. */
			function unknownStatus(category: CheckCategory): CheckResult {
				return {
					...buildCheckResult(category, [createFinding(category, `${category} check`, 'low', 'stale cache entry')]),
					score: 0,
					passed: false,
					checkStatus: 'pending_migration' as unknown as CheckResult['checkStatus'],
				};
			}

			it('does NOT flip to the minimal profile when the majority of checks merely FAILED TO RUN', () => {
				// 3 measured and passing, 7 unmeasured. Old behaviour: 7/10 = 0.7 > 0.5 → minimal.
				// New behaviour: the ratio is computed over the 3 measured checks, 0/3 = 0 → no flip.
				const results: CheckResult[] = [
					ok('mx'),
					ok('spf'),
					ok('dmarc'),
					unmeasured('dnssec'),
					unmeasured('ssl'),
					unmeasured('caa'),
					unmeasured('ns'),
					unmeasured('mta_sts'),
					unmeasured('subdomain_takeover'),
					unmeasured('http_security'),
				];
				const ctx = detectDomainContext(results);
				expect(ctx.profile).not.toBe('minimal');
				const failureSignals = ctx.signals.filter((sig) => sig.includes('checks failed'));
				expect(failureSignals).toHaveLength(0);
			});

			it('STILL flips to minimal when the majority of checks ran and genuinely failed (behaviour preserved)', () => {
				const results: CheckResult[] = [ok('mx'), ok('spf'), failed('dmarc'), failed('dnssec'), failed('ssl'), failed('caa'), failed('ns')];
				const ctx = detectDomainContext(results);
				expect(ctx.profile).toBe('minimal');
				const failureSignals = ctx.signals.filter((sig) => sig.includes('checks failed'));
				// Non-empty guard: without it the signal-content assertion below could never execute.
				expect(failureSignals.length).toBeGreaterThan(0);
				expect(failureSignals[0]).toContain('71%'); // 5 failed of 7 measured
			});

			it('is UNCHANGED for a result set where every check completed', () => {
				// The "73 stays 73" guarantee: with no unmeasured checks, the filter is a no-op.
				const results: CheckResult[] = [ok('mx'), ok('spf'), ok('dmarc'), failed('dnssec'), failed('ssl')];
				const ctx = detectDomainContext(results);
				expect(ctx.profile).toBe('mail_enabled');
				expect(ctx.signals.filter((sig) => sig.includes('checks failed'))).toHaveLength(0); // 2/5 = 0.4, not > 0.5
			});

			it('flips to minimal when ALL measured checks failed, even though unmeasured checks outnumber them (denominator must exclude unmeasured too)', () => {
				// 3 measured, all genuinely failed; 7 unmeasured. Correct: 3 failed / 3 measured = 100% → minimal.
				// A half-fix that filters only the numerator but still divides by results.length (10)
				// would compute 3/10 = 30% → mail_enabled, silently making `minimal` unreachable whenever
				// timeouts coexist with real failures. This test pins the DENOMINATOR half of the fix.
				const results: CheckResult[] = [
					failed('spf'),
					failed('dmarc'),
					failed('dnssec'),
					unmeasured('ssl'),
					unmeasured('caa'),
					unmeasured('ns'),
					unmeasured('mta_sts'),
					unmeasured('subdomain_takeover'),
					unmeasured('http_security'),
					unmeasured('bimi'),
				];
				const ctx = detectDomainContext(results);
				expect(ctx.profile).toBe('minimal');
				const failureSignals = ctx.signals.filter((sig) => sig.includes('checks failed'));
				expect(failureSignals.length).toBeGreaterThan(0);
				expect(failureSignals[0]).toContain('100%'); // 3 failed of 3 measured
			});

			it('does not flip or emit a signal when NO check was measured at all (denominator-zero guard)', () => {
				// All checks unmeasured — totalChecks === 0 is reachable with a non-empty result set.
				// failureRatio must resolve to 0 (not NaN), so there is no flip and no signal.
				const results: CheckResult[] = [unmeasured('spf'), unmeasured('dmarc'), unmeasured('dnssec'), unmeasured('ssl'), unmeasured('caa')];
				const ctx = detectDomainContext(results);
				expect(ctx.profile).not.toBe('minimal');
				expect(ctx.signals.filter((sig) => sig.includes('checks failed'))).toHaveLength(0);
			});

			it('treats a check with ABSENT checkStatus (legacy CheckResult shape) as measured', () => {
				// 2 legacy-passing (no checkStatus property at all) + 3 explicit-failed = 5 measured;
				// 3/5 = 60% > 50% → minimal. A wrong-predicate mutation (checkStatus === 'completed'
				// instead of !== 'timeout' && !== 'error') would exclude the legacy checks from BOTH
				// counts, landing on 3/3 = 100% instead — the '60%' assertion below catches that.
				const results: CheckResult[] = [legacy('spf'), legacy('caa'), failed('dmarc'), failed('dnssec'), failed('ssl')];
				const ctx = detectDomainContext(results);
				expect(ctx.profile).toBe('minimal');
				const failureSignals = ctx.signals.filter((sig) => sig.includes('checks failed'));
				expect(failureSignals.length).toBeGreaterThan(0);
				expect(failureSignals[0]).toContain('60%'); // 3 failed of 5 measured (incl. 2 legacy-passing)
			});

			it('treats an OUT-OF-UNION checkStatus (e.g. a version-skewed cache re-read) as UNMEASURED, excluded from both numerator and denominator', () => {
				// 2 measured-passing + 3 unrecognized-status entries. If a denylist predicate let the
				// unrecognized status through as "measured", these 3 (each `passed: false`) would count
				// as measured failures: 3 failed / 5 measured = 60% > 50% -> minimal, and the 'checks
				// failed' signal would report '60%'. The allowlist form must exclude them from BOTH
				// counts instead, leaving 0 measured failures out of 2 measured -> no flip, no signal.
				const results: CheckResult[] = [ok('mx'), ok('spf'), unknownStatus('dnssec'), unknownStatus('ssl'), unknownStatus('caa')];
				const ctx = detectDomainContext(results);
				expect(ctx.profile).not.toBe('minimal');
				expect(ctx.signals.filter((sig) => sig.includes('checks failed'))).toHaveLength(0);
			});
		});

		describe('scoring v2 profile weights', () => {
			it('mail_enabled core weights sum to 54', () => {
				const core = PROFILE_WEIGHTS.mail_enabled;
				const coreSum = (['spf', 'dmarc', 'dkim', 'dnssec', 'ssl'] as const).reduce((sum, k) => sum + core[k].importance, 0);
				expect(coreSum).toBe(54);
			});

			it('mail_enabled protective weights sum to 20', () => {
				const p = PROFILE_WEIGHTS.mail_enabled;
				const protSum = (
					['subdomain_takeover', 'http_security', 'mta_sts', 'mx', 'caa', 'ns', 'lookalikes', 'shadow_domains'] as const
				).reduce((sum, k) => sum + p[k].importance, 0);
				expect(protSum).toBe(20);
			});

			it('mail_enabled hardening weights are all 0', () => {
				const p = PROFILE_WEIGHTS.mail_enabled;
				for (const cat of ['dane', 'bimi', 'tlsrpt', 'txt_hygiene', 'mx_reputation', 'srv', 'zone_hygiene'] as const) {
					expect(p[cat].importance).toBe(0);
				}
			});

			it('enterprise_mail core weights sum to 63', () => {
				const core = PROFILE_WEIGHTS.enterprise_mail;
				const coreSum = (['spf', 'dmarc', 'dkim', 'dnssec', 'ssl'] as const).reduce((sum, k) => sum + core[k].importance, 0);
				expect(coreSum).toBe(63);
			});

			it('web_only zeroes email auth core weights', () => {
				const p = PROFILE_WEIGHTS.web_only;
				expect(p.spf.importance).toBe(0);
				expect(p.dmarc.importance).toBe(0);
				expect(p.dkim.importance).toBe(0);
				expect(p.ssl.importance).toBeGreaterThan(0);
			});

			it('non_mail core weights sum to 29', () => {
				const core = PROFILE_WEIGHTS.non_mail;
				const coreSum = (['spf', 'dmarc', 'dkim', 'dnssec', 'ssl'] as const).reduce((sum, k) => sum + core[k].importance, 0);
				expect(coreSum).toBe(29);
			});

			it('minimal core weights sum to 15', () => {
				const core = PROFILE_WEIGHTS.minimal;
				const coreSum = (['spf', 'dmarc', 'dkim', 'dnssec', 'ssl'] as const).reduce((sum, k) => sum + core[k].importance, 0);
				expect(coreSum).toBe(15);
			});

			it('DNSSEC is critical in all profiles per NIST SP 800-81r3', () => {
				expect(PROFILE_CRITICAL_CATEGORIES.mail_enabled).toContain('dnssec');
				expect(PROFILE_CRITICAL_CATEGORIES.enterprise_mail).toContain('dnssec');
				expect(PROFILE_CRITICAL_CATEGORIES.non_mail).toContain('dnssec');
				expect(PROFILE_CRITICAL_CATEGORIES.web_only).toContain('dnssec');
				expect(PROFILE_CRITICAL_CATEGORIES.minimal).toContain('dnssec');
			});

			it('mail profiles include email auth + DNSSEC', () => {
				expect(PROFILE_CRITICAL_CATEGORIES.mail_enabled).toEqual(expect.arrayContaining(['spf', 'dmarc', 'dkim', 'ssl', 'dnssec']));
			});

			it('non_mail/web_only include DANE_HTTPS for certificate integrity', () => {
				expect(PROFILE_CRITICAL_CATEGORIES.non_mail).toContain('dane_https');
				expect(PROFILE_CRITICAL_CATEGORIES.web_only).toContain('dane_https');
			});

			it('non_mail/web_only ceiling triggers include http_security', () => {
				expect(PROFILE_CRITICAL_CATEGORIES.non_mail).toContain('http_security');
				expect(PROFILE_CRITICAL_CATEGORIES.web_only).toContain('http_security');
			});

			it('minimal ceiling triggers ssl + dnssec + subdomain_takeover', () => {
				expect(PROFILE_CRITICAL_CATEGORIES.minimal).toEqual(['ssl', 'dnssec', 'subdomain_takeover']);
			});

			it('mail_enabled DNSSEC weight is NIST-aligned at 10', () => {
				expect(PROFILE_WEIGHTS.mail_enabled.dnssec.importance).toBe(10);
			});

			it('enterprise_mail DMARC weight is 20 and DNSSEC is 13', () => {
				expect(PROFILE_WEIGHTS.enterprise_mail.dmarc.importance).toBe(20);
				expect(PROFILE_WEIGHTS.enterprise_mail.dnssec.importance).toBe(13);
			});

			it('web_only DNSSEC and SSL are co-equal at 14', () => {
				expect(PROFILE_WEIGHTS.web_only.dnssec.importance).toBe(14);
				expect(PROFILE_WEIGHTS.web_only.ssl.importance).toBe(14);
			});

			it('non_mail has elevated DMARC=3, DKIM=2, DNSSEC=12, SSL=10', () => {
				expect(PROFILE_WEIGHTS.non_mail.dmarc.importance).toBe(3);
				expect(PROFILE_WEIGHTS.non_mail.dkim.importance).toBe(2);
				expect(PROFILE_WEIGHTS.non_mail.dnssec.importance).toBe(12);
				expect(PROFILE_WEIGHTS.non_mail.ssl.importance).toBe(10);
			});

			it('minimal has DNSSEC=5, SSL=7', () => {
				expect(PROFILE_WEIGHTS.minimal.dnssec.importance).toBe(5);
				expect(PROFILE_WEIGHTS.minimal.ssl.importance).toBe(7);
			});

			it('authoritative_dns_infra treats mail and web controls as non-scoring noise', () => {
				const p = PROFILE_WEIGHTS.authoritative_dns_infra;
				expect(p.authoritative_dns_infra.importance).toBe(40);
				expect(p.dnssec.importance).toBe(20);
				expect(p.ns.importance).toBe(15);
				expect(p.zone_hygiene.importance).toBe(10);
				expect(p.spf.importance).toBe(0);
				expect(p.dmarc.importance).toBe(0);
				expect(p.dkim.importance).toBe(0);
				expect(p.ssl.importance).toBe(0);
				expect(p.http_security.importance).toBe(0);
			});

			it('SUBDOMAIN_TAKEOVER is critical for mail_enabled', () => {
				expect(PROFILE_CRITICAL_CATEGORIES.mail_enabled).toContain('subdomain_takeover');
			});

			it('SUBDOMAIN_TAKEOVER is critical for enterprise_mail', () => {
				expect(PROFILE_CRITICAL_CATEGORIES.enterprise_mail).toContain('subdomain_takeover');
			});

			it('SUBDOMAIN_TAKEOVER is critical for minimal', () => {
				expect(PROFILE_CRITICAL_CATEGORIES.minimal).toContain('subdomain_takeover');
			});
		});
	});
}
