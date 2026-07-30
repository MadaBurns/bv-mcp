// SPDX-License-Identifier: BUSL-1.1

/**
 * Shared scoring-engine test suite — the single source of truth for these tests.
 *
 * Run against BOTH import surfaces so source↔built (dist/DTS) drift is caught:
 *   - packages/dns-checks/src/__tests__/scoring/scoring-engine.spec.ts → source (`../../scoring`)
 *   - test/scoring-engine.spec.ts → built package (`@blackveil/dns-checks/scoring`)
 *
 * The two thin spec files inject their respective module; the assertions live
 * here once, so the trees can't drift apart. NOT a `.spec.ts`/`.test.ts`, so
 * neither vitest run collects it directly.
 */

import { describe, expect, it } from 'vitest';
import type { CheckCategory, CheckResult } from '../../scoring';

/** The scoring module under test — source or built package, injected by the caller. */
type ScoringModule = typeof import('../../scoring');

export function defineScoringEngineSuite(s: ScoringModule): void {
	const {
		scoreToGrade,
		nistScoreToGrade,
		NIST_GRADE_THRESHOLDS,
		computeScanScore,
		IMPORTANCE_WEIGHTS,
		CORE_WEIGHTS,
		PROTECTIVE_WEIGHTS,
		buildCheckResult,
		createFinding,
		CATEGORY_DISPLAY_WEIGHTS,
		DEFAULT_SCORING_CONFIG,
	} = s;

	describe('scoring-engine', () => {
		it('maps numeric scores to expected grade bands', () => {
			expect(scoreToGrade(92)).toBe('A+');
			expect(scoreToGrade(87)).toBe('A');
			expect(scoreToGrade(49)).toBe('F');
		});

		it('maps numeric scores to the NIST-aligned 6-band DISPLAY grade', () => {
			// Cut-points: A+≥95, A≥90, B≥80, C≥70, D≥60, F<60.
			expect(nistScoreToGrade(100)).toBe('A+');
			expect(nistScoreToGrade(95)).toBe('A+');
			expect(nistScoreToGrade(94)).toBe('A');
			expect(nistScoreToGrade(90)).toBe('A');
			expect(nistScoreToGrade(89)).toBe('B');
			expect(nistScoreToGrade(80)).toBe('B');
			expect(nistScoreToGrade(79)).toBe('C');
			expect(nistScoreToGrade(70)).toBe('C');
			expect(nistScoreToGrade(69)).toBe('D');
			expect(nistScoreToGrade(60)).toBe('D');
			expect(nistScoreToGrade(59)).toBe('F');
			expect(nistScoreToGrade(0)).toBe('F');
		});

		it('NIST 6-band emits no +/- bands (distinct from the 9-band canonical scale)', () => {
			const seen = new Set(Array.from({ length: 101 }, (_, score) => nistScoreToGrade(score)));
			expect([...seen].sort()).toEqual(['A', 'A+', 'B', 'C', 'D', 'F']);
			// thresholds are exported + consistent with the mapping
			expect(NIST_GRADE_THRESHOLDS.A_PLUS).toBe(95);
			expect(NIST_GRADE_THRESHOLDS.D).toBe(60);
		});

		it('withholds the grade when no check results are present (zero evidence, not a clean scan)', () => {
			// Was: seeded overall 100 / "Excellent!" summary for zero submitted checks — the
			// defect this whole gate exists to remove. The intent this test pins is "empty
			// input is handled and produces a coherent, explanatory summary" — that summary
			// is now the evidence note, not a fabricated clean bill of health.
			const scan = computeScanScore([]);
			expect(scan.overall).toBeNull();
			expect(scan.grade).toBeNull();
			expect(scan.evidenceInsufficient).toBe(true);
			expect(scan.summary).toContain('No checks were submitted for scoring');
		});

		it('surfaces the three-tier breakdown on the scan score', () => {
			const scan = computeScanScore([
				buildCheckResult('http_security', [createFinding('http_security', 'No CSP', 'high', 'Missing Content-Security-Policy')]),
			]);
			expect(scan.tierBreakdown).toBeDefined();
			expect(typeof scan.tierBreakdown?.core).toBe('number');
			expect(typeof scan.tierBreakdown?.protective).toBe('number');
			expect(typeof scan.tierBreakdown?.hardening).toBe('number');
			// core tier is the 70-point budget; all core checks absent → 100% → full core points
			expect(scan.tierBreakdown?.core).toBeGreaterThan(0);
		});

		it('omits the tier breakdown for the degenerate no-checks result', () => {
			// The empty-results early return is intentionally minimal (optional field absent).
			expect(computeScanScore([]).tierBreakdown).toBeUndefined();
		});

		it('applies verified critical penalty during aggregate scoring', () => {
			const scan = computeScanScore([
				buildCheckResult('subdomain_takeover', [
					createFinding('subdomain_takeover', 'Verified takeover', 'critical', 'Fingerprint confirmed', {
						verificationStatus: 'verified',
					}),
				]),
			]);

			// Core: all never-run → excluded (empty tier renormalizes to 100%) → 70 points.
			// Protective: ONLY subdomain_takeover ran (score=60, weight=4); every other protective
			// category is never-run and excluded (NOT padded to 100 — that was the masking bug), so
			// protective renormalizes over the single measured category: (60/100)*4 / 4 = 0.6 → 12.
			// Base: 70 + 12 + 0 = 82; no email bonus (spf/dmarc absent); then -15 verified-critical = 67.
			expect(scan.overall).toBeLessThanOrEqual(70);
			expect(scan.overall).toBeGreaterThanOrEqual(64);
		});

		it('IMPORTANCE_WEIGHTS covers every CheckCategory value', () => {
			const displayKeys = Object.keys(CATEGORY_DISPLAY_WEIGHTS).sort();
			const importanceKeys = Object.keys(IMPORTANCE_WEIGHTS).sort();
			expect(importanceKeys).toEqual(displayKeys);
		});

		it('computeScanScore reports NO category scores when nothing ran (never a phantom 100)', () => {
			// A category that produced no result was not measured — it must be absent from
			// categoryScores, never seeded to a misleading perfect 100 (which read as "clean" and
			// silently earned full weight). With zero results, the map is empty.
			const scan = computeScanScore([]);
			const categories: CheckCategory[] = Object.keys(CATEGORY_DISPLAY_WEIGHTS) as CheckCategory[];
			for (const cat of categories) {
				expect(scan.categoryScores[cat]).toBeUndefined();
			}
			expect(Object.keys(scan.categoryScores)).toHaveLength(0);
		});

		it('exports CORE_WEIGHTS and PROTECTIVE_WEIGHTS', () => {
			expect(CORE_WEIGHTS).toBeDefined();
			expect(PROTECTIVE_WEIGHTS).toBeDefined();
			expect(Object.keys(CORE_WEIGHTS)).toContain('dmarc');
			expect(Object.keys(PROTECTIVE_WEIGHTS)).toContain('subdomain_takeover');
		});

		describe('evidence-sufficiency gate', () => {
			function ok(category: CheckCategory): CheckResult {
				return { ...buildCheckResult(category, [createFinding(category, `${category} OK`, 'info', 'ok')], true), checkStatus: 'completed' };
			}
			function unmeasured(category: CheckCategory): CheckResult {
				return {
					...buildCheckResult(category, [createFinding(category, `${category} timed out`, 'low', 'no run')]),
					score: 0,
					passed: false,
					checkStatus: 'timeout' as const,
				};
			}
			const CATS: CheckCategory[] = [
				'mx',
				'spf',
				'dmarc',
				'dkim',
				'dnssec',
				'ssl',
				'caa',
				'ns',
				'mta_sts',
				'subdomain_takeover',
				'http_security',
				'bimi',
				'tlsrpt',
				'dane',
				'ptr',
				'srv',
				'txt_hygiene',
				'zone_hygiene',
				'subdomailing',
			];
			/** 19 categories, the first `nCompleted` measured and the rest unmeasured. */
			function scan(nCompleted: number): CheckResult[] {
				return CATS.map((c, i) => (i < nCompleted ? ok(c) : unmeasured(c)));
			}

			// 20 categories — one more than CATS — chosen SPECIFICALLY so the default 60%
			// threshold lands on a whole number (12/20 = 0.60 exactly). 19 categories can
			// never hit the boundary (12/19 = 63.2%, 11/19 = 57.9%), so a `>=` → `>` mutation
			// in `isEvidenceSufficient` would survive every OTHER assertion in this file.
			const CATS_AT_BOUNDARY: CheckCategory[] = [...CATS, 'lookalikes'];
			function scanAtBoundary(nCompleted: number): CheckResult[] {
				return CATS_AT_BOUNDARY.map((c, i) => (i < nCompleted ? ok(c) : unmeasured(c)));
			}

			it('withholds the grade when fewer than 60% of attempted checks completed', () => {
				// 4/19 = 21%.
				const score = computeScanScore(scan(4));
				expect(score.overall).toBeNull();
				expect(score.grade).toBeNull();
				expect(score.evidenceInsufficient).toBe(true);
				expect(score.evidence).toEqual({ attempted: 19, completed: 4, ratio: 4 / 19 });
				// tierBreakdown is brief-mandated payload on the ungraded (non-empty-input)
				// path — it was computed before the gate fired and stays available so a
				// caller can still see the tier-weighted composition behind the (withheld)
				// number, same as findings/categoryScores. Deleting the `tierBreakdown:
				// genericResult.tierBreakdown` line from the gate's return object survives
				// every OTHER assertion in this file, so this must be pinned directly.
				expect(score.tierBreakdown).toBeDefined();
			});

			it('explains WHY the grade is absent, in the note and in the summary', () => {
				const score = computeScanScore(scan(4));
				expect(score.evidenceNote).toBeDefined();
				expect(score.evidenceNote).toContain('4 of 19');
				// The summary is what the text report renders verbatim for an ungraded scan,
				// so it must carry the explanation rather than a stale "Grade: X" string.
				expect(score.summary).toBe(score.evidenceNote);
				expect(score.summary).not.toMatch(/Grade: [A-F]/);
			});

			it('still returns everything that WAS measured', () => {
				const score = computeScanScore(scan(4));
				// The four completed checks contributed their findings and category scores.
				expect(score.findings.length).toBeGreaterThan(0);
				expect(Object.keys(score.categoryScores).length).toBeGreaterThan(0);
			});

			it('grades AT the threshold exactly, ungrades just below it (gate compares ratio >= threshold, never >)', () => {
				// 12/20 = 0.60 lands exactly ON the default threshold: the gate must still grade,
				// because it withholds on ratio < threshold, not <=. A `>=` → `>` mutation in
				// isEvidenceSufficient would incorrectly ungrade this case.
				const atThreshold = computeScanScore(scanAtBoundary(12));
				expect(atThreshold.overall).not.toBeNull();
				expect(atThreshold.grade).not.toBeNull();
				expect(atThreshold.evidenceInsufficient).toBeUndefined();

				// 11/20 = 0.55 — one check short of the boundary — must ungrade.
				const justBelow = computeScanScore(scanAtBoundary(11));
				expect(justBelow.overall).toBeNull();
				expect(justBelow.evidenceInsufficient).toBe(true);
			});

			it('respects a SCORING_CONFIG threshold override', () => {
				const strict = { ...DEFAULT_SCORING_CONFIG, thresholds: { ...DEFAULT_SCORING_CONFIG.thresholds, evidenceSufficiency: 0.95 } };
				const score = computeScanScore(scan(18), undefined, strict); // 18/19 = 94.7%
				expect(score.overall).toBeNull();
				expect(score.evidenceInsufficient).toBe(true);

				const lenient = { ...DEFAULT_SCORING_CONFIG, thresholds: { ...DEFAULT_SCORING_CONFIG.thresholds, evidenceSufficiency: 0.1 } };
				expect(computeScanScore(scan(4), undefined, lenient).overall).not.toBeNull();
			});

			it('clamps an out-of-range threshold on a HAND-BUILT config too, not just one parsed via parseScoringConfig', () => {
				// parseScoringConfig's own [0,1] clamp (config.ts) only runs for configs
				// parsed from a SCORING_CONFIG JSON string. computeScanScore is a published,
				// directly-callable API — a caller (this package's own vendoring consumers
				// included) can hand-build a ScoringConfig and pass it straight in, bypassing
				// that clamp entirely. A percent-not-ratio typo (60 meaning "60%") must not
				// ungrade every scan that reaches the function this way; it must clamp to 1
				// (maximally strict) exactly like the parsed path does.
				const percentTypo = {
					...DEFAULT_SCORING_CONFIG,
					thresholds: { ...DEFAULT_SCORING_CONFIG.thresholds, evidenceSufficiency: 60 },
				};
				// If the clamp is missing, 60 stays 60 and NOTHING can satisfy `ratio >= 60`
				// (ratio never exceeds 1) — every scan, including a fully-complete one, would
				// ungrade. Using a fully-complete 19/19 scan proves the clamp lands at exactly
				// 1 (the maximally strict, still-satisfiable value), not merely "less broken".
				const score = computeScanScore(scan(19), undefined, percentTypo);
				expect(score.overall).not.toBeNull();
				expect(score.grade).not.toBeNull();
				expect(score.evidenceInsufficient).toBeUndefined();
			});

			it('falls back to the default threshold when a hand-built config supplies a NaN, not just a missing key', () => {
				// `Number(undefined)` is NaN, not undefined — a vendoring consumer building
				// `{ evidenceSufficiency: Number(undefined) }` bypasses the `?? EVIDENCE_SUFFICIENCY_THRESHOLD`
				// fallback (`??` only catches null/undefined) and lands directly in the clamp:
				// `Math.max(0, Math.min(1, NaN))` is NaN, and `ratio >= NaN` is always false, so
				// EVERY scan — including a fully-measured, healthy one — would ungrade. The engine
				// must detect the non-finite value and fall back to the named constant instead of
				// clamping it.
				const nanThreshold = {
					...DEFAULT_SCORING_CONFIG,
					thresholds: { ...DEFAULT_SCORING_CONFIG.thresholds, evidenceSufficiency: NaN },
				};
				const score = computeScanScore(scan(19), undefined, nanThreshold);
				expect(score.overall).not.toBeNull();
				expect(score.grade).not.toBeNull();
				expect(score.evidenceInsufficient).toBeUndefined();
			});

			it('ungrades the empty result set — zero submitted evidence yields no grade (DD1 as overridden)', () => {
				const score = computeScanScore([]);
				expect(score.overall).toBeNull();
				expect(score.grade).toBeNull();
				expect(score.evidenceInsufficient).toBe(true);
				expect(score.evidence).toEqual({ attempted: 0, completed: 0, ratio: 0 });
			});

			it('ungrades the empty result set even with an evidenceSufficiency:0 config (empty-branch is deliberately stricter than the predicate)', () => {
				// isEvidenceSufficient({ratio:0}, 0) evaluates `0 >= 0` = true — the predicate
				// alone would call zero evidence "sufficient" at a zero threshold. The empty-
				// results branch in computeScanScore does NOT delegate to isEvidenceSufficient
				// for this reason: it returns null/null/evidenceInsufficient UNCONDITIONALLY,
				// regardless of what threshold a hand-built or vendored config supplies. This
				// pins that choice so a future "cleanup" that refactors the empty branch into
				// `if (!isEvidenceSufficient(evidence, evidenceThreshold)) { ... }` (removing
				// the special case as apparently-redundant) goes RED instead of silently
				// re-opening the zero-evidence-grade defect this whole gate exists to close.
				const zeroThreshold = { ...DEFAULT_SCORING_CONFIG, thresholds: { ...DEFAULT_SCORING_CONFIG.thresholds, evidenceSufficiency: 0 } };
				const score = computeScanScore([], undefined, zeroThreshold);
				expect(score.overall).toBeNull();
				expect(score.grade).toBeNull();
				expect(score.evidenceInsufficient).toBe(true);
			});
		});
	});

	describe('scoring v2 three-tier', () => {
		describe('confidence gate', () => {
			it('does not zero category for heuristic high findings', () => {
				const findings = [
					createFinding('dkim', 'No DKIM records found among tested selectors', 'high', 'No DKIM records were found', {
						confidence: 'heuristic',
					}),
				];
				const dkimResult = buildCheckResult('dkim', findings);
				const score = computeScanScore([dkimResult]);
				// DKIM contributes its computed score (75), not zeroed
				expect(score.categoryScores.dkim).toBe(75);
			});

			it('zeros category for deterministic high findings', () => {
				const findings = [
					createFinding('spf', 'No SPF record found', 'high', 'No SPF record found for example.com', { confidence: 'deterministic' }),
				];
				const spfResult = buildCheckResult('spf', findings);
				const score = computeScanScore([spfResult]);
				// SPF should be zeroed — triggers critical gap ceiling (64)
				expect(score.overall).toBeLessThanOrEqual(64);
			});
		});

		describe('three-tier formula', () => {
			it('perfect core + default protective yields ~95 with email bonus', () => {
				const results = (['spf', 'dmarc', 'dkim', 'dnssec', 'ssl'] as const).map((cat) =>
					buildCheckResult(cat, [createFinding(cat, `${cat} configured`, 'info', 'All good')]),
				);
				const score = computeScanScore(results);
				// Core=70 (all 100%), Protective=20 (all absent → 100%), Hardening=0 (no results)
				// Email bonus: SPF strong + DKIM present + DMARC present → +5 (emailBonusFull)
				// Total: 70 + 20 + 0 + 5 = 95
				expect(score.overall).toBe(95);
			});

			it('hardening categories can only add points', () => {
				const coreResults = (['spf', 'dmarc', 'dkim', 'dnssec', 'ssl'] as const).map((cat) =>
					buildCheckResult(cat, [createFinding(cat, `${cat} ok`, 'info', 'fine')]),
				);
				const scoreWithout = computeScanScore(coreResults);
				const hardeningFail = buildCheckResult('dane', [createFinding('dane', 'No DANE', 'high', 'No TLSA records found')]);
				const scoreWith = computeScanScore([...coreResults, hardeningFail]);
				// Failed hardening contributes 0 points (score < 50) but never subtracts
				expect(scoreWith.overall).toBeGreaterThanOrEqual(scoreWithout.overall);
			});

			it('hardening pass adds bonus points', () => {
				const coreResults = (['spf', 'dmarc', 'dkim', 'dnssec', 'ssl'] as const).map((cat) =>
					buildCheckResult(cat, [createFinding(cat, `${cat} ok`, 'info', 'fine')]),
				);
				const scoreWithout = computeScanScore(coreResults);
				const hardeningPass = buildCheckResult('bimi', [createFinding('bimi', 'BIMI record configured', 'info', 'BIMI configured')]);
				const scoreWith = computeScanScore([...coreResults, hardeningPass]);
				expect(scoreWith.overall).toBeGreaterThan(scoreWithout.overall);
			});

			it('new grade boundaries apply', () => {
				expect(scoreToGrade(92)).toBe('A+');
				expect(scoreToGrade(91)).toBe('A');
				expect(scoreToGrade(87)).toBe('A');
				expect(scoreToGrade(86)).toBe('B+');
				expect(scoreToGrade(76)).toBe('B');
				expect(scoreToGrade(75)).toBe('C+');
				expect(scoreToGrade(52)).toBe('D');
				expect(scoreToGrade(49)).toBe('F');
			});

			it('E grade no longer exists', () => {
				// Scores 50-54 should be D, not E
				expect(scoreToGrade(50)).toBe('D');
				expect(scoreToGrade(54)).toBe('D');
			});
		});

		describe('transient check failures are excluded from scoring, not zeroed', () => {
			const passingCore = (): CheckResult[] => [
				{ ...buildCheckResult('spf', []), score: 100, passed: true },
				{ ...buildCheckResult('dmarc', []), score: 100, passed: true },
				{ ...buildCheckResult('dkim', []), score: 100, passed: true },
				{ ...buildCheckResult('dnssec', []), score: 100, passed: true },
				{ ...buildCheckResult('ssl', []), score: 100, passed: true },
			];

			it('a transient http_security failure (checkStatus=timeout) does NOT lower the overall', () => {
				const baseline = computeScanScore(passingCore());
				const httpTimeout: CheckResult = { ...buildCheckResult('http_security', []), score: 0, passed: false, checkStatus: 'timeout' };
				const withTransient = computeScanScore([...passingCore(), httpTimeout]);
				// Excluded & renormalized → identical to the baseline, NOT dragged toward 0.
				expect(withTransient.overall).toBe(baseline.overall);
				expect(withTransient.categoryScores.http_security).toBeUndefined();
			});

			it('a transient failure with checkStatus=error is also excluded', () => {
				const baseline = computeScanScore(passingCore());
				const httpErr: CheckResult = { ...buildCheckResult('http_security', []), score: 0, passed: false, checkStatus: 'error' };
				expect(computeScanScore([...passingCore(), httpErr]).overall).toBe(baseline.overall);
			});

			it('a CONCLUSIVE low score (checkStatus completed) still counts against the overall', () => {
				const baseline = computeScanScore(passingCore());
				const httpBad: CheckResult = {
					...buildCheckResult('http_security', [createFinding('http_security', 'No CSP', 'medium', 'missing')]),
					score: 0,
					passed: false,
				};
				// Genuinely measured 0 (no transient status) must still drag the score down.
				expect(computeScanScore([...passingCore(), httpBad]).overall).toBeLessThan(baseline.overall);
			});
		});

		describe('an OUT-OF-UNION checkStatus (version-skewed cache re-read) is excluded exactly like timeout/error, never silently scored via the ?? 100 full-credit fallback', () => {
			// The `CheckStatus` union is closed to 'completed' | 'timeout' | 'error', but a
			// `CheckResult` re-read from an untrusted source (e.g. `JSON.parse` of a cached KV entry
			// with no Zod revalidation after a version-skewed deploy) can carry a string outside that
			// union at runtime. A denylist predicate (`!== 'timeout' && !== 'error'`) would treat that
			// value as measured; if the resulting result also lacks a real `score`, `generic.ts`'s
			// `categoryScores[key] ?? 100` fallback then scores it as if it had PASSED — the exact
			// defect this predicate closes.
			const passingCore = (): CheckResult[] => [
				{ ...buildCheckResult('spf', []), score: 100, passed: true },
				{ ...buildCheckResult('dmarc', []), score: 100, passed: true },
				{ ...buildCheckResult('dkim', []), score: 100, passed: true },
				{ ...buildCheckResult('dnssec', []), score: 100, passed: true },
				{ ...buildCheckResult('ssl', []), score: 100, passed: true },
			];
			/** A genuinely-measured, genuinely-failing protective category — the control for what a
			 * correctly-renormalized score looks like with no help from the skewed category. */
			const mtaStsFail = (): CheckResult => ({
				...buildCheckResult('mta_sts', [createFinding('mta_sts', 'No MTA-STS policy', 'medium', 'missing policy')]),
				score: 0,
				passed: false,
				checkStatus: 'completed',
			});
			/** Simulates a `CheckResult` clawed back from a stale/skewed cache entry: `checkStatus`
			 * outside the closed union, and `score` entirely absent — the worst case, with no numeric
			 * value to fall back on at all. Never constructible through the typed CheckResult surface. */
			const nsSkewed = (): CheckResult =>
				({ category: 'ns', passed: false, findings: [], checkStatus: 'pending_migration' }) as unknown as CheckResult;

			it('THE FULL-CREDIT REGRESSION TEST: does not raise the overall at all — behaves exactly as if the skewed category were never submitted (transientFailures site)', () => {
				// If the skewed category were (wrongly) treated as measured, it would enter the
				// protective weighted sum with `categoryScores.ns ?? 100` = full credit, pulling the
				// overall ABOVE this control value — the opposite of what "we couldn't measure it"
				// should ever do to a score.
				const withoutSkewed = computeScanScore([...passingCore(), mtaStsFail()]);
				const withSkewed = computeScanScore([...passingCore(), mtaStsFail(), nsSkewed()]);
				expect(withSkewed.overall).toBe(withoutSkewed.overall);
			});

			it('never lists the skewed category in categoryScores at all — not even as an explicit `undefined` (categoryScores population site)', () => {
				// Object.keys still picks up a key that was assigned `undefined` (as a denylist-form
				// population loop would do here, since `result.score` is itself absent), so this is a
				// distinct assertion from the overall-score equality above — it pins the population
				// loop itself, independent of whether the weighted-sum exclusion is correct.
				const scan = computeScanScore([...passingCore(), mtaStsFail(), nsSkewed()]);
				expect(Object.keys(scan.categoryScores).sort()).toEqual(['dkim', 'dmarc', 'dnssec', 'mta_sts', 'spf', 'ssl']);
			});
		});

		describe('never-run categories are excluded, not scored 100', () => {
			// scan_domain runs a FIXED roster that excludes some scored categories entirely —
			// notably `lookalikes` and `shadow_domains` (protective weight 2 each), which are
			// surfaced only by the dedicated deep-scan tools. Historically the engine seeded
			// EVERY category to 100, so a never-run category surfaced as a perfect 100 in
			// categoryScores AND was silently awarded full protective weight — masking the real
			// brand-abuse findings the dedicated tools return. A never-run scored category must
			// be treated like an inconclusive one: absent from categoryScores and excluded from
			// the weighted tier (renormalized), never a phantom 100.
			const passingCore = (): CheckResult[] => [
				{ ...buildCheckResult('spf', []), score: 100, passed: true },
				{ ...buildCheckResult('dmarc', []), score: 100, passed: true },
				{ ...buildCheckResult('dkim', []), score: 100, passed: true },
				{ ...buildCheckResult('dnssec', []), score: 100, passed: true },
				{ ...buildCheckResult('ssl', []), score: 100, passed: true },
			];
			const takeoverFail = (): CheckResult => ({
				...buildCheckResult('subdomain_takeover', [createFinding('subdomain_takeover', 'Dangling delegation', 'high', 'takeover risk')]),
				score: 0,
				passed: false,
			});

			it('a never-run scored category is absent from categoryScores (never a phantom 100)', () => {
				const scan = computeScanScore([...passingCore(), takeoverFail()]);
				expect(scan.categoryScores.lookalikes).toBeUndefined();
				expect(scan.categoryScores.shadow_domains).toBeUndefined();
				// Only categories that actually produced a result appear — categoryScores can never
				// list a category with no corresponding checkStatus.
				expect(Object.keys(scan.categoryScores).sort()).toEqual(['dkim', 'dmarc', 'dnssec', 'spf', 'ssl', 'subdomain_takeover']);
			});

			it('a never-run protective category does NOT inflate the overall (excluded + renormalized)', () => {
				const measured = [...passingCore(), takeoverFail()];
				const excluded = computeScanScore(measured).overall;
				// Actually MEASURING lookalikes+shadow_domains as perfect can only hold or raise the
				// overall — never lower it. Pre-fix the two un-run categories were auto-padded to 100,
				// making these identical; that padding IS the masking bug, so the fixed engine must
				// score the excluded case strictly lower when a real protective failure is present.
				const withPerfectExtras = computeScanScore([
					...measured,
					{ ...buildCheckResult('lookalikes', []), score: 100, passed: true },
					{ ...buildCheckResult('shadow_domains', []), score: 100, passed: true },
				]).overall;
				expect(excluded).toBeLessThan(withPerfectExtras);
			});
		});
	});
}
