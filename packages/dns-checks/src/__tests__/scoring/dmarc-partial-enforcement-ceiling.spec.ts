// SPDX-License-Identifier: BUSL-1.1

/**
 * Scoring model 1.26.0 — DMARC partial enforcement caps the top letter.
 *
 * THE DECISION THIS FILE PINS.
 * Measured 2026-09-10 on the 1.25.0 package (mail_enabled, every other check perfect):
 * absent 64 · p=none 64 · quarantine 100 · reject 100 · reject+strict 100. Quarantine
 * and reject were score-IDENTICAL, so the model offered no gradient toward the
 * mandated end state (NZ SGE Oct 2026, US BOD 18-01, BSI TR-03182 all name p=reject).
 * Two things now move, both structurally declared and both DOWNWARD only:
 *
 *   1. `DMARC policy set to quarantine` is `medium` (was `low`) and carries
 *      `metadata.partialEnforcement: true`; `DMARC not applied to all emails` (pct<100)
 *      keeps `medium` and gains the same declaration. The category now sits BELOW reject.
 *   2. The generic engine caps a scan at `partialEnforcementCeiling` (94 — the top of
 *      NIST display A) when a CRITICAL category is partially enforced and not already a
 *      critical gap. dmarc is critical in `mail_enabled` / `enterprise_mail` ONLY, so the
 *      gate reaches no other profile by construction.
 *
 * The ordering this preserves: none/absent (64, D) < partial enforcement (≤94, A) <
 * full reject (100, A+). The operator's "cannot pass D without p=reject" cap was
 * adjudicated AGAINST (0 of 12 surveyed peer graders cap a composite on quarantine; it
 * would flatten quarantine into the no-record bucket), and this file guards that
 * boundary too: quarantine must never score like p=none.
 *
 * WHAT IS DELIBERATELY NOT CHANGED.
 * The finding TITLES are load-bearing downstream (`assess_spoofability` derives posture
 * from them; `generate_rollout_plan` / maturity staging match by substring) and stay
 * exactly as they were. `sp=` / `t=y` semantics are settled DEFERs. The engine's INTERNAL
 * 9-band `grade` still reads A+ at 94 — the customer-visible NIST letter is what moves.
 *
 * WHY THESE TESTS RUN THE REAL CHECK.
 * `checkDMARC` (record → classifier → `buildCheckResult`) is what both repos consume, so
 * the declaration is proven end-to-end through `computeProfileAwareScanScore`, not on a
 * hand-built finding. The one synthetic finding here (the PROSE CONTROL) exists to prove
 * the opposite: prose alone must NOT arm the ceiling.
 */

import { describe, expect, it } from 'vitest';
import { checkDMARC } from '../../checks/check-dmarc';
import { buildCheckResult, computeProfileAwareScanScore, createFinding, DEFAULT_SCORING_CONFIG } from '../../scoring';
import { classifyDmarc } from '../../scoring/classifiers/dmarc';
import { findingsIndicatePartialEnforcement } from '../../scoring/model';
import { nistScoreToGrade } from '../../scoring/engine';
import type { DomainProfile, ScoringConfig } from '../../scoring';
import type { CheckCategory, CheckResult, DNSQueryFunction } from '../../types';

const DOMAIN = 'victim.example';
const DMARC_NAME = `_dmarc.${DOMAIN}`;

function ok(category: CheckCategory): CheckResult {
	return buildCheckResult(category, [createFinding(category, `${category} OK`, 'info', 'Check passed')], true);
}

const NON_DMARC_CATEGORIES: CheckCategory[] = [
	'spf',
	'dkim',
	'dnssec',
	'ssl',
	'mta_sts',
	'caa',
	'bimi',
	'tlsrpt',
	'subdomain_takeover',
	'mx',
	'ns',
	'txt_hygiene',
	'http_security',
	'dane',
	'mx_reputation',
	'srv',
	'zone_hygiene',
	'dane_https',
	'svcb_https',
];

/** An otherwise-clean roster with the given dmarc result. */
function rosterWithDmarc(dmarcResult: CheckResult): CheckResult[] {
	return [...NON_DMARC_CATEGORIES.map(ok), dmarcResult];
}

function mockDNS(record: string | null): DNSQueryFunction {
	return async (name, type) => (type === 'TXT' && name === DMARC_NAME && record !== null ? [record] : []);
}

/** The REAL check: DNS → tree-walk → classifier → buildCheckResult. */
async function realDmarc(record: string | null): Promise<CheckResult> {
	return checkDMARC(DOMAIN, mockDNS(record));
}

async function scoreWith(record: string | null, profile: DomainProfile, config?: ScoringConfig) {
	const dmarc = await realDmarc(record);
	const { score } = computeProfileAwareScanScore(rosterWithDmarc(dmarc), { profile, config });
	if (score.overall === null) throw new Error(`fixture ungraded: ${score.summary}`);
	return { score, overall: score.overall, dmarc };
}

const QUARANTINE = 'v=DMARC1; p=quarantine; rua=mailto:d@victim.example';
const REJECT = 'v=DMARC1; p=reject; rua=mailto:d@victim.example';
const REJECT_PCT50 = 'v=DMARC1; p=reject; pct=50; rua=mailto:d@victim.example';
const P_NONE = 'v=DMARC1; p=none; rua=mailto:d@victim.example';

const CEILING = DEFAULT_SCORING_CONFIG.thresholds.partialEnforcementCeiling;

describe('classifier: the partial-enforcement declaration is structural', () => {
	it('quarantine is medium and declares partialEnforcement, keeps its title, and is NOT a missing control', () => {
		const findings = classifyDmarc({ recordCount: 1, policy: 'quarantine', domain: DOMAIN, rua: 'mailto:d@victim.example' });
		const quarantine = findings.find((f) => f.title === 'DMARC policy set to quarantine');
		expect(quarantine).toBeDefined();
		expect(quarantine?.severity).toBe('medium');
		expect(quarantine?.metadata?.partialEnforcement).toBe(true);
		expect(quarantine?.metadata?.missingControl).toBeUndefined();
	});

	it('pct<100 keeps medium and declares partialEnforcement whatever p= says', () => {
		const findings = classifyDmarc({ recordCount: 1, policy: 'reject', domain: DOMAIN, pct: '50', rua: 'mailto:d@victim.example' });
		const pct = findings.find((f) => f.title === 'DMARC not applied to all emails');
		expect(pct?.severity).toBe('medium');
		expect(pct?.metadata?.partialEnforcement).toBe(true);
	});

	it('the quarantine detail stays clear of every MISSING_CONTROL_REGEX trigger word', () => {
		const findings = classifyDmarc({ recordCount: 1, policy: 'quarantine', domain: DOMAIN });
		const quarantine = findings.find((f) => f.title === 'DMARC policy set to quarantine');
		expect(quarantine?.detail).not.toMatch(/(no\s+[^\r\n]{1,64}\srecord|missing|required|not\s+found)/i);
	});

	it('findingsIndicatePartialEnforcement ignores a finding that is also a missing control', () => {
		const both = createFinding('dmarc', 'x', 'high', 'y', { partialEnforcement: true, missingControl: true });
		expect(findingsIndicatePartialEnforcement([both])).toBe(false);
		const partialOnly = createFinding('dmarc', 'x', 'medium', 'y', { partialEnforcement: true });
		expect(findingsIndicatePartialEnforcement([partialOnly])).toBe(true);
	});
});

describe('mail_enabled: partial enforcement caps the top letter at 94 (NIST A, never A+)', () => {
	it('1. p=quarantine + rua on an otherwise-perfect roster → exactly 94, partialEnforcementGaps [dmarc], criticalGaps []', async () => {
		const { score, overall } = await scoreWith(QUARANTINE, 'mail_enabled');
		expect(overall).toBe(94);
		expect(score.partialEnforcementGaps).toEqual(['dmarc']);
		expect(score.criticalGaps).toEqual([]);
		expect(nistScoreToGrade(overall)).toBe('A');
	});

	it('2. POSITIVE CONTROL — p=reject + rua on the same roster → 100 with no gaps (the gate is off)', async () => {
		const { score, overall } = await scoreWith(REJECT, 'mail_enabled');
		expect(overall).toBe(100);
		expect(score.partialEnforcementGaps).toEqual([]);
		expect(score.criticalGaps).toEqual([]);
		expect(nistScoreToGrade(overall)).toBe('A+');
	});

	it('3. p=reject; pct=50 + rua → capped at ≤94 with gaps [dmarc] (a staged pct is not full reject)', async () => {
		const { score, overall } = await scoreWith(REJECT_PCT50, 'mail_enabled');
		expect(overall).toBeLessThanOrEqual(94);
		expect(score.partialEnforcementGaps).toEqual(['dmarc']);
		expect(score.criticalGaps).toEqual([]);
	});

	it('4. p=none + rua → 64: missing beats partial, and partialEnforcementGaps stays empty', async () => {
		const { score, overall } = await scoreWith(P_NONE, 'mail_enabled');
		expect(overall).toBe(DEFAULT_SCORING_CONFIG.thresholds.criticalGapCeiling);
		expect(overall).toBe(64);
		expect(score.criticalGaps).toEqual(['dmarc']);
		expect(score.partialEnforcementGaps).toEqual([]);
	});

	it('preserves the ordering none/absent (64) < partial (≤94) < full reject (100)', async () => {
		const none = (await scoreWith(P_NONE, 'mail_enabled')).overall;
		const absent = (await scoreWith(null, 'mail_enabled')).overall;
		const quarantine = (await scoreWith(QUARANTINE, 'mail_enabled')).overall;
		const staged = (await scoreWith(REJECT_PCT50, 'mail_enabled')).overall;
		const reject = (await scoreWith(REJECT, 'mail_enabled')).overall;
		expect(none).toBe(absent);
		expect(none).toBeLessThan(quarantine);
		expect(none).toBeLessThan(staged);
		expect(quarantine).toBeLessThanOrEqual(CEILING);
		expect(staged).toBeLessThanOrEqual(CEILING);
		expect(quarantine).toBeLessThan(reject);
		expect(staged).toBeLessThan(reject);
	});

	it('the gradient exists at the CATEGORY level too: quarantine scores below reject before any ceiling', async () => {
		const quarantine = await realDmarc(QUARANTINE);
		const reject = await realDmarc(REJECT);
		expect(quarantine.score).toBeLessThan(reject.score);
		expect(quarantine.passed).toBe(true);
	});
});

describe('5. profile boundary: critical-category keyed, so only the mail profiles are capped', () => {
	it('enterprise_mail + quarantine → capped', async () => {
		const { score, overall } = await scoreWith(QUARANTINE, 'enterprise_mail');
		expect(overall).toBeLessThanOrEqual(94);
		expect(score.partialEnforcementGaps).toEqual(['dmarc']);
	});

	it('web_only + quarantine → NOT capped (dmarc weight 3, not critical)', async () => {
		const { score } = await scoreWith(QUARANTINE, 'web_only');
		expect(score.partialEnforcementGaps).toEqual([]);
		expect(score.criticalGaps).toEqual([]);
	});

	it('non_mail + quarantine → NOT capped (dmarc weighted but not critical)', async () => {
		const { score } = await scoreWith(QUARANTINE, 'non_mail');
		expect(score.partialEnforcementGaps).toEqual([]);
		expect(score.criticalGaps).toEqual([]);
	});
});

describe('6. measurement gate: an unmeasured dmarc check cannot arm the ceiling', () => {
	it('checkStatus: timeout carrying the real quarantine finding → no cap, no gap', async () => {
		const measured = await realDmarc(QUARANTINE);
		const timedOut: CheckResult = { ...measured, score: 0, passed: false, checkStatus: 'timeout' };
		const { score } = computeProfileAwareScanScore(rosterWithDmarc(timedOut), { profile: 'mail_enabled' });
		expect(score.overall).not.toBeNull();
		expect(score.partialEnforcementGaps).toEqual([]);
		expect(score.criticalGaps).toEqual([]);
		// Excluded and renormalized — the remaining roster is perfect.
		expect(score.overall).toBeGreaterThan(94);
		expect(score.categoryScores.dmarc).toBeUndefined();
	});
});

describe('7. PROSE CONTROL: the ceiling is structural-only', () => {
	it('a dmarc finding whose detail reads "partial enforcement via quarantine" with NO metadata → no cap', () => {
		const prose = buildCheckResult(
			'dmarc',
			[createFinding('dmarc', 'DMARC policy set to quarantine', 'medium', 'DMARC provides partial enforcement via quarantine on this domain.')],
			true,
			true,
		);
		expect(findingsIndicatePartialEnforcement(prose.findings)).toBe(false);
		const { score } = computeProfileAwareScanScore(rosterWithDmarc(prose), { profile: 'mail_enabled' });
		expect(score.partialEnforcementGaps).toEqual([]);
		// The medium finding still costs its −15 on the category; only the CEILING is absent.
		expect(score.overall).toBeGreaterThan(94);
	});
});

describe('8. config: the ceiling is a threshold like criticalGapCeiling', () => {
	it('thresholds.partialEnforcementCeiling: 89 → overall 89 on the quarantine roster', async () => {
		const config: ScoringConfig = {
			...DEFAULT_SCORING_CONFIG,
			thresholds: { ...DEFAULT_SCORING_CONFIG.thresholds, partialEnforcementCeiling: 89 },
		};
		const { score, overall } = await scoreWith(QUARANTINE, 'mail_enabled', config);
		expect(overall).toBe(89);
		expect(score.partialEnforcementGaps).toEqual(['dmarc']);
	});

	it('a hand-built config that PREDATES the key falls back to the default 94 rather than disabling the ceiling', async () => {
		const { partialEnforcementCeiling: _dropped, ...legacyThresholds } = DEFAULT_SCORING_CONFIG.thresholds;
		const legacy = { ...DEFAULT_SCORING_CONFIG, thresholds: legacyThresholds } as unknown as ScoringConfig;
		const { overall } = await scoreWith(QUARANTINE, 'mail_enabled', legacy);
		expect(overall).toBe(94);
	});
});
