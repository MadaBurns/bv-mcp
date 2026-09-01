// SPDX-License-Identifier: BUSL-1.1

/**
 * Scoring model 1.20.0 — `web_only` weights the non-sender lockdown (Option B,
 * ratified 2026-09-02).
 *
 * THE DECISION THIS FILE PINS.
 * A non-sending domain is a prime impersonation target, and the correct posture is
 * the published lockdown: `v=spf1 -all` (NIST SP 800-177r1 §4.4.2), an enforcing
 * DMARC policy, and a null MX (RFC 7505). The per-check rubric for that posture has
 * existed for a long time — check-mx scores no-MX+no-SPF as spoofable with
 * `{ missingControl: true }` (→ 0) and no-MX+`-all` as "Correctly-configured
 * non-mail domain"; the dmarc classifier scores reject/quarantine/none correctly —
 * but `web_only` multiplied all of it by an importance of ZERO, so a fully
 * spoofable unconfigured domain and a locked-down one scored identically
 * (measured 2026-09-02: fundhaus.app, no SPF record + plain no-MX, rendered 82/B).
 *
 * The change: `web_only` adopts the same small identity weights `non_mail` has
 * always carried — spf 2, dmarc 3, mx 1 — so the existing rubric flows into the
 * score, bounded to single-digit points by the tier normalizer.
 *
 * WHAT IS DELIBERATELY NOT CHANGED.
 *   - NO critical-gap ceiling: spf/dmarc stay OUT of `web_only`'s critical set
 *     (twin-settled 2026-09-01; measured 2026-09-02: 93.1% of the no-MX corpus
 *     cohort — 55% of the whole corpus — lacks every lockdown record, so a
 *     p=none-style hard cap here would re-grade half the index in one release).
 *     Movement flows through weights only.
 *   - dkim stays 0 in `web_only`: a non-sender cannot earn sender DKIM marks, and
 *     the NZ SGE blank-key wildcard variant was examined and not adopted
 *     (2026-09-01 research spec §Option B).
 *   - Mail profiles and `non_mail` weights are untouched.
 */

import { describe, expect, it } from 'vitest';
import { buildCheckResult, computeScanScore, createFinding, getProfileWeights } from '../../scoring';
import type { DomainContext } from '../../scoring';
import type { CheckCategory, CheckResult, Finding } from '../../types';

function ok(category: CheckCategory): CheckResult {
	return buildCheckResult(category, [createFinding(category, `${category} OK`, 'info', 'Check passed')], true);
}

function zeroed(category: CheckCategory, title: string, detail: string): CheckResult {
	const finding: Finding = createFinding(category, title, 'medium', detail, { missingControl: true });
	return buildCheckResult(category, [finding], false);
}

const OTHER_CATEGORIES: CheckCategory[] = [
	'dkim',
	'dnssec',
	'ssl',
	'mta_sts',
	'caa',
	'bimi',
	'tlsrpt',
	'subdomain_takeover',
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

/** A non-sender that published the full lockdown: -all SPF, enforcing DMARC, null MX. */
function lockedDownRoster(): CheckResult[] {
	return [
		...OTHER_CATEGORIES.map(ok),
		buildCheckResult('spf', [createFinding('spf', 'SPF hard-fail lockdown', 'info', 'v=spf1 -all')], true),
		buildCheckResult('dmarc', [createFinding('dmarc', 'DMARC policy enforcing', 'info', 'p=reject')], true),
		buildCheckResult('mx', [createFinding('mx', 'Null MX published', 'info', 'RFC 7505 null MX declares the domain non-receiving')], false),
	];
}

/** The fundhaus class: no SPF record, no DMARC enforcement, plain no-MX — fully spoofable. */
function unlockedRoster(): CheckResult[] {
	return [
		...OTHER_CATEGORIES.map(ok),
		zeroed('spf', 'No SPF record', 'The domain publishes no SPF policy; any server may claim to send as it.'),
		zeroed('dmarc', 'DMARC record not found', 'No DMARC policy is published.'),
		zeroed('mx', 'No MX and no SPF — domain spoofable', 'No mail exchange records and no SPF policy.'),
	];
}

function contextFor(profile: DomainContext['profile']): DomainContext {
	return {
		profile,
		signals: ['test fixture'],
		weights: getProfileWeights(profile),
		detectedProvider: null,
	};
}

describe('web_only identity weights (scoring model 1.20.0)', () => {
	it('adopts the non_mail identity weights: spf 2, dmarc 3, mx 1', () => {
		const w = getProfileWeights('web_only');
		expect(w.spf.importance).toBe(2);
		expect(w.dmarc.importance).toBe(3);
		expect(w.mx.importance).toBe(1);
	});

	it('deliberately keeps dkim at 0 (a non-sender cannot earn sender DKIM marks)', () => {
		expect(getProfileWeights('web_only').dkim.importance).toBe(0);
	});

	it('leaves every other profile identity weight untouched', () => {
		expect(getProfileWeights('mail_enabled').spf.importance).toBe(10);
		expect(getProfileWeights('mail_enabled').dmarc.importance).toBe(16);
		expect(getProfileWeights('non_mail').spf.importance).toBe(2);
		expect(getProfileWeights('non_mail').dmarc.importance).toBe(3);
		expect(getProfileWeights('non_mail').mx.importance).toBe(1);
	});
});

describe('web_only discriminates locked-down from spoofable non-senders', () => {
	it('scores the lockdown strictly above the unconfigured domain', () => {
		const locked = computeScanScore(lockedDownRoster(), contextFor('web_only'));
		const unlocked = computeScanScore(unlockedRoster(), contextFor('web_only'));
		expect(locked.overall).not.toBeNull();
		expect(unlocked.overall).not.toBeNull();
		expect(locked.overall!).toBeGreaterThanOrEqual(unlocked.overall! + 8);
	});

	it('pins the exact contract values: lockdown 100, spoofable 89 on the synthetic rosters', () => {
		// The unlocked roster is otherwise PERFECT — real spoofable non-senders carry
		// other flaws and land lower (fundhaus.app, 82/B pre-model, ≈ mid-70s / NIST C
		// post-model). The 11-point spread is the ratified weights-only movement:
		// spf+dmarc = 5/33 of the 70-point core tier, mx = 1/28 of protective.
		const locked = computeScanScore(lockedDownRoster(), contextFor('web_only'));
		const unlocked = computeScanScore(unlockedRoster(), contextFor('web_only'));
		expect(locked.overall).toBe(100);
		expect(unlocked.overall).toBe(89);
	});

	it('keeps a fully locked-down non-sender in the top band (the lockdown is rewarded, not just the gap punished)', () => {
		const locked = computeScanScore(lockedDownRoster(), contextFor('web_only'));
		expect(locked.overall!).toBeGreaterThanOrEqual(90);
	});
});

describe('the movement is weights-only — no ceiling leaks into web_only', () => {
	it('a fully spoofable non-sender is NOT capped at 64 (55% of the corpus; a hard cap is a separate, unratified decision)', () => {
		const unlocked = computeScanScore(unlockedRoster(), contextFor('web_only'));
		expect(unlocked.overall!).toBeGreaterThan(64);
	});

	it('mail_enabled scoring of the same rosters is unchanged by this model revision (identity weights already non-zero there)', () => {
		const locked = computeScanScore(lockedDownRoster(), contextFor('mail_enabled'));
		const unlocked = computeScanScore(unlockedRoster(), contextFor('mail_enabled'));
		expect(locked.overall!).toBeGreaterThan(unlocked.overall!);
	});
});
