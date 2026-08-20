// SPDX-License-Identifier: BUSL-1.1

/**
 * Scoring side of the partial lame-delegation CRITICAL escalation.
 *
 * THE TRAP THIS FILE PINS.
 * `critical` is not, by itself, a scoring lever. `scoring/engine.ts` builds
 * `findingSeverityCounts.critical` from `verifiedCriticalCount` — findings that are
 * BOTH `severity === 'critical'` AND `inferFindingConfidence(f) === 'verified'` — and
 * `verified` is only ever returned from an explicit `metadata.confidence` (or the
 * `subdomain_takeover` + `verificationStatus` special case). So an escalation that
 * bumps severity WITHOUT stamping confidence moves the overall score by exactly zero,
 * and looks like it worked because the finding renders red.
 *
 * WHAT IS DELIBERATELY NOT ASSERTED HERE.
 * The −15 `criticalOverallPenalty` and the 64 `criticalGapCeiling` are DECOUPLED. The
 * penalty reads the verified-critical count; the ceiling reads only
 * `criticalCategories ∩ missingControls`. Lame delegation is not a missing control —
 * the domain HAS NS records, some of them are dead — and the finding sets no
 * `missingControl`, so the ceiling is structurally unreachable for it. There is
 * therefore NO `overall <= 64` assertion anywhere in this file, and adding `ns` to
 * `PROFILE_CRITICAL_CATEGORIES` to try to make the ceiling fire is a separate product
 * decision, not this change.
 */

import { describe, expect, it } from 'vitest';
import {
	PROFILE_WEIGHTS,
	buildCheckResult,
	computeScanScore,
	createFinding,
	getProfileWeights,
	inferFindingConfidence,
} from '../../scoring';
import { assessLameDelegation, getPartialLameDelegationFinding } from '../../checks/ns-analysis';
import type { CheckCategory, CheckResult, DomainContext, Finding } from '../../types';

/** The engine's own predicate, restated so the test measures the MECHANISM, not a threshold. */
function verifiedCriticalCount(findings: Finding[]): number {
	return findings.filter((f) => f.severity === 'critical' && inferFindingConfidence(f) === 'verified').length;
}

function ok(category: CheckCategory): CheckResult {
	return buildCheckResult(category, [createFinding(category, `${category} OK`, 'info', 'Check passed')], true);
}

/**
 * A mail-profile roster that is NOT clamped at 100.
 *
 * `dmarc` is deliberately degraded below a perfect score. A mail profile is
 * email-bonus eligible, and on an otherwise-perfect roster the bonus pushes the
 * pre-ceiling score to the 100 clamp — where a −15 penalty is absorbed silently and
 * every delta reads as zero. An earlier version of this test measured exactly that
 * and reported "the escalation has no effect".
 */
function mailRoster(nsFinding: Finding | null): CheckResult[] {
	const categories: CheckCategory[] = [
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
		'txt_hygiene',
		'http_security',
		'dane',
		'mx_reputation',
		'srv',
		'zone_hygiene',
		'dane_https',
		'svcb_https',
	];
	const results = categories.map(ok);
	results.push(
		buildCheckResult('dmarc', [createFinding('dmarc', 'DMARC policy is p=none', 'high', 'Monitoring only, no enforcement.')], true),
	);
	results.push(
		nsFinding === null
			? ok('ns')
			: buildCheckResult('ns', [nsFinding, createFinding('ns', 'Nameservers published', 'info', 'NS RRset present.')], true),
	);
	return results;
}

function mailContext(): DomainContext {
	return {
		profile: 'mail_enabled',
		signals: ['MX present'],
		weights: getProfileWeights('mail_enabled'),
		detectedProvider: null,
	};
}

const assessment = assessLameDelegation([
	{ nameserver: 'ns1.healthy.example', outcome: 'resolves', hostNxdomain: false },
	{ nameserver: 'ns2.abandoned.example', outcome: 'no_address', hostNxdomain: true },
]);

// ---------------------------------------------------------------------------
// C1 — CHARACTERIZATION TEST. Passes on arrival BY DESIGN.
// ---------------------------------------------------------------------------

describe('CHARACTERIZATION: severity alone is not a scoring lever', () => {
	it('a critical but UNSTAMPED ns finding contributes ZERO to the verified-critical count', () => {
		// Pinned by MECHANISM, not by an absolute `overall`: the count is immune to fixture
		// drift on unrelated categories, whereas a pinned score is not. This is the exact
		// reason the escalation needs a confidence stamp to register at all.
		const unstamped = createFinding(
			'ns',
			'Lame delegation — nameserver does not answer for the zone',
			'critical',
			'The parent zone delegates victim.example to ns2.abandoned.example, which has no address.',
		);
		expect(unstamped.metadata?.confidence).toBeUndefined();
		expect(inferFindingConfidence(unstamped)).toBe('deterministic');

		const score = computeScanScore(mailRoster(unstamped), mailContext());
		expect(score.findings.some((f) => f.severity === 'critical')).toBe(true);
		expect(verifiedCriticalCount(score.findings)).toBe(0);
	});
});

// ---------------------------------------------------------------------------
// C2 — the intended behavior, on an UNCLAMPED fixture.
// ---------------------------------------------------------------------------

describe('the −15 critical penalty', () => {
	it('applies the −15 critical penalty when the lame-delegation finding is verified-claimable', () => {
		// The two rosters differ ONLY in whether claimability was SHOWN. Severity is
		// `critical` in both, so the `ns` category score is identical in both and the whole
		// delta is attributable to the verified-critical penalty.
		const notShown = getPartialLameDelegationFinding('victim.example', assessment, []);
		const claimable = getPartialLameDelegationFinding('victim.example', assessment, ['ns2.abandoned.example']);
		expect(notShown.severity).toBe('critical');
		expect(claimable.severity).toBe('critical');

		const unstampedScore = computeScanScore(mailRoster(notShown), mailContext());
		const verifiedScore = computeScanScore(mailRoster(claimable), mailContext());

		expect(verifiedCriticalCount(unstampedScore.findings)).toBe(0);
		expect(verifiedCriticalCount(verifiedScore.findings)).toBe(1);

		// Guard the measurement itself: a fixture sitting on the 100 clamp would report a
		// zero delta no matter what the engine did. `preCeiling` is
		// clampPercent(round(base) + emailBonus − criticalPenalty), so a roster whose
		// base+bonus exceeds 115 absorbs the whole penalty silently.
		expect(unstampedScore.overall).not.toBeNull();
		expect(unstampedScore.overall!).toBeLessThan(100);

		// MEASURED on this roster: unstamped 97 (A+) → verified 82 (B+). Asserted as a
		// FLOOR, not an equality — the absolute numbers move with unrelated fixture
		// categories, the −15 mechanism does not.
		expect(unstampedScore.overall! - verifiedScore.overall!).toBeGreaterThanOrEqual(15);
	});
});

// ---------------------------------------------------------------------------
// C5 — profile-correct weighting.
// ---------------------------------------------------------------------------

describe('ns importance is per-profile, and the bump applies ONCE', () => {
	it('is 3 in the mail profiles after the escalation', () => {
		// A nameserver an attacker can claim is authoritative-control-adjacent, which is
		// the same weight class the web profiles already assign `ns`.
		expect(PROFILE_WEIGHTS.mail_enabled.ns.importance).toBe(3);
		expect(PROFILE_WEIGHTS.enterprise_mail.ns.importance).toBe(3);
	});

	it('is STILL 3 — unchanged — in web_only and non_mail', () => {
		// These two were ALREADY 3. The original proposal said a flat "2→3", which applied
		// to every profile would have double-bumped them to 4.
		expect(PROFILE_WEIGHTS.web_only.ns.importance).toBe(3);
		expect(PROFILE_WEIGHTS.non_mail.ns.importance).toBe(3);
	});

	it('leaves the two profiles this change does not speak to alone', () => {
		expect(PROFILE_WEIGHTS.minimal.ns.importance).toBe(1);
		expect(PROFILE_WEIGHTS.authoritative_dns_infra.ns.importance).toBe(15);
	});
});
