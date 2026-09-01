// SPDX-License-Identifier: BUSL-1.1

/**
 * Scoring model 1.19.0 — DMARC `p=none` is a missing enforcement control.
 *
 * THE DECISION THIS FILE PINS.
 * A published `p=none` policy instructs receivers to take NO action on messages that
 * fail authentication (RFC 9989 §5.1.4 names it Monitoring Mode). For enforcement it
 * is therefore equivalent to publishing nothing: spoofed mail is delivered either
 * way. The reference class agrees — BitSight grades `p=none` identically to no
 * record, dimension-scoped. The classifier now declares `{ missingControl: true }`
 * on the `DMARC policy set to none` finding, which:
 *
 *   - zeroes the dmarc category (`buildCheckResult` → score 0, passed false), and
 *   - arms the `criticalGapCeiling` (64 → NIST display D) in the profiles where
 *     dmarc is a critical category — `mail_enabled` / `enterprise_mail` ONLY.
 *
 * WHAT IS DELIBERATELY NOT CHANGED.
 * The finding TITLE is load-bearing downstream (the impersonation escalation and
 * `dmarcIsWeak` in scan post-processing match it exactly; `assess_spoofability`
 * derives posture from it; rollout planning matches it by substring) and stays
 * `DMARC policy set to none`. Non-mail profiles gain NO ceiling: dmarc is not in
 * their critical set, so a parked/web-only domain at p=none is NOT capped — that
 * boundary is a separate, unratified product decision (Option B of the 2026-09-01
 * research spec) and this file guards against it leaking in accidentally.
 */

import { describe, expect, it } from 'vitest';
import { buildCheckResult, computeScanScore, createFinding, getProfileWeights } from '../../scoring';
import { classifyDmarc } from '../../scoring/classifiers/dmarc';
import type { DomainContext } from '../../scoring';
import type { CheckCategory, CheckResult } from '../../types';

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

/** An otherwise-clean roster with the REAL classifier's dmarc result for the given facts. */
function rosterWithDmarc(dmarcResult: CheckResult): CheckResult[] {
	return [...NON_DMARC_CATEGORIES.map(ok), dmarcResult];
}

function contextFor(profile: DomainContext['profile']): DomainContext {
	return {
		profile,
		signals: ['test fixture'],
		weights: getProfileWeights(profile),
		detectedProvider: null,
	};
}

/** The real classifier output for a plain organizational-domain p=none record. */
function pNoneResult(): CheckResult {
	return buildCheckResult('dmarc', classifyDmarc({ recordCount: 1, policy: 'none', domain: 'victim.example' }), false, true);
}

/** The real classifier output for a domain with no DMARC record at all. */
function absentResult(): CheckResult {
	return buildCheckResult('dmarc', classifyDmarc({ recordCount: 0, policy: null, domain: 'victim.example' }), false, false);
}

describe('classifier: p=none declares the missing enforcement control', () => {
	it('emits the p=none finding at high severity with missingControl: true', () => {
		const findings = classifyDmarc({ recordCount: 1, policy: 'none', domain: 'victim.example' });
		const none = findings.find((f) => f.title === 'DMARC policy set to none');
		expect(none).toBeDefined();
		expect(none?.severity).toBe('high');
		expect(none?.metadata?.missingControl).toBe(true);
	});

	it('keeps the declaration and severity on the parent-enforcing asymmetry variant, without renaming the title', () => {
		const findings = classifyDmarc({
			recordCount: 1,
			policy: 'none',
			domain: 'billing.example.com',
			inheritedFromParent: true,
			orgPolicy: 'reject',
			orgDomain: 'example.com',
		});
		const none = findings.find((f) => f.title === 'DMARC policy set to none');
		expect(none).toBeDefined();
		expect(none?.severity).toBe('high');
		expect(none?.metadata?.missingControl).toBe(true);
		expect(none?.detail).toMatch(/asymmetric/i);
	});

	it('does NOT extend the declaration to quarantine (discrimination control)', () => {
		const findings = classifyDmarc({ recordCount: 1, policy: 'quarantine', domain: 'victim.example', rua: 'mailto:d@victim.example' });
		const quarantine = findings.find((f) => f.title === 'DMARC policy set to quarantine');
		expect(quarantine?.severity).toBe('low');
		expect(quarantine?.metadata?.missingControl).toBeUndefined();
	});
});

describe('check result: p=none zeroes the dmarc category', () => {
	it('scores 0 and fails, exactly like the absent-record case', () => {
		const pNone = pNoneResult();
		const absent = absentResult();
		expect(pNone.score).toBe(0);
		expect(pNone.passed).toBe(false);
		expect(absent.score).toBe(0);
		expect(absent.passed).toBe(false);
	});

	it('keeps the observational pair intact: record published, control not active', () => {
		const pNone = pNoneResult();
		expect(pNone.recordPresent).toBe(true);
		expect(pNone.controlPresent).toBe(false);
	});
});

describe('mail profiles: p=none arms the critical-gap ceiling', () => {
	it('caps an otherwise-clean mail_enabled domain at 64', () => {
		const score = computeScanScore(rosterWithDmarc(pNoneResult()), contextFor('mail_enabled'));
		expect(score.overall).toBeLessThanOrEqual(64);
	});

	it('creates no ordering inversion: p=none and absent score identically on the same roster', () => {
		const pNone = computeScanScore(rosterWithDmarc(pNoneResult()), contextFor('mail_enabled'));
		const absent = computeScanScore(rosterWithDmarc(absentResult()), contextFor('mail_enabled'));
		expect(pNone.overall).toBe(absent.overall);
	});
});

describe('non-mail profiles: the ceiling does NOT leak (Option B is a separate decision)', () => {
	it('web_only (dmarc weighted 3 since model 1.20.0, still not critical) stays uncapped on an otherwise-clean roster', () => {
		const score = computeScanScore(rosterWithDmarc(pNoneResult()), contextFor('web_only'));
		expect(score.overall).toBeGreaterThan(64);
	});

	it('non_mail (dmarc weighted but not critical) stays uncapped on an otherwise-clean roster', () => {
		const score = computeScanScore(rosterWithDmarc(pNoneResult()), contextFor('non_mail'));
		expect(score.overall).toBeGreaterThan(64);
	});
});
