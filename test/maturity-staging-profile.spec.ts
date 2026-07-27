// SPDX-License-Identifier: BUSL-1.1
//
// Cluster 3 — Defect I
//   Maturity classifier must respect scoringProfile.
//   - web_only domains evaluate against a WEB-ONLY ladder (no mail categories
//     can pull the stage up or down).
//   - mail_enabled stage 4 ("Hardened") tightened: stripe.com (no DNSSEC,
//     no MTA-STS, no BIMI, no DANE) is NOT Hardened despite hasCaa +
//     hasDkimDiscovered = 2.
//
// Plan: docs/plans/2026-05-28-fact-check-defect-remediation-tdd-plan.md §5.3
// Fact-check baseline (2026-05-28):
//   - gov.uk currently → stage 1 "DNS-Only" (wrong — has DNSSEC + DMARCbis
//     + HSTS + Fastly + strong web posture).
//   - stripe.com currently → stage 4 "Hardened" (wrong — missing transport
//     and integrity hardening).

import { describe, it, expect } from 'vitest';
import { computeMaturityStage } from '../src/tools/scan/maturity-staging';
import { buildCheckResult, createFinding } from '../src/lib/scoring';
import type { CheckResult } from '../src/lib/scoring';

// Helpers -----------------------------------------------------------------

function passingCheck(category: Parameters<typeof buildCheckResult>[0], title: string): CheckResult {
	return buildCheckResult(category, [createFinding(category, title, 'info', 'ok')]);
}

// gov.uk-shaped checks (no MX, strong web + DNSSEC + DMARC strict)
function govUkChecks(): CheckResult[] {
	return [
		buildCheckResult('mx', [createFinding('mx', 'No MX records found', 'info', 'web-only domain')]),
		buildCheckResult('spf', [createFinding('spf', 'SPF record found', 'info', 'v=spf1 -all (anti-spoof)')]),
		// dmarc: p=reject + np=reject + adkim=s + aspf=s + sp=none(downgraded) + no ruf(low)
		buildCheckResult('dmarc', [
			createFinding('dmarc', 'DMARC record found', 'info', 'p=reject; np=reject; adkim=s; aspf=s'),
			createFinding('dmarc', 'No forensic reporting configured (ruf= absent)', 'low', 'no ruf'),
		]),
		passingCheck('dnssec', 'DNSSEC validated'),
		passingCheck('ssl', 'SSL certificate valid'),
		buildCheckResult('http_security', [
			createFinding('http_security', 'HSTS configured (preload)', 'info', 'HSTS preload + max-age >= 1y'),
		]),
	];
}

// stripe.com-shaped checks (mail_enabled, no DNSSEC, no MTA-STS, no BIMI, no DANE)
function stripeChecks(): CheckResult[] {
	return [
		buildCheckResult('mx', [createFinding('mx', 'MX records found', 'info', '2 records')]),
		passingCheck('spf', 'SPF record configured'),
		buildCheckResult('dmarc', [createFinding('dmarc', 'DMARC record found', 'info', 'p=reject')]),
		buildCheckResult('dkim', [createFinding('dkim', 'DKIM configured', 'info', 'selectors found', { selectorsFound: ['s1', 's2'] })]),
		buildCheckResult('caa', [createFinding('caa', 'CAA records found', 'info', '0 issue "amazon.com"')]),
		buildCheckResult('ssl', [createFinding('ssl', 'SSL certificate valid', 'info', 'ok')]),
		// No DNSSEC, no MTA-STS, no BIMI, no DANE — stripe.com lacks transport hardening.
		// Use high-severity findings so `passed=false` and the maturity classifier sees them as absent.
		buildCheckResult('dnssec', [createFinding('dnssec', 'No DNSKEY records found', 'high', 'No DNSSEC')]),
		buildCheckResult('mta_sts', [createFinding('mta_sts', 'No MTA-STS or TLS-RPT records found', 'high', 'missing')]),
	];
}

// proton.me-shaped (strong mail, full hardening — stays stage 4)
function protonChecks(): CheckResult[] {
	return [
		buildCheckResult('mx', [createFinding('mx', 'MX records found', 'info', '2 records')]),
		passingCheck('spf', 'SPF record configured'),
		buildCheckResult('dmarc', [createFinding('dmarc', 'DMARC record found', 'info', 'p=reject')]),
		buildCheckResult('dkim', [
			createFinding('dkim', 'DKIM configured', 'info', 'selectors found', { selectorsFound: ['protonmail', 'protonmail2'] }),
		]),
		passingCheck('mta_sts', 'MTA-STS configured'),
		passingCheck('dnssec', 'DNSSEC validated'),
		passingCheck('dane', 'DANE TLSA configured'),
		buildCheckResult('tlsrpt', [createFinding('tlsrpt', 'TLS-RPT configured', 'info', 'ok')]),
		buildCheckResult('bimi', [createFinding('bimi', 'BIMI record configured', 'info', 'ok')]),
	];
}

describe('Defect I — computeMaturityStage accepts profile and respects it', () => {
	it('classifies gov.uk-style web_only domain at stage ≥ 3 (regression — 2026-05-28 baseline was 1)', () => {
		const stage = computeMaturityStage(govUkChecks(), 'web_only');
		expect(stage.stage).toBeGreaterThanOrEqual(3);
		// Label should NOT be "DNS-Only" any more for a domain with this much web posture.
		expect(stage.label).not.toBe('DNS-Only');
		// Description should reflect web-only nature.
		expect(stage.description.toLowerCase()).toMatch(/web|http|tls|browser|dns/);
	});

	it('classifies mail-enabled proton.me-style domain at stage 4 (Hardened) — regression', () => {
		const stage = computeMaturityStage(protonChecks(), 'mail_enabled');
		expect(stage.stage).toBe(4);
		expect(stage.label).toBe('Hardened');
	});

	it('classifies stripe.com-style mail-enabled domain at stage ≤ 3 (NOT Hardened) — regression', () => {
		// stripe.com is missing DNSSEC, MTA-STS, BIMI, DANE — transport/integrity hardening absent.
		const stage = computeMaturityStage(stripeChecks(), 'mail_enabled');
		expect(stage.stage).toBeLessThanOrEqual(3);
		expect(stage.label).not.toBe('Hardened');
	});

	it('cross-domain ordering: proton.me Hardened > stripe.com (regression)', () => {
		const proton = computeMaturityStage(protonChecks(), 'mail_enabled');
		const stripe = computeMaturityStage(stripeChecks(), 'mail_enabled');
		expect(proton.stage).toBeGreaterThan(stripe.stage);
	});

	it('cross-domain ordering: gov.uk web_only stage ≥ 3, stripe.com stage ≤ 3 — both are mid-tier in their own ladders', () => {
		const govuk = computeMaturityStage(govUkChecks(), 'web_only');
		const stripe = computeMaturityStage(stripeChecks(), 'mail_enabled');
		// gov.uk: classified on web-only ladder, gets ≥3 ("Defensive" or higher).
		expect(govuk.stage).toBeGreaterThanOrEqual(3);
		// stripe: classified on mail-enabled ladder, capped at ≤3 ("Enforcing") without transport hardening.
		expect(stripe.stage).toBeLessThanOrEqual(3);
	});

	it('backward-compatible: omitting profile argument still produces a stage (legacy callers)', () => {
		const stage = computeMaturityStage(protonChecks());
		// Without explicit profile, falls back to existing mail-enabled inference.
		expect(stage.stage).toBeGreaterThanOrEqual(3);
	});

	it('web_only ladder yields stage 0/1 (Basic) when only SSL is present', () => {
		const checks: CheckResult[] = [
			buildCheckResult('mx', [createFinding('mx', 'No MX records found', 'info', 'web-only')]),
			passingCheck('ssl', 'SSL certificate valid'),
		];
		const stage = computeMaturityStage(checks, 'web_only');
		expect(stage.stage).toBeLessThanOrEqual(1);
	});

	it('web_only ladder yields stage ≥ 2 when SSL + DNSSEC + HSTS present', () => {
		const checks: CheckResult[] = [
			buildCheckResult('mx', [createFinding('mx', 'No MX records found', 'info', 'web-only')]),
			passingCheck('ssl', 'SSL certificate valid'),
			passingCheck('dnssec', 'DNSSEC validated'),
			buildCheckResult('http_security', [createFinding('http_security', 'HSTS configured', 'info', 'HSTS')]),
		];
		const stage = computeMaturityStage(checks, 'web_only');
		expect(stage.stage).toBeGreaterThanOrEqual(2);
	});

	// Regression — a spoofable web_only domain (no SPF -all / no DMARC reject) must NOT be
	// labelled "Hardened" (the word collided with the mail ladder's Stage 4) and must NOT
	// reach the top "Defensive"/"Comprehensive" tiers on infrastructure hardening alone,
	// because it is still freely impersonated in the From: header. (dunninghams.net case:
	// score 57/D+, spf:0 dmarc:0, yet previously labelled "Hardened".)
	function spoofableWebOnlyChecks(): CheckResult[] {
		return [
			buildCheckResult('mx', [createFinding('mx', 'No MX records found', 'info', 'web-only')]),
			buildCheckResult('spf', [createFinding('spf', 'No SPF record found', 'high', 'Missing SPF')]),
			buildCheckResult('dmarc', [createFinding('dmarc', 'No DMARC record found', 'high', 'Missing DMARC')]),
			passingCheck('ssl', 'SSL certificate valid'),
			passingCheck('dnssec', 'DNSSEC validated'),
		];
	}

	it('web_only spoofable domain (SSL+DNSSEC, no anti-spoof) is Stage 2 "Transport-Hardened", never "Hardened"', () => {
		const stage = computeMaturityStage(spoofableWebOnlyChecks(), 'web_only');
		expect(stage.stage).toBe(2);
		expect(stage.label).toBe('Transport-Hardened');
		expect(stage.label).not.toBe('Hardened');
		// Honesty: the rating must flag the spoofability gap.
		expect(`${stage.description} ${stage.nextStep}`).toMatch(/SPF|DMARC|impersonat/i);
	});

	it('web_only spoofable domain never reaches Defensive/Comprehensive on infra hardening alone', () => {
		// Even with SSL + DNSSEC + HSTS, no anti-spoof policy caps the ceiling at Stage 2.
		const checks = [
			...spoofableWebOnlyChecks(),
			buildCheckResult('http_security', [createFinding('http_security', 'HSTS configured (preload)', 'info', 'HSTS')]),
		];
		const stage = computeMaturityStage(checks, 'web_only');
		expect(stage.stage).toBeLessThanOrEqual(2);
		expect(['Defensive', 'Comprehensive', 'Hardened']).not.toContain(stage.label);
	});

	it('web_only domain WITH anti-spoof (SPF -all + DMARC reject) + SSL + DNSSEC reaches Defensive', () => {
		const checks: CheckResult[] = [
			buildCheckResult('mx', [createFinding('mx', 'No MX records found', 'info', 'web-only')]),
			buildCheckResult('spf', [createFinding('spf', 'SPF record found', 'info', 'v=spf1 -all')]),
			buildCheckResult('dmarc', [createFinding('dmarc', 'DMARC record found', 'info', 'p=reject')]),
			passingCheck('ssl', 'SSL certificate valid'),
			passingCheck('dnssec', 'DNSSEC validated'),
		];
		const stage = computeMaturityStage(checks, 'web_only');
		expect(stage.stage).toBeGreaterThanOrEqual(3);
		expect(stage.label).toBe('Defensive');
	});
});

// ---------------------------------------------------------------------------
// Issue #574 — an UNMEASURABLE input must produce an abstention, never a
// confident negative verdict (the principle already established for
// `check_mta_sts` by #455 / v3.25.4).
//
// Live repro 2026-07-27: 22+ `bnz.co.nz` hosts whose `ssl` probe Akamai blocked
// were published as "Stage 0 — Unprotected / No TLS detected on this web-only
// domain. Traffic is not authenticated or encrypted." Those hosts (named
// consumer-banking hostnames) demonstrably DO serve TLS. The ladder read only
// `passed`, which the scan pipeline forcibly stamps `false` on any inconclusive
// check — so a measurement GAP became an affirmative security CLAIM.
// ---------------------------------------------------------------------------

/** The exact shape `scan-domain.ts` re-stamps onto an inconclusive check. */
function erroredCheck(category: Parameters<typeof buildCheckResult>[0]): CheckResult {
	return {
		...buildCheckResult(category, [
			createFinding(category, `${category} check error`, 'high', 'Check failed: connection blocked at the edge'),
		]),
		score: 0,
		passed: false,
		checkStatus: 'error' as const,
		partial: true,
	};
}

/**
 * The CONTROL half of the one-variable pair: a web-only domain with anti-spoof
 * email policy + TLS + DNSSEC, and an http_security check that COMPLETED and
 * found no HSTS. Ladder A places it at stage 3 "Defensive".
 */
function defensiveWebOnlyChecks(): CheckResult[] {
	return [
		buildCheckResult('mx', [createFinding('mx', 'No MX records found', 'info', 'web-only')]),
		buildCheckResult('spf', [createFinding('spf', 'SPF record found', 'info', 'v=spf1 -all')]),
		buildCheckResult('dmarc', [createFinding('dmarc', 'DMARC record found', 'info', 'p=reject')]),
		passingCheck('ssl', 'SSL certificate valid'),
		passingCheck('dnssec', 'DNSSEC validated'),
		buildCheckResult('http_security', [createFinding('http_security', 'No HSTS header', 'medium', 'Strict-Transport-Security absent')]),
	];
}

/** The VARIABLE half: byte-identical, except the TLS probe never completed. */
function tlsUnmeasuredWebOnlyChecks(): CheckResult[] {
	return defensiveWebOnlyChecks().map((c) => (c.category === 'ssl' ? erroredCheck('ssl') : c));
}

describe('#574 — web-only ladder abstains when the TLS probe was never measured', () => {
	it('CONTROL: the measured variant is unchanged at stage 3 "Defensive"', () => {
		// Non-vacuity guard. Without this, a fix that abstained on EVERYTHING
		// would satisfy every assertion below.
		const stage = computeMaturityStage(defensiveWebOnlyChecks(), 'web_only');
		expect(stage.stage).toBe(3);
		expect(stage.label).toBe('Defensive');
		expect(stage.indeterminate).toBeUndefined();
	});

	it('VARIABLE: an errored ssl check yields an indeterminate result, not stage 0', () => {
		const stage = computeMaturityStage(tlsUnmeasuredWebOnlyChecks(), 'web_only');
		expect(stage.indeterminate).toBe(true);
	});

	it('VARIABLE: the "No TLS detected" claim is unreachable when ssl was never measured', () => {
		const stage = computeMaturityStage(tlsUnmeasuredWebOnlyChecks(), 'web_only');
		const prose = `${stage.label} ${stage.description} ${stage.nextStep}`;
		// The exact published sentence, and its component claims.
		expect(prose).not.toMatch(/No TLS detected/i);
		expect(prose).not.toMatch(/not authenticated or encrypted/i);
		expect(stage.label).not.toBe('Unprotected');
	});

	it('VARIABLE: the prose names the measurement gap and how to resolve it', () => {
		const stage = computeMaturityStage(tlsUnmeasuredWebOnlyChecks(), 'web_only');
		expect(stage.label).toMatch(/not determined/i);
		// It must read as a measurement gap, not a verdict…
		expect(stage.description).toMatch(/could not be measured|not measured|blocked|timed out/i);
		expect(stage.description).toMatch(/not a security verdict|measurement gap/i);
		// …and tell the reader what to do about it.
		expect(stage.nextStep).toMatch(/re-?scan|verify/i);
	});

	it('a timed-out ssl check abstains the same way an errored one does', () => {
		const checks = defensiveWebOnlyChecks().map((c) =>
			c.category === 'ssl' ? { ...erroredCheck('ssl'), checkStatus: 'timeout' as const } : c,
		);
		expect(computeMaturityStage(checks, 'web_only').indeterminate).toBe(true);
	});

	it('non_mail domains route through the same ladder and abstain identically', () => {
		expect(computeMaturityStage(tlsUnmeasuredWebOnlyChecks(), 'non_mail').indeterminate).toBe(true);
	});
});

describe('#574 — web-only ladder keeps the stage but discloses an unmeasured http_security', () => {
	it('an errored http_security (ssl measured) keeps the honest stage-3 floor', () => {
		const checks = defensiveWebOnlyChecks().map((c) => (c.category === 'http_security' ? erroredCheck('http_security') : c));
		const stage = computeMaturityStage(checks, 'web_only');
		// The stage is a LOWER BOUND and remains honest — only stage 4 was gated on HSTS.
		expect(stage.stage).toBe(3);
		expect(stage.label).toBe('Defensive');
		expect(stage.indeterminate).toBeUndefined();
	});

	it('…and discloses that HSTS could not be measured, so stage 4 was not assessable', () => {
		const checks = defensiveWebOnlyChecks().map((c) => (c.category === 'http_security' ? erroredCheck('http_security') : c));
		const stage = computeMaturityStage(checks, 'web_only');
		const prose = `${stage.description} ${stage.nextStep}`;
		expect(prose).toMatch(/HSTS/);
		expect(prose).toMatch(/could not be measured|not measured/i);
	});

	it('CONTROL: a completed http_security adds no disclosure', () => {
		const stage = computeMaturityStage(defensiveWebOnlyChecks(), 'web_only');
		expect(`${stage.description} ${stage.nextStep}`).not.toMatch(/could not be measured/i);
	});
});

// ---------------------------------------------------------------------------
// Ladder B (mail-enabled). OPPOSITE polarity, and arguably worse: `hasSpf` /
// `hasDmarc` are ABSENCE-of-finding tests, so an errored spf/dmarc — which emits
// a "check error" finding rather than a "No SPF record" finding — read TRUE and
// a measurement failure inflated maturity UPWARD. False reassurance.
// ---------------------------------------------------------------------------
describe('#574 — mail ladder: an unmeasured spf/dmarc never reads as present', () => {
	function enforcingMailChecks(): CheckResult[] {
		return [
			buildCheckResult('mx', [createFinding('mx', 'MX records found', 'info', '2 records')]),
			buildCheckResult('spf', [createFinding('spf', 'SPF record configured', 'info', 'ok')]),
			buildCheckResult('dmarc', [createFinding('dmarc', 'DMARC record found', 'info', 'p=reject')]),
		];
	}

	it('CONTROL: the measured variant is unchanged at stage 3 "Enforcing"', () => {
		const stage = computeMaturityStage(enforcingMailChecks(), 'mail_enabled');
		expect(stage.stage).toBe(3);
		expect(stage.label).toBe('Enforcing');
		expect(stage.indeterminate).toBeUndefined();
	});

	it('an errored spf check no longer inflates the domain to "Enforcing"', () => {
		const checks = enforcingMailChecks().map((c) => (c.category === 'spf' ? erroredCheck('spf') : c));
		const stage = computeMaturityStage(checks, 'mail_enabled');
		expect(stage.label).not.toBe('Enforcing');
		expect(stage.stage).not.toBe(3);
	});

	it('an errored dmarc check no longer inflates the domain to "Enforcing"', () => {
		const checks = enforcingMailChecks().map((c) => (c.category === 'dmarc' ? erroredCheck('dmarc') : c));
		const stage = computeMaturityStage(checks, 'mail_enabled');
		expect(stage.label).not.toBe('Enforcing');
	});

	it('…and abstains rather than swapping false reassurance for a false alarm', () => {
		// Deflating an unmeasured check into stage 0 "No email authentication — any
		// server can send email as this domain" would be the SAME defect pointing the
		// other way. The unmeasured input abstains at BOTH ends.
		const checks = enforcingMailChecks().map((c) => (c.category === 'dmarc' ? erroredCheck('dmarc') : c));
		const stage = computeMaturityStage(checks, 'mail_enabled');
		expect(stage.indeterminate).toBe(true);
		expect(`${stage.label} ${stage.description}`).not.toMatch(/No email authentication|any server can send/i);
	});

	it('an errored bimi/dane/dkim check no longer counts as a hardening signal', () => {
		// hasBimi / hasDane / hasDkimDiscovered are finding-title probes with the same
		// absence polarity — an errored check emitted no "No DKIM records found"
		// finding, so DKIM read as "discovered".
		const base: CheckResult[] = [
			buildCheckResult('spf', [createFinding('spf', 'SPF record configured', 'info', 'ok')]),
			buildCheckResult('dmarc', [createFinding('dmarc', 'DMARC record found', 'info', 'p=reject')]),
			buildCheckResult('mta_sts', [createFinding('mta_sts', 'MTA-STS configured', 'info', 'ok')]),
		];
		// mta_sts (1 signal) + an ERRORED dkim must NOT reach the 2 signals stage 4 needs.
		const stage = computeMaturityStage([...base, erroredCheck('dkim')], 'mail_enabled');
		expect(stage.stage).toBe(3);
		expect(stage.label).not.toBe('Hardened');

		// CONTROL: a genuinely discovered DKIM selector still reaches stage 4.
		const control = computeMaturityStage(
			[...base, buildCheckResult('dkim', [createFinding('dkim', 'DKIM configured', 'info', 'ok', { selectorsFound: ['s1'] })])],
			'mail_enabled',
		);
		expect(control.stage).toBe(4);
	});

	it('an EMPTY check set keeps its historical stage 0 (contract preserved)', () => {
		// `test/maturity-staging.spec.ts:93` locks this. "Nothing was attempted" is
		// already withheld one layer up by `isGraded` in format-report; the abstention
		// added here keys on a check that was ATTEMPTED and did not complete.
		const stage = computeMaturityStage([]);
		expect(stage.stage).toBe(0);
		expect(stage.indeterminate).toBeUndefined();
	});
});
