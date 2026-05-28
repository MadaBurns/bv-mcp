// SPDX-License-Identifier: BUSL-1.1
//
// Cluster 3 — Canary regression suite
//
// Locks in the v3.3.12 → v3.3.13+ behavioral changes on the 2026-05-28 fact-check
// canaries. Mocked DNS fixtures (no live network — per plan §10).
//
// Coverage:
//   - gov.uk: web_only profile must yield maturity stage ≥ 3 (was 1)
//   - stripe.com: mail_enabled profile must NOT be Hardened (was 4) — stage ≤ 3
//   - proton.me: mail_enabled regression — stays at stage 4 Hardened
//   - DMARC cross-domain ordering: gov.uk score > stripe.com score
//   - DMARC floor: gov.uk DMARCbis-strict policy scores ≥ 85 (was 70)
//
// Tests are unit-level (call the staging classifier + DMARC check directly with
// synthetic checks/records). They avoid the full scanDomain pipeline so they're
// stable and fast.

import { describe, it, expect, vi } from 'vitest';
import { computeMaturityStage } from '../src/tools/scan/maturity-staging';
import { checkDMARC } from '../packages/dns-checks/src/checks/check-dmarc';
import { buildCheckResult, createFinding } from '../src/lib/scoring';
import type { CheckResult } from '../src/lib/scoring';
import type { DNSQueryFunction } from '../packages/dns-checks/src/types';

// Canary DNS fixtures captured 2026-05-28. See fact-check plan §0.

const GOV_UK_DMARC = 'v=DMARC1; p=reject; sp=none; np=reject; adkim=s; aspf=s; fo=1; rua=mailto:dmarc-rua@dmarc.service.gov.uk';
const STRIPE_DMARC = 'v=DMARC1; p=reject; pct=100; fo=1; rua=mailto:dmarc@stripe.com; ruf=mailto:ruf@stripe.com';

function dmarcMock(domain: string, record: string): DNSQueryFunction {
	return vi.fn(async (q: string, _type: string) => (q === `_dmarc.${domain}` ? [record] : []));
}

function passingCheck(category: Parameters<typeof buildCheckResult>[0], title: string): CheckResult {
	return buildCheckResult(category, [createFinding(category, title, 'info', 'ok')]);
}

function govUkChecks(): CheckResult[] {
	return [
		buildCheckResult('mx', [createFinding('mx', 'No MX records found', 'info', 'web-only domain')]),
		buildCheckResult('spf', [createFinding('spf', 'SPF record found', 'info', 'v=spf1 -all (anti-spoof)')]),
		buildCheckResult('dmarc', [
			createFinding('dmarc', 'DMARC record found', 'info', 'p=reject; np=reject; adkim=s; aspf=s'),
		]),
		passingCheck('dnssec', 'DNSSEC validated'),
		passingCheck('ssl', 'SSL certificate valid'),
		buildCheckResult('http_security', [createFinding('http_security', 'HSTS configured (preload)', 'info', 'HSTS preload + max-age >= 1y')]),
	];
}

function stripeChecks(): CheckResult[] {
	return [
		buildCheckResult('mx', [createFinding('mx', 'MX records found', 'info', '2 records')]),
		passingCheck('spf', 'SPF record configured'),
		buildCheckResult('dmarc', [createFinding('dmarc', 'DMARC record found', 'info', 'p=reject')]),
		buildCheckResult('dkim', [
			createFinding('dkim', 'DKIM configured', 'info', 'selectors found', { selectorsFound: ['s1', 's2'] }),
		]),
		passingCheck('ssl', 'SSL certificate valid'),
		buildCheckResult('caa', [createFinding('caa', 'CAA records found', 'info', '0 issue "amazon.com"')]),
		// stripe.com has NO DNSSEC, NO MTA-STS, NO BIMI, NO DANE (per 2026-05-28 fact-check)
		buildCheckResult('dnssec', [createFinding('dnssec', 'No DNSKEY records found', 'high', 'No DNSSEC')]),
		buildCheckResult('mta_sts', [createFinding('mta_sts', 'No MTA-STS or TLS-RPT records found', 'high', 'missing')]),
	];
}

function protonChecks(): CheckResult[] {
	return [
		buildCheckResult('mx', [createFinding('mx', 'MX records found', 'info', '2 records (Proton)')]),
		passingCheck('spf', 'SPF record configured'),
		buildCheckResult('dmarc', [createFinding('dmarc', 'DMARC record found', 'info', 'p=reject; rua present')]),
		buildCheckResult('dkim', [
			createFinding('dkim', 'DKIM configured', 'info', 'selectors found', { selectorsFound: ['protonmail', 'protonmail2'] }),
		]),
		passingCheck('mta_sts', 'MTA-STS configured'),
		passingCheck('dnssec', 'DNSSEC validated'),
		passingCheck('dane', 'DANE TLSA configured'),
	];
}

describe('Cluster 3 canary regression — maturity classifier', () => {
	it('gov.uk maturityStage ≥ 3 under web_only (regression — 2026-05-28 baseline was 1 "DNS-Only")', () => {
		const stage = computeMaturityStage(govUkChecks(), 'web_only');
		expect(stage.stage).toBeGreaterThanOrEqual(3);
		expect(stage.label).not.toBe('DNS-Only');
	});

	it('stripe.com maturityStage ≤ 3 under mail_enabled (regression — 2026-05-28 baseline was 4 "Hardened")', () => {
		const stage = computeMaturityStage(stripeChecks(), 'mail_enabled');
		expect(stage.stage).toBeLessThanOrEqual(3);
		expect(stage.label).not.toBe('Hardened');
	});

	it('proton.me maturityStage = 4 under mail_enabled (negative regression — does NOT change)', () => {
		const stage = computeMaturityStage(protonChecks(), 'mail_enabled');
		expect(stage.stage).toBe(4);
		expect(stage.label).toBe('Hardened');
	});

	it('cross-domain ordering: proton.me > stripe.com (regression — both classified on mail-enabled ladder)', () => {
		const proton = computeMaturityStage(protonChecks(), 'mail_enabled');
		const stripe = computeMaturityStage(stripeChecks(), 'mail_enabled');
		expect(proton.stage).toBeGreaterThan(stripe.stage);
	});
});

describe('Cluster 3 canary regression — DMARC scoring', () => {
	it('gov.uk DMARCbis-strict policy scores ≥ 85 (regression — 2026-05-28 baseline was 70)', async () => {
		const result = await checkDMARC('gov.uk', dmarcMock('gov.uk', GOV_UK_DMARC));
		expect(result.score).toBeGreaterThanOrEqual(85);
	});

	it('cross-domain ordering: gov.uk DMARC > stripe.com DMARC (regression — was 70 < 85)', async () => {
		const govuk = await checkDMARC('gov.uk', dmarcMock('gov.uk', GOV_UK_DMARC));
		const stripe = await checkDMARC('stripe.com', dmarcMock('stripe.com', STRIPE_DMARC));
		expect(govuk.score).toBeGreaterThan(stripe.score);
	});

	it('np=reject downgrades subdomain-weaker finding from HIGH to LOW (mechanism that drives gov.uk floor)', async () => {
		const result = await checkDMARC('gov.uk', dmarcMock('gov.uk', GOV_UK_DMARC));
		const finding = result.findings.find((f) => f.title === 'Subdomain policy weaker than parent policy');
		// Plan §5.4: the downgrade keeps the signal visible but no longer drags the score 25 points.
		if (finding) {
			expect(finding.severity).toBe('low');
		}
	});
});
