// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import { computeScanScore, buildCheckResult, createFinding, type CheckResult } from '../src/lib/scoring';
import { applyInteractionPenalties } from '../src/lib/category-interactions';

/**
 * Build a realistic scan result payload modeled after constructy.co.nz:
 * - mail_enabled profile
 * - DMARC ≥ 80, DNSSEC ≤ 40 (triggers weak_dnssec_enforcing_dmarc interaction)
 * - 2 high, 6 medium, 11 low findings (19 total non-info)
 */
function buildRealisticCheckResults(): CheckResult[] {
	return [
		// Core tier
		buildCheckResult('spf', [
			createFinding('spf', 'SPF record valid', 'info', 'v=spf1 include:_spf.google.com ~all'),
			createFinding('spf', 'SPF soft fail qualifier', 'low', 'Using ~all instead of -all'),
		]),
		buildCheckResult('dmarc', [
			createFinding('dmarc', 'DMARC policy configured', 'info', 'v=DMARC1; p=quarantine'),
			createFinding('dmarc', 'DMARC not at reject', 'low', 'Policy is quarantine, not reject'),
		]),
		buildCheckResult('dkim', [
			createFinding('dkim', 'DKIM selector not discovered', 'medium',
				'No DKIM selectors were found among the tested set', { confidence: 'heuristic' }),
		]),
		buildCheckResult('dnssec', [
			createFinding('dnssec', 'DNSSEC not enabled', 'high', 'No DNSSEC validation for this domain', {
				confidence: 'deterministic', missingControl: true,
			}),
		]),
		buildCheckResult('ssl', [
			createFinding('ssl', 'SSL certificate valid', 'info', 'Certificate is valid'),
			createFinding('ssl', 'TLS 1.0 supported', 'medium', 'Legacy TLS version enabled'),
		]),
		// Protective tier
		buildCheckResult('subdomain_takeover', [
			createFinding('subdomain_takeover', 'No dangling CNAMEs', 'info', 'Clean'),
		]),
		buildCheckResult('http_security', [
			createFinding('http_security', 'Missing HSTS', 'medium', 'No Strict-Transport-Security header'),
			createFinding('http_security', 'Missing CSP', 'medium', 'No Content-Security-Policy header'),
		]),
		buildCheckResult('mta_sts', [
			createFinding('mta_sts', 'No MTA-STS record found', 'high', 'No MTA-STS DNS record found', {
				confidence: 'deterministic', missingControl: true,
			}),
		]),
		buildCheckResult('subdomailing', [
			createFinding('subdomailing', 'No subdomailing risk', 'info', 'Clean'),
		]),
		buildCheckResult('mx', [
			createFinding('mx', 'MX records present', 'info', 'aspmx.l.google.com'),
			createFinding('mx', 'Provider detected', 'info', 'google', { provider: 'google' }),
		]),
		buildCheckResult('caa', [
			createFinding('caa', 'No CAA records', 'medium', 'No CAA records found', {
				confidence: 'deterministic', missingControl: true,
			}),
		]),
		buildCheckResult('ns', [
			createFinding('ns', 'Name servers valid', 'info', 'ns1.domaincontrol.com'),
		]),
		buildCheckResult('dane_https', [
			createFinding('dane_https', 'No DANE HTTPS records', 'low', 'No SVCB/HTTPS DANE records'),
		]),
		buildCheckResult('svcb_https', [
			createFinding('svcb_https', 'No SVCB records', 'low', 'No HTTPS/SVCB records'),
		]),
		// Hardening tier
		buildCheckResult('dane', [
			createFinding('dane', 'No DANE records found', 'low', 'No TLSA records found'),
		]),
		buildCheckResult('bimi', [
			createFinding('bimi', 'No BIMI record found', 'low', 'No BIMI record found at default._bimi.constructy.co.nz', {
				confidence: 'deterministic',
			}),
		]),
		buildCheckResult('tlsrpt', [
			createFinding('tlsrpt', 'No TLS-RPT record', 'low', 'No _smtp._tls record found'),
		]),
	];
}

describe('scoring determinism', () => {
	it('produces identical scores for identical inputs across 10 runs', () => {
		const results = buildRealisticCheckResults();
		const scores: number[] = [];

		for (let i = 0; i < 10; i++) {
			// Deep-clone inputs to prevent any shared-state mutation
			const cloned: CheckResult[] = JSON.parse(JSON.stringify(results));
			const score = computeScanScore(cloned);
			const { adjustedScore } = applyInteractionPenalties(score);
			scores.push(adjustedScore.overall);
		}

		// All 10 runs must produce the exact same score
		const unique = new Set(scores);
		expect(unique.size).toBe(1);
		expect(scores[0]).toBe(scores[9]);
	});

	it('degraded hardening check with passed:true/score:0 does not inflate score', () => {
		const results = buildRealisticCheckResults();

		// Simulate a timeout-degraded DANE check: score forced to 0 but passed still true
		// This was the pre-fix behavior that caused non-deterministic scoring
		const degradedResults = results.map((r) => {
			if (r.category === 'dane') {
				return { ...r, score: 0, passed: true, checkStatus: 'timeout' as const };
			}
			return r;
		});

		// Simulate a correctly-degraded DANE check: both score=0 and passed=false
		const correctResults = results.map((r) => {
			if (r.category === 'dane') {
				return { ...r, score: 0, passed: false, checkStatus: 'timeout' as const };
			}
			return r;
		});

		const degradedScore = computeScanScore(degradedResults);
		const correctScore = computeScanScore(correctResults);

		// With the fix in buildGenericContext (score >= 50 check), both should produce the same result
		expect(degradedScore.overall).toBe(correctScore.overall);
		expect(degradedScore.grade).toBe(correctScore.grade);
	});

	it('identical category scores with different check orders produce same overall score', () => {
		const results = buildRealisticCheckResults();

		// Forward order
		const scoreA = computeScanScore(results);

		// Reversed order
		const reversed = [...results].reverse();
		const scoreB = computeScanScore(reversed);

		expect(scoreA.overall).toBe(scoreB.overall);
		expect(scoreA.grade).toBe(scoreB.grade);
	});

	it('shuffled results produce same score across 10 iterations', () => {
		const results = buildRealisticCheckResults();

		// Deterministic shuffles using index-based rotations
		const scores: number[] = [];
		for (let i = 0; i < 10; i++) {
			const rotated = [...results.slice(i % results.length), ...results.slice(0, i % results.length)];
			const score = computeScanScore(rotated);
			const { adjustedScore } = applyInteractionPenalties(score);
			scores.push(adjustedScore.overall);
		}

		const unique = new Set(scores);
		expect(unique.size).toBe(1);
	});
});
