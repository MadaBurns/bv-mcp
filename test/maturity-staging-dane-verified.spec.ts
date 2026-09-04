// SPDX-License-Identifier: BUSL-1.1

/**
 * #841 — maturity staging credits a DANE pin toward Stage 4 ONLY when the finding
 * carries `certificateMatchVerified: true`. Before this, a title regex matched the
 * honest "present, not verified" finding too, so an unreadable or stale SMTP pin
 * bought a Stage-4 "Hardened" promotion.
 */

import { describe, it, expect } from 'vitest';
import { computeMaturityStage } from '../src/tools/scan/maturity-staging';
import { buildCheckResult, createFinding } from '../src/lib/scoring';
import type { CheckResult, Finding } from '../src/lib/scoring';

/**
 * A Stage-3 mail roster with exactly ONE hardening signal (CAA — not a transport /
 * integrity signal), so the DANE credit alone decides Stage 4: it supplies both the
 * second hardening signal AND the required transport signal.
 */
function stage3Roster(): CheckResult[] {
	return [
		buildCheckResult('mx', [createFinding('mx', 'MX records found', 'info', '2 records')]),
		buildCheckResult('spf', [createFinding('spf', 'SPF record configured', 'info', 'ok')]),
		buildCheckResult('dmarc', [createFinding('dmarc', 'DMARC record found', 'info', 'p=reject')]),
		buildCheckResult('dkim', [createFinding('dkim', 'DKIM configured', 'info', 'selectors', { detectionMethod: 'provider-implied' })]),
		buildCheckResult('caa', [createFinding('caa', 'CAA records found', 'info', 'ok')]),
	];
}

const dane = (category: 'dane' | 'dane_https', finding: Finding) => buildCheckResult(category, [{ ...finding, category }]);

describe('maturity staging — DANE credit requires certificateMatchVerified (#841)', () => {
	it('baseline: the roster is Stage 3 without DANE', () => {
		expect(computeMaturityStage(stage3Roster(), 'mail_enabled').stage).toBe(3);
	});

	it('an unverified SMTP pin (present, not verified — title still "DANE TLSA configured") does NOT promote', () => {
		const checks = [
			...stage3Roster(),
			dane(
				'dane',
				createFinding('dane', 'DANE TLSA configured for _25._tcp.mx.example.com', 'low', 'present, not verified', {
					certificateMatchVerified: false,
				}),
			),
		];
		expect(computeMaturityStage(checks, 'mail_enabled').stage).toBe(3);
	});

	it('a legacy title-only finding with no marker does NOT promote either', () => {
		const checks = [...stage3Roster(), dane('dane', createFinding('dane', 'DANE TLSA configured', 'info', 'ok'))];
		expect(computeMaturityStage(checks, 'mail_enabled').stage).toBe(3);
	});

	it('a pending HTTPS pin verification (unverified low with sub-state metadata) does NOT promote', () => {
		const checks = [
			...stage3Roster(),
			dane(
				'dane_https',
				createFinding('dane_https', 'DANE TLSA configured for _443._tcp.example.com', 'low', 'present, not verified', {
					certificateMatchVerified: false,
					certificateProbe: 'pending',
					notAssessedReason: 'certificate_probe_pending',
				}),
			),
		];
		expect(computeMaturityStage(checks, 'mail_enabled').stage).toBe(3);
	});

	it('a VERIFIED HTTPS pin promotes to Stage 4', () => {
		const checks = [
			...stage3Roster(),
			dane(
				'dane_https',
				createFinding('dane_https', 'DANE TLSA verified against the served certificate for _443._tcp.example.com', 'info', 'verified', {
					certificateMatchVerified: true,
				}),
			),
		];
		const stage = computeMaturityStage(checks, 'mail_enabled');
		expect(stage.stage).toBe(4);
	});

	it('a VERIFIED SMTP pin would promote too (the marker, not the category, is what counts)', () => {
		const checks = [
			...stage3Roster(),
			dane(
				'dane',
				createFinding('dane', 'DANE TLSA verified against the served certificate for _25._tcp.mx.example.com', 'info', 'verified', {
					certificateMatchVerified: true,
				}),
			),
		];
		expect(computeMaturityStage(checks, 'mail_enabled').stage).toBe(4);
	});

	it('a mismatched pin (high, certificateMatchVerified: false) does NOT promote', () => {
		const checks = [
			...stage3Roster(),
			dane(
				'dane_https',
				createFinding('dane_https', 'DANE TLSA pin does not match the served certificate for _443._tcp.example.com', 'high', 'mismatch', {
					certificateMatchVerified: false,
				}),
			),
		];
		expect(computeMaturityStage(checks, 'mail_enabled').stage).toBe(3);
	});
});
