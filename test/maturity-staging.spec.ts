import { describe, it, expect } from 'vitest';
import { computeMaturityStage } from '../src/tools/scan/maturity-staging';
import { buildCheckResult, createFinding } from '../src/lib/scoring';
import type { CheckResult } from '../src/lib/scoring';

describe('computeMaturityStage', () => {
	it('returns Stage 0 when no SPF and no DMARC', () => {
		const checks: CheckResult[] = [
			buildCheckResult('spf', [createFinding('spf', 'No SPF record found', 'critical', 'Missing SPF')]),
			buildCheckResult('dmarc', [createFinding('dmarc', 'No DMARC record found', 'critical', 'Missing DMARC')]),
		];
		const stage = computeMaturityStage(checks);
		expect(stage.stage).toBe(0);
		expect(stage.label).toBe('Unprotected');
		expect(stage.nextStep).toContain('Publish SPF');
	});

	it('returns Stage 1 when SPF exists and DMARC p=none with no rua=', () => {
		const checks: CheckResult[] = [
			buildCheckResult('spf', [createFinding('spf', 'SPF record configured', 'info', 'ok')]),
			buildCheckResult('dmarc', [
				createFinding('dmarc', 'DMARC policy set to none', 'high', 'Policy is none'),
				createFinding('dmarc', 'No aggregate reporting', 'medium', 'No rua='),
			]),
		];
		const stage = computeMaturityStage(checks);
		expect(stage.stage).toBe(1);
		expect(stage.label).toBe('Basic');
		expect(stage.nextStep).toContain('aggregate reporting');
	});

	it('returns Stage 2 when SPF exists and DMARC p=none with rua=', () => {
		const checks: CheckResult[] = [
			buildCheckResult('spf', [createFinding('spf', 'SPF record configured', 'info', 'ok')]),
			buildCheckResult('dmarc', [createFinding('dmarc', 'DMARC policy set to none', 'high', 'Policy is none')]),
		];
		const stage = computeMaturityStage(checks);
		expect(stage.stage).toBe(2);
		expect(stage.label).toBe('Monitoring');
		expect(stage.nextStep).toContain('p=quarantine');
	});

	it('returns Stage 3 when SPF + DKIM + DMARC p=reject', () => {
		const checks: CheckResult[] = [
			buildCheckResult('spf', [createFinding('spf', 'SPF record configured', 'info', 'ok')]),
			buildCheckResult('dkim', [createFinding('dkim', 'DKIM configured', 'info', 'Found selectors')]),
			buildCheckResult('dmarc', [createFinding('dmarc', 'DMARC record found', 'info', 'p=reject')]),
		];
		const stage = computeMaturityStage(checks);
		expect(stage.stage).toBe(3);
		expect(stage.label).toBe('Enforcing');
		expect(stage.nextStep).toContain('MTA-STS');
	});

	it('returns Stage 4 when SPF + DKIM + DMARC p=reject + MTA-STS + DNSSEC', () => {
		const checks: CheckResult[] = [
			buildCheckResult('spf', [createFinding('spf', 'SPF record configured', 'info', 'ok')]),
			buildCheckResult('dkim', [createFinding('dkim', 'DKIM configured', 'info', 'Found selectors')]),
			buildCheckResult('dmarc', [createFinding('dmarc', 'DMARC record found', 'info', 'p=reject')]),
			buildCheckResult('mta_sts', [createFinding('mta_sts', 'MTA-STS configured', 'info', 'ok')]),
			buildCheckResult('dnssec', [createFinding('dnssec', 'DNSSEC validated', 'info', 'ok')]),
		];
		const stage = computeMaturityStage(checks);
		expect(stage.stage).toBe(4);
		expect(stage.label).toBe('Hardened');
		expect(stage.nextStep).toBe('');
	});

	it('returns Stage 4 when SPF + DKIM + DMARC p=quarantine + BIMI + DNSSEC', () => {
		const checks: CheckResult[] = [
			buildCheckResult('spf', [createFinding('spf', 'SPF record configured', 'info', 'ok')]),
			buildCheckResult('dkim', [createFinding('dkim', 'DKIM configured', 'info', 'Found selectors')]),
			buildCheckResult('dmarc', [createFinding('dmarc', 'DMARC policy set to quarantine', 'low', 'Policy is quarantine')]),
			buildCheckResult('bimi', [createFinding('bimi', 'BIMI record configured', 'info', 'BIMI valid')]),
			buildCheckResult('dnssec', [createFinding('dnssec', 'DNSSEC validated', 'info', 'ok')]),
		];
		const stage = computeMaturityStage(checks);
		expect(stage.stage).toBe(4);
		expect(stage.label).toBe('Hardened');
	});

	it('returns Stage 2 when DMARC p=none with rua= (DKIM absence does not block Stage 2)', () => {
		const checks: CheckResult[] = [
			buildCheckResult('spf', [createFinding('spf', 'SPF record configured', 'info', 'ok')]),
			buildCheckResult('dkim', [createFinding('dkim', 'No DKIM records found among tested selectors', 'high', 'Missing DKIM')]),
			buildCheckResult('dmarc', [createFinding('dmarc', 'DMARC policy set to none', 'high', 'Policy is none')]),
		];
		const stage = computeMaturityStage(checks);
		expect(stage.stage).toBe(2);
		expect(stage.label).toBe('Monitoring');
	});

	it('returns Stage 0 when checks array is empty', () => {
		const stage = computeMaturityStage([]);
		expect(stage.stage).toBe(0);
		expect(stage.label).toBe('Unprotected');
	});

	it('returns Unprotected for non-mail domain without DNSSEC', () => {
		const checks: CheckResult[] = [
			buildCheckResult('mx', [createFinding('mx', 'No MX records found', 'info', 'Domain has no MX')]),
			buildCheckResult('spf', [createFinding('spf', 'No SPF record found', 'critical', 'Missing SPF')]),
			buildCheckResult('dmarc', [createFinding('dmarc', 'No DMARC record found', 'critical', 'Missing DMARC')]),
			{ category: 'dnssec', passed: false, score: 0, findings: [createFinding('dnssec', 'No DNSKEY records', 'high', 'No DNSSEC')] },
		];
		const stage = computeMaturityStage(checks);
		expect(stage.stage).toBe(0);
		expect(stage.label).toBe('Unprotected');
		expect(stage.description).toContain('does not accept email');
		expect(stage.nextStep).toContain('DNSSEC');
	});

	it('returns DNS-Only for non-mail domain with DNSSEC', () => {
		const checks: CheckResult[] = [
			buildCheckResult('mx', [createFinding('mx', 'No MX records found', 'info', 'Domain has no MX')]),
			buildCheckResult('spf', [createFinding('spf', 'No SPF record found', 'critical', 'Missing SPF')]),
			buildCheckResult('dnssec', [createFinding('dnssec', 'DNSSEC validated', 'info', 'ok')]),
		];
		const stage = computeMaturityStage(checks);
		expect(stage.stage).toBe(1);
		expect(stage.label).toBe('DNS-Only');
		expect(stage.description).toContain('does not accept email');
		expect(stage.description).toContain('DNSSEC');
		expect(stage.nextStep).toBe('');
	});

	it('does not short-circuit to non-mail path when MX records exist', () => {
		const checks: CheckResult[] = [
			buildCheckResult('mx', [createFinding('mx', 'MX records found', 'info', '2 MX records')]),
			buildCheckResult('spf', [createFinding('spf', 'SPF record configured', 'info', 'ok')]),
			buildCheckResult('dkim', [createFinding('dkim', 'DKIM configured', 'info', 'Found selectors')]),
			buildCheckResult('dmarc', [createFinding('dmarc', 'DMARC record found', 'info', 'p=reject')]),
		];
		const stage = computeMaturityStage(checks);
		expect(stage.stage).toBe(3);
		expect(stage.label).toBe('Enforcing');
	});
});

describe('maturity staging v2', () => {
	it('Stage 3 does not require DKIM discovery', () => {
		// SPF + DMARC p=reject, but DKIM not found — should still be Stage 3
		const checks: CheckResult[] = [
			buildCheckResult('spf', [createFinding('spf', 'SPF record configured', 'info', 'ok')]),
			buildCheckResult('dkim', [createFinding('dkim', 'No DKIM records found among tested selectors', 'high', 'No DKIM')]),
			buildCheckResult('dmarc', [createFinding('dmarc', 'DMARC record found', 'info', 'p=reject')]),
		];
		const stage = computeMaturityStage(checks);
		expect(stage.stage).toBe(3);
		expect(stage.label).toBe('Enforcing');
	});

	it('Stage 1 is specifically DMARC p=none without rua', () => {
		// SPF present, DMARC p=none, no rua — Stage 1
		const checks: CheckResult[] = [
			buildCheckResult('spf', [createFinding('spf', 'SPF record configured', 'info', 'ok')]),
			buildCheckResult('dmarc', [
				createFinding('dmarc', 'DMARC policy set to none', 'high', 'Policy is none'),
				createFinding('dmarc', 'No aggregate reporting', 'medium', 'No rua='),
			]),
		];
		const stage = computeMaturityStage(checks);
		expect(stage.stage).toBe(1);
		expect(stage.label).toBe('Basic');
	});

	it('SPF + DMARC p=none without rua= falls to Stage 1 (not Stage 2)', () => {
		// Stage 2 requires p=none WITH rua=; without rua= it falls to Stage 1
		const checks: CheckResult[] = [
			buildCheckResult('spf', [createFinding('spf', 'SPF record configured', 'info', 'ok')]),
			buildCheckResult('dmarc', [
				createFinding('dmarc', 'DMARC policy set to none', 'high', 'Policy is none'),
				createFinding('dmarc', 'No aggregate reporting', 'medium', 'No rua='),
			]),
		];
		const stage = computeMaturityStage(checks);
		expect(stage.stage).toBe(1);
		expect(stage.label).toBe('Basic');
	});

	it('Stage 4 accepts CAA as hardening signal', () => {
		// SPF + DMARC p=reject + DNSSEC + CAA passed — 2 hardening signals
		const checks: CheckResult[] = [
			buildCheckResult('spf', [createFinding('spf', 'SPF record configured', 'info', 'ok')]),
			buildCheckResult('dmarc', [createFinding('dmarc', 'DMARC record found', 'info', 'p=reject')]),
			buildCheckResult('dnssec', [createFinding('dnssec', 'DNSSEC validated', 'info', 'ok')]),
			{ category: 'caa', passed: true, score: 100, findings: [createFinding('caa', 'CAA records found', 'info', 'ok')] },
		];
		const stage = computeMaturityStage(checks);
		expect(stage.stage).toBe(4);
		expect(stage.label).toBe('Hardened');
	});

	it('Stage 4 accepts DKIM discovered as hardening signal', () => {
		// SPF + DMARC p=reject + DKIM found (selectorsFound) + MTA-STS — 2 hardening signals
		const checks: CheckResult[] = [
			buildCheckResult('spf', [createFinding('spf', 'SPF record configured', 'info', 'ok')]),
			buildCheckResult('dkim', [
				createFinding('dkim', 'DKIM configured', 'info', 'Found selectors', { selectorsFound: ['google', 'selector2'] }),
			]),
			buildCheckResult('dmarc', [createFinding('dmarc', 'DMARC record found', 'info', 'p=reject')]),
			buildCheckResult('mta_sts', [createFinding('mta_sts', 'MTA-STS configured', 'info', 'ok')]),
		];
		const stage = computeMaturityStage(checks);
		expect(stage.stage).toBe(4);
		expect(stage.label).toBe('Hardened');
	});

	it('provider-implied DKIM does NOT count as discovered for Stage 4', () => {
		// SPF + DMARC p=reject + provider-implied DKIM + MTA-STS
		// provider-implied DKIM is only 1 real hardening signal (MTA-STS), need 2 for Stage 4
		const checks: CheckResult[] = [
			buildCheckResult('spf', [createFinding('spf', 'SPF record configured', 'info', 'ok')]),
			buildCheckResult('dkim', [
				createFinding('dkim', 'DKIM selector not discovered', 'medium', 'Provider-implied', { detectionMethod: 'provider-implied' }),
			]),
			buildCheckResult('dmarc', [createFinding('dmarc', 'DMARC record found', 'info', 'p=reject')]),
			buildCheckResult('mta_sts', [createFinding('mta_sts', 'MTA-STS configured', 'info', 'ok')]),
		];
		const stage = computeMaturityStage(checks);
		expect(stage.stage).toBe(3); // Only 1 hardening signal (MTA-STS), need 2
	});
});
