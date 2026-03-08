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
			{ category: 'mta_sts', passed: true, score: 100, findings: [createFinding('mta_sts', 'MTA-STS configured', 'info', 'ok')] },
			{ category: 'dnssec', passed: true, score: 100, findings: [createFinding('dnssec', 'DNSSEC validated', 'info', 'ok')] },
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
			{ category: 'dnssec', passed: true, score: 100, findings: [createFinding('dnssec', 'DNSSEC validated', 'info', 'ok')] },
		];
		const stage = computeMaturityStage(checks);
		expect(stage.stage).toBe(4);
		expect(stage.label).toBe('Hardened');
	});

	it('returns Stage 2 when DKIM missing but everything else present (DKIM required for Stage 3)', () => {
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
});
