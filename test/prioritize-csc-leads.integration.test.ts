// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, vi, afterEach } from 'vitest';
import type { CheckResult } from '../src/lib/scoring';
import type { LockPosture } from '../src/tools/check-rdap-lookup';
import type { DiscoveredCandidate } from '../src/tools/prioritize-csc-leads';
import { IN_MEMORY_CACHE } from '../src/lib/cache';

const mockScanDomain = vi.fn();
const mockCheckRdap = vi.fn();

vi.mock('../src/tools/scan-domain', () => ({
	scanDomain: (...args: unknown[]) => mockScanDomain(...args),
}));

vi.mock('../src/tools/check-rdap-lookup', async (importOriginal) => {
	const orig = await importOriginal<typeof import('../src/tools/check-rdap-lookup')>();
	return {
		...orig,
		checkRdapLookup: (...args: unknown[]) => mockCheckRdap(...args),
	};
});

function check(category: string, passed: boolean, findings: Array<{ title: string; severity: string }> = []): CheckResult {
	return { category, passed, score: passed ? 100 : 0, findings: findings.map((f) => ({ category, title: f.title, severity: f.severity, detail: '' })) } as CheckResult;
}

function scan(checks: CheckResult[], overall: number, grade: string) {
	return { checks, score: { overall, grade } };
}

function rdapWithPosture(posture: LockPosture): CheckResult {
	return { category: 'rdap', passed: true, score: 100, findings: [{ category: 'rdap', title: 'Registration details', severity: 'info', detail: '', metadata: { lockPosture: posture } } as never] } as CheckResult;
}

function rdapFailed(): CheckResult {
	return { category: 'rdap', passed: false, score: 0, findings: [{ category: 'rdap', title: 'RDAP lookup failed', severity: 'low', detail: '', metadata: { registrarSource: 'lookup_failed' } } as never] } as CheckResult;
}

const lp = (over: Partial<LockPosture>): LockPosture => ({ level: 'unknown', transferLocked: false, deleteLocked: false, updateLocked: false, registryLevel: false, registrarLevel: false, ...over });

afterEach(() => {
	mockScanDomain.mockReset();
	mockCheckRdap.mockReset();
	IN_MEMORY_CACHE.clear();
});

describe('prioritizeCscLeads — domains[] path', () => {
	it('ranks three domains hottest-first; each ownershipBucket is "unknown"', async () => {
		// hot: unlocked + failing DMARC; warm: registrar-lock + failing SSL; cold: registry-lock + clean
		mockScanDomain.mockImplementation((domain: string) => {
			if (domain === 'hot.com') return Promise.resolve(scan([check('dmarc', false, [{ title: 'No DMARC', severity: 'high' }]), check('ssl', true), check('dnssec', true)], 45, 'F'));
			if (domain === 'warm.com') return Promise.resolve(scan([check('dmarc', true), check('ssl', false, [{ title: 'Cert expired', severity: 'high' }]), check('dnssec', true)], 70, 'C'));
			return Promise.resolve(scan([check('dmarc', true), check('ssl', true), check('dnssec', true)], 95, 'A+'));
		});
		mockCheckRdap.mockImplementation((domain: string) => {
			if (domain === 'hot.com') return Promise.resolve(rdapWithPosture(lp({ level: 'unlocked', transferLocked: false })));
			if (domain === 'warm.com') return Promise.resolve(rdapWithPosture(lp({ level: 'registrar-lock', registrarLevel: true, transferLocked: true })));
			return Promise.resolve(rdapWithPosture(lp({ level: 'registry-lock', registryLevel: true, transferLocked: true })));
		});

		const { prioritizeCscLeads } = await import('../src/tools/prioritize-csc-leads');
		const report = await prioritizeCscLeads({ domains: ['cold.com', 'warm.com', 'hot.com'] });

		expect(report.brand).toBeNull();
		expect(report.totalDomains).toBe(3);
		expect(report.rankedLeads[0].domain).toBe('hot.com');
		expect(report.rankedLeads[report.rankedLeads.length - 1].domain).toBe('cold.com');
		expect(report.rankedLeads.every((l) => l.ownershipBucket === 'unknown')).toBe(true);
		// cold.com: registry locked + all passing → 0 recommendations
		const cold = report.rankedLeads.find((l) => l.domain === 'cold.com')!;
		expect(cold.recommendedCount).toBe(0);
	});

	it('per-domain isolation: a scan throw lands in summary.skipped, others still rank', async () => {
		mockScanDomain.mockImplementation((domain: string) => {
			if (domain === 'boom.com') return Promise.reject(new Error('scan exploded'));
			return Promise.resolve(scan([check('dmarc', false, [{ title: 'No DMARC', severity: 'high' }]), check('ssl', true), check('dnssec', true)], 50, 'F'));
		});
		mockCheckRdap.mockResolvedValue(rdapWithPosture(lp({ level: 'unlocked', transferLocked: false })));

		const { prioritizeCscLeads } = await import('../src/tools/prioritize-csc-leads');
		const report = await prioritizeCscLeads({ domains: ['ok1.com', 'boom.com', 'ok2.com'] });

		expect(report.totalDomains).toBe(2);
		expect(report.rankedLeads.map((l) => l.domain).sort()).toEqual(['ok1.com', 'ok2.com']);
		expect(report.summary.skipped.map((s) => s.domain)).toContain('boom.com');
	});

	it('RDAP failure isolation: MultiLock not recommended while scan-driven products still evaluate', async () => {
		mockScanDomain.mockResolvedValue(scan([check('dmarc', false, [{ title: 'No DMARC', severity: 'high' }]), check('ssl', false, [{ title: 'Cert expired', severity: 'high' }]), check('dnssec', true)], 40, 'F'));
		mockCheckRdap.mockResolvedValue(rdapFailed());

		const { prioritizeCscLeads } = await import('../src/tools/prioritize-csc-leads');
		const report = await prioritizeCscLeads({ domains: ['failrdap.com'] });

		const lead = report.rankedLeads[0];
		expect(lead.recommendedCscProducts).not.toContain('csc_multilock');
		expect(lead.recommendedCscProducts).toContain('managed_dmarc');
		expect(lead.recommendedCscProducts).toContain('digital_certificates');
	});
});

describe('prioritizeCscLeads — brand path (injected discovery)', () => {
	it('maps discovered buckets; impersonation discounted by the 0.3 multiplier; report.brand set', async () => {
		mockScanDomain.mockResolvedValue(scan([check('dmarc', false, [{ title: 'No DMARC', severity: 'high' }]), check('ssl', true), check('dnssec', true)], 50, 'F'));
		mockCheckRdap.mockResolvedValue(rdapWithPosture(lp({ level: 'unlocked', transferLocked: false })));

		const discoverPortfolio = vi.fn(async (): Promise<DiscoveredCandidate[]> => [
			{ domain: 'owned1.com', ownershipBucket: 'consolidated' },
			{ domain: 'owned2.com', ownershipBucket: 'consolidated' },
			{ domain: 'typo.com', ownershipBucket: 'impersonation' },
		]);

		const { prioritizeCscLeads } = await import('../src/tools/prioritize-csc-leads');
		const report = await prioritizeCscLeads({ brand: 'acme' }, undefined, undefined, { discoverPortfolio });

		expect(report.brand).toBe('acme');
		expect(report.totalDomains).toBe(3);
		const typo = report.rankedLeads.find((l) => l.domain === 'typo.com')!;
		const owned = report.rankedLeads.find((l) => l.domain === 'owned1.com')!;
		// identical reports → owned (×1.0) outranks typo (×0.3)
		expect(typo.gapSeverity).toBeLessThan(owned.gapSeverity);
		expect(typo.ownershipBucket).toBe('impersonation');
	});

	it('discovery yielding no candidates → rankedLeads [] + a discovery_incomplete skipped note; report.brand set', async () => {
		const discoverPortfolio = vi.fn(async (): Promise<DiscoveredCandidate[]> => []);
		const { prioritizeCscLeads } = await import('../src/tools/prioritize-csc-leads');
		const report = await prioritizeCscLeads({ brand: 'empty' }, undefined, undefined, { discoverPortfolio });

		expect(report.brand).toBe('empty');
		expect(report.rankedLeads).toEqual([]);
		expect(report.summary.skipped.some((s) => s.reason === 'discovery_incomplete')).toBe(true);
	});
});
