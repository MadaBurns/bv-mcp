// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, vi, afterEach } from 'vitest';
import type { CheckResult } from '../src/lib/scoring';
import type { LockPosture } from '../src/tools/check-rdap-lookup';

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

function rdapWithPosture(posture: LockPosture): CheckResult {
	return { category: 'rdap', passed: true, score: 100, findings: [{ category: 'rdap', title: 'Registration details', severity: 'info', detail: '', metadata: { lockPosture: posture } } as never] } as CheckResult;
}

function rdapFailed(): CheckResult {
	return { category: 'rdap', passed: false, score: 0, findings: [{ category: 'rdap', title: 'RDAP lookup failed', severity: 'low', detail: '', metadata: { registrarSource: 'lookup_failed' } } as never] } as CheckResult;
}

afterEach(() => {
	mockScanDomain.mockReset();
	mockCheckRdap.mockReset();
});

describe('mapCscProducts — concurrency', () => {
	it('runs scan and RDAP in parallel (total ≈ max(delays), not sum)', async () => {
		const DELAY_MS = 40;
		mockScanDomain.mockImplementation(
			() =>
				new Promise<{ checks: never[]; score: { overall: number; grade: string } }>((r) =>
					setTimeout(() => r({ checks: [], score: { overall: 90, grade: 'A' } }), DELAY_MS),
				),
		);
		mockCheckRdap.mockImplementation(() => new Promise<CheckResult>((r) => setTimeout(() => r(rdapFailed()), DELAY_MS)));

		const { mapCscProducts } = await import('../src/tools/map-csc-products');
		const t0 = Date.now();
		await mapCscProducts('parallel.com');
		const elapsed = Date.now() - t0;

		// Sequential (await scan THEN rdap) would be ≥ 2 × DELAY_MS ≈ 80ms.
		// Parallel: both calls start before either resolves → elapsed ≈ DELAY_MS.
		// Allow generous slack (×1.7) for CI scheduler jitter.
		expect(elapsed).toBeLessThan(DELAY_MS * 1.7);
	});
});

describe('mapCscProducts — wiring', () => {
	it('unlocked RDAP + failing DMARC + passing SSL/DNSSEC → MultiLock high + Managed DMARC; count 2', async () => {
		mockScanDomain.mockResolvedValue({
			checks: [check('dmarc', false, [{ title: 'No DMARC record', severity: 'high' }]), check('ssl', true), check('dnssec', true)],
			score: { overall: 55, grade: 'F' },
		});
		mockCheckRdap.mockResolvedValue(rdapWithPosture({ level: 'unlocked', transferLocked: false, deleteLocked: false, updateLocked: false, registryLevel: false, registrarLevel: false }));

		const { mapCscProducts } = await import('../src/tools/map-csc-products');
		const report = await mapCscProducts('unlocked.com');

		const multilock = report.recommendations.find((r) => r.product === 'csc_multilock')!;
		const dmarc = report.recommendations.find((r) => r.product === 'managed_dmarc')!;
		expect(multilock.recommended).toBe(true);
		expect(multilock.priority).toBe('high');
		expect(dmarc.recommended).toBe(true);
		expect(report.recommendations.find((r) => r.product === 'digital_certificates')!.recommended).toBe(false);
		expect(report.recommendations.find((r) => r.product === 'dnssec_management')!.recommended).toBe(false);
		expect(report.recommendedCount).toBe(2);
		expect(report.domain).toBe('unlocked.com');
		expect(report.score).toBe(55);
		expect(report.grade).toBe('F');
	});

	it('RDAP lookup_failed isolates the MultiLock line — scan-driven products still evaluate', async () => {
		mockScanDomain.mockResolvedValue({
			checks: [check('dmarc', false, [{ title: 'No DMARC record', severity: 'high' }]), check('ssl', false, [{ title: 'Cert expired', severity: 'high' }]), check('dnssec', true)],
			score: { overall: 40, grade: 'F' },
		});
		mockCheckRdap.mockResolvedValue(rdapFailed());

		const { mapCscProducts } = await import('../src/tools/map-csc-products');
		const report = await mapCscProducts('failrdap.com');

		expect(report.lockPosture).toBeNull();
		expect(report.recommendations.find((r) => r.product === 'csc_multilock')!.recommended).toBe(false);
		expect(report.recommendations.find((r) => r.product === 'managed_dmarc')!.recommended).toBe(true);
		expect(report.recommendations.find((r) => r.product === 'digital_certificates')!.recommended).toBe(true);
	});
});
