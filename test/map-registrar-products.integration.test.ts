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

describe('mapRegistrarProducts — concurrency', () => {
	it('runs scan and RDAP in parallel (total ≈ max(delays), not sum)', async () => {
		const DELAY_MS = 40;
		mockScanDomain.mockImplementation(
			() =>
				new Promise<{ checks: never[]; score: { overall: number; grade: string } }>((r) =>
					setTimeout(() => r({ checks: [], score: { overall: 90, grade: 'A' } }), DELAY_MS),
				),
		);
		mockCheckRdap.mockImplementation(() => new Promise<CheckResult>((r) => setTimeout(() => r(rdapFailed()), DELAY_MS)));

		const { mapRegistrarProducts } = await import('../src/tools/map-registrar-products');
		const t0 = Date.now();
		await mapRegistrarProducts('parallel.com');
		const elapsed = Date.now() - t0;

		// Sequential (await scan THEN rdap) would be ≥ 2 × DELAY_MS ≈ 80ms.
		// Parallel: both calls start before either resolves → elapsed ≈ DELAY_MS.
		// Allow generous slack (×1.7) for CI scheduler jitter.
		expect(elapsed).toBeLessThan(DELAY_MS * 1.7);
	});
});

describe('mapRegistrarProducts — wiring', () => {
	it('unlocked RDAP + failing DMARC + passing SSL/DNSSEC → registry lock high + Managed DMARC; count 2', async () => {
		mockScanDomain.mockResolvedValue({
			checks: [check('dmarc', false, [{ title: 'No DMARC record', severity: 'high' }]), check('ssl', true), check('dnssec', true)],
			score: { overall: 55, grade: 'F' },
		});
		mockCheckRdap.mockResolvedValue(rdapWithPosture({ level: 'unlocked', transferLocked: false, deleteLocked: false, updateLocked: false, registryLevel: false, registrarLevel: false }));

		const { mapRegistrarProducts } = await import('../src/tools/map-registrar-products');
		const report = await mapRegistrarProducts('unlocked.com');

		const registryLock = report.recommendations.find((r) => r.product === 'registry_lock')!;
		const dmarc = report.recommendations.find((r) => r.product === 'managed_dmarc')!;
		expect(registryLock.recommended).toBe(true);
		expect(registryLock.priority).toBe('high');
		expect(dmarc.recommended).toBe(true);
		expect(report.recommendations.find((r) => r.product === 'digital_certificates')!.recommended).toBe(false);
		expect(report.recommendations.find((r) => r.product === 'dnssec_management')!.recommended).toBe(false);
		expect(report.recommendedCount).toBe(2);
		expect(report.domain).toBe('unlocked.com');
		expect(report.score).toBe(55);
		expect(report.grade).toBe('F');
	});

	it('RDAP lookup_failed isolates the registry lock line — scan-driven products still evaluate', async () => {
		mockScanDomain.mockResolvedValue({
			checks: [check('dmarc', false, [{ title: 'No DMARC record', severity: 'high' }]), check('ssl', false, [{ title: 'Cert expired', severity: 'high' }]), check('dnssec', true)],
			score: { overall: 40, grade: 'F' },
		});
		mockCheckRdap.mockResolvedValue(rdapFailed());

		const { mapRegistrarProducts } = await import('../src/tools/map-registrar-products');
		const report = await mapRegistrarProducts('failrdap.com');

		expect(report.lockPosture).toBeNull();
		expect(report.recommendations.find((r) => r.product === 'registry_lock')!.recommended).toBe(false);
		expect(report.recommendations.find((r) => r.product === 'managed_dmarc')!.recommended).toBe(true);
		expect(report.recommendations.find((r) => r.product === 'digital_certificates')!.recommended).toBe(true);
	});
});

// #962: mapRegistrarProducts threaded scanResult.score.grade — the INTERNAL 9-band
// scale — straight into the report, so a score of 86 (9-band 'B+') printed
// "(B+)" beside a customer-facing rollup that would show the 6-band 'B'
// elsewhere. It must route through displayGradeFor like analyze_drift (#727).
describe('mapRegistrarProducts — customer-facing grade is the 6-band scale (#962)', () => {
	it('score 86 (9-band B+) reports the 6-band letter B, not B+', async () => {
		mockScanDomain.mockResolvedValue({
			checks: [check('dmarc', true), check('ssl', true), check('dnssec', true)],
			score: { overall: 86, grade: 'B+' },
		});
		mockCheckRdap.mockResolvedValue(rdapFailed());

		const { mapRegistrarProducts, formatRegistrarProducts } = await import('../src/tools/map-registrar-products');
		const report = await mapRegistrarProducts('sixband.com');

		expect(report.score).toBe(86);
		expect(report.grade).toBe('B');
		expect(formatRegistrarProducts(report, 'full')).toContain('86/100 (B)');
		expect(formatRegistrarProducts(report, 'full')).not.toContain('(B+)');
	});

	it('an ungraded scan (null score/grade) renders "not measured", never a fabricated letter', async () => {
		mockScanDomain.mockResolvedValue({
			checks: [],
			score: { overall: null, grade: null },
		});
		mockCheckRdap.mockResolvedValue(rdapFailed());

		const { mapRegistrarProducts, formatRegistrarProducts } = await import('../src/tools/map-registrar-products');
		const report = await mapRegistrarProducts('ungraded.com');

		expect(report.grade).toBeNull();
		expect(formatRegistrarProducts(report, 'full')).toContain('not measured');
	});
});
