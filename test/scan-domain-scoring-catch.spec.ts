// SPDX-License-Identifier: BUSL-1.1

/**
 * Defense-in-depth: scanDomain must never throw out a generic error when the
 * scoring path fails. A scoring failure (e.g. the prod "m5 is not defined"
 * ReferenceError from a stale bundle) used to crash the entire scan because the
 * post-processing fallback re-ran the same throwing scoring call with no outer
 * guard. The scan should instead return the check findings with a clear
 * "scoring unavailable" degradation marker.
 *
 * Uses hoisted vi.mock to force the scoring calls to throw, which is required
 * because the Workers pool caches module namespaces. Both the canonical main-path
 * call (computeScanScore) and the catch-block fallback (computeProfileAwareScanScore,
 * which internally delegates to computeScanScore) must be made to throw — in the real
 * "m5 is not defined" failure the underlying engine throws, so every scoring entry
 * point fails together. Mocking only the wrapper would leave the main path succeeding,
 * which can't happen in reality.
 */
import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();

const mockProfileAwareScore = vi.fn();
const mockScanScore = vi.fn();

vi.mock('@blackveil/dns-checks/scoring', async (importOriginal) => {
	const orig = await importOriginal<typeof import('@blackveil/dns-checks/scoring')>();
	return {
		...orig,
		computeScanScore: (...args: unknown[]) => mockScanScore(...args),
		computeProfileAwareScanScore: (...args: unknown[]) => mockProfileAwareScore(...args),
	};
});

function installEmptyDnsFetch() {
	globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
		const url = String(input instanceof Request ? input.url : input);
		// DoH JSON resolvers → empty (no records) answer for every query.
		if (/dns-query|\/resolve|dns-json|dns\.google|cloudflare-dns/.test(url)) {
			return Promise.resolve(createDohResponse([], []));
		}
		// Any other outbound (http_security probe, mta-sts policy, etc.) → benign 200.
		return Promise.resolve(new Response('', { status: 200 }));
	}) as unknown as typeof globalThis.fetch;
}

afterEach(() => {
	restore();
	mockProfileAwareScore.mockReset();
	mockScanScore.mockReset();
	vi.doUnmock('../src/tools/check-mta-sts');
	vi.resetModules();
});

describe('scanDomain — scoring-failure degradation', () => {
	it('returns check findings with a degraded marker instead of throwing when scoring fails', async () => {
		installEmptyDnsFetch();
		// Real "m5 is not defined" stale-bundle failure: the underlying engine throws,
		// so the canonical main-path computeScanScore call AND the catch-block
		// computeProfileAwareScanScore fallback (which delegates to computeScanScore)
		// both throw.
		mockScanScore.mockImplementation(() => {
			throw new ReferenceError('m5 is not defined');
		});
		mockProfileAwareScore.mockImplementation(() => {
			throw new ReferenceError('m5 is not defined');
		});

		const { scanDomain } = await import('../src/tools/scan-domain');

		// Must resolve — not reject — even though every scoring call throws.
		const result = await scanDomain('example.com');

		// Checks ran and their findings are preserved for the operator.
		expect(result.checks.length).toBeGreaterThan(0);

		// Overall score is explicitly marked unavailable (null), not a misleading real 0.
		expect(result.score.grade).toBeNull();
		expect(result.score.overall).toBeNull();
		expect(result.scoringNote).toBeTruthy();
		expect(result.scoringNote!.toLowerCase()).toMatch(/scoring (unavailable|could not)/);

		// Both scoring entry points were exercised: the canonical main-path
		// computeScanScore call and the catch-block computeProfileAwareScanScore fallback.
		expect(mockScanScore).toHaveBeenCalled();
		expect(mockProfileAwareScore).toHaveBeenCalled();
	});

	it('re-applies the degraded error status to a failed check when post-processing throws', async () => {
		// The mta_sts check throws on the first attempt AND on the transient-failure retry, so it stays
		// degraded (safeCheck -> checkStatus 'error', score 0) while every other check completes.
		// resetModules + doMock replaces the check at the module boundary (DNS-level throws are
		// swallowed inside the checks, so they never reach safeCheck's catch).
		vi.resetModules();
		vi.doMock('../src/tools/check-mta-sts', () => ({
			checkMtaSts: vi.fn().mockRejectedValue(new Error('Simulated check failure')),
		}));
		installEmptyDnsFetch();
		mockScanScore.mockImplementation(() => {
			throw new ReferenceError('m5 is not defined');
		});
		mockProfileAwareScore.mockImplementation(() => {
			throw new ReferenceError('m5 is not defined');
		});

		const { scanDomain } = await import('../src/tools/scan-domain');
		const result = await scanDomain('example.com');

		// Post-processing and the scoring fallback both failed: unscored result, findings preserved.
		expect(result.score.overall).toBeNull();
		// The catch block re-applied the degraded status to the failed category only.
		const mtaSts = result.checks.find((check) => check.category === 'mta_sts');
		expect(mtaSts).toMatchObject({ score: 0, passed: false, checkStatus: 'error' });
		const others = result.checks.filter((check) => check.category !== 'mta_sts');
		expect(others.length).toBeGreaterThan(0);
		expect(others.some((check) => check.checkStatus === 'error' || check.checkStatus === 'timeout')).toBe(false);
	});
});
