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

		// Overall score is explicitly marked unavailable, not a misleading real 0.
		expect(result.score.grade).toBe('N/A');
		expect(result.scoringNote).toBeTruthy();
		expect(result.scoringNote!.toLowerCase()).toMatch(/scoring (unavailable|could not)/);

		// Both scoring entry points were exercised: the canonical main-path
		// computeScanScore call and the catch-block computeProfileAwareScanScore fallback.
		expect(mockScanScore).toHaveBeenCalled();
		expect(mockProfileAwareScore).toHaveBeenCalled();
	});
});
