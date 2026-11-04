// SPDX-License-Identifier: BUSL-1.1

/**
 * Contract: `scan_domain`'s published `score` IS the `@blackveil/dns-checks`
 * scoring result for the checks it submitted — no worker-side post-scoring
 * adjustment (scoring model 2.0.0 removed the category-interaction penalty layer).
 *
 * The fixture is a mail domain with MX but NO SPF, NO DMARC and NO DKIM — exactly the
 * correlated-weakness shape the deleted layer used to dock (`no_spf_no_dmarc` −10,
 * `no_spf_no_dkim` −5, `weak_dkim_permissive_dmarc` −5). Re-introducing ANY
 * post-scoring subtraction makes `score.overall` diverge from the package output and
 * fails the equality assertions below. A guard assertion confirms the fixture really
 * is in that weak shape, so the equality cannot hold vacuously on a healthy domain.
 */

import { describe, it, expect, afterEach, beforeEach, vi } from 'vitest';
import { computeScanScore, computeProfileAwareScanScore } from '@blackveil/dns-checks/scoring';
import { setupFetchMock, createDohResponse, nsResponse, httpResponse } from './helpers/dns-mock';
import { IN_MEMORY_CACHE } from '../src/lib/cache';

const { restore } = setupFetchMock();

beforeEach(() => IN_MEMORY_CACHE.clear());
afterEach(() => restore());

/** MX present, every TXT lookup (SPF/DMARC/DKIM/...) empty, no CAA, no DNSSEC. */
function mockMailDomainWithNoEmailAuth() {
	globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
		if (!url.includes('cloudflare-dns.com')) return Promise.resolve(httpResponse('OK'));
		if (url.includes('type=MX') || url.includes('type=15')) {
			return Promise.resolve(
				createDohResponse([{ name: 'example.com', type: 15 }], [{ name: 'example.com', type: 15, TTL: 300, data: '10 mail.example.com.' }]),
			);
		}
		if (url.includes('type=NS') || url.includes('type=2')) {
			return Promise.resolve(nsResponse('example.com', ['ns1.example.com.', 'ns2.example.com.']));
		}
		return Promise.resolve(createDohResponse([], []));
	});
}

describe('scan_domain score parity with @blackveil/dns-checks', () => {
	it('reports score.overall and grade equal to the package output for the same submitted checks (weak mail domain)', async () => {
		mockMailDomainWithNoEmailAuth();
		const { scanDomain } = await import('../src/tools/scan-domain');
		const result = await scanDomain('example.com', undefined, { forceRefresh: true });

		// Guard: the fixture is the weak shape the deleted interaction rules targeted.
		expect(result.score.categoryScores.spf).toBe(0);
		expect(result.score.categoryScores.dmarc).toBe(0);
		expect(typeof result.score.overall).toBe('number');

		// Parity with the package for the exact checks + context scan_domain scored.
		const fromPackage = computeScanScore(result.checks, result.context);
		expect(result.score.overall).toBe(fromPackage.overall);
		expect(result.score.grade).toBe(fromPackage.grade);
		expect(result.score.categoryScores).toEqual(fromPackage.categoryScores);

		// And with the package's profile-aware entry point for the same profile.
		const profileAware = computeProfileAwareScanScore(result.checks, { profile: result.context.profile });
		expect(result.score.overall).toBe(profileAware.score.overall);
		expect(result.score.grade).toBe(profileAware.score.grade);
	});

	it('keeps the published interactionEffects field, always empty', async () => {
		mockMailDomainWithNoEmailAuth();
		const { scanDomain } = await import('../src/tools/scan-domain');
		const result = await scanDomain('example.com', undefined, { forceRefresh: true });

		expect(result).toHaveProperty('interactionEffects');
		expect(result.interactionEffects).toEqual([]);
	});
});
