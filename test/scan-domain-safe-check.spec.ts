import { describe, it, expect, afterEach, beforeEach, vi } from 'vitest';
import { setupFetchMock, txtResponse, nsResponse, caaResponse, dnssecResponse, httpResponse } from './helpers/dns-mock';
import { IN_MEMORY_CACHE } from '../src/lib/cache';
import { createDohResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();

beforeEach(() => IN_MEMORY_CACHE.clear());
afterEach(() => restore());

/**
 * Minimal fetch mock that returns healthy defaults for all check types.
 * Identical to the one in scan-domain.spec.ts.
 */
function mockAllChecks() {
	globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

		if (url.includes('cloudflare-dns.com')) {
			if (url.includes('type=TXT') || url.includes('type=16')) {
				if (url.includes('_dmarc.')) {
					return Promise.resolve(txtResponse('_dmarc.example.com', ['v=DMARC1; p=reject']));
				}
				if (url.includes('_domainkey.')) {
					return Promise.resolve(txtResponse('default._domainkey.example.com', ['v=DKIM1; k=rsa; p=MIGf']));
				}
				if (url.includes('_mta-sts.')) {
					return Promise.resolve(txtResponse('_mta-sts.example.com', ['v=STSv1; id=20240101']));
				}
				if (url.includes('_smtp._tls.')) {
					return Promise.resolve(txtResponse('_smtp._tls.example.com', ['v=TLSRPTv1; rua=mailto:tls@example.com']));
				}
				if (url.includes('default._bimi.')) {
					return Promise.resolve(txtResponse('default._bimi.example.com', ['v=BIMI1; l=https://example.com/logo.svg']));
				}
				return Promise.resolve(txtResponse('example.com', ['v=spf1 include:_spf.google.com -all']));
			}

			if (url.includes('type=NS') || url.includes('type=2')) {
				return Promise.resolve(nsResponse('example.com', ['ns1.example.com.', 'ns2.example.com.']));
			}

			if (url.includes('type=CAA') || url.includes('type=257')) {
				return Promise.resolve(caaResponse('example.com', ['0 issue "letsencrypt.org"']));
			}

			if (url.includes('type=A') || url.includes('type=1')) {
				return Promise.resolve(dnssecResponse('example.com', true));
			}

			return Promise.resolve(createDohResponse([], []));
		}

		if (url.includes('mta-sts.') && url.includes('.well-known')) {
			return Promise.resolve(httpResponse('version: STSv1\nmode: enforce\nmx: *.example.com\nmax_age: 86400'));
		}

		if (url.startsWith('https://')) {
			return Promise.resolve(httpResponse('OK'));
		}

		return Promise.resolve(httpResponse('OK'));
	});
}

describe('safeCheck error handling', () => {
	afterEach(() => {
		vi.doUnmock('../src/tools/check-mta-sts');
		vi.resetModules();
	});

	it('should return score 0 when a check throws an error', async () => {
		// Force the mta-sts check module itself to throw so safeCheck's catch block fires.
		// DNS-level throws are caught internally by check functions, so we mock at the
		// module boundary instead.
		// vi.resetModules() clears the module registry so scan-domain re-resolves its
		// static imports, picking up the vi.doMock replacement for check-mta-sts.
		vi.resetModules();
		vi.doMock('../src/tools/check-mta-sts', () => ({
			checkMtaSts: vi.fn().mockRejectedValue(new Error('Simulated check failure')),
		}));
		mockAllChecks();
		const { scanDomain } = await import('../src/tools/scan-domain');
		const result = await scanDomain('example.com');

		const mtaSts = result.checks.find((c) => c.category === 'mta_sts');
		expect(mtaSts).toBeDefined();
		expect(mtaSts!.score).toBe(0);
		expect(mtaSts!.checkStatus).toBe('error');
	});
});

describe('scan-domain retry acceptance (SQ-71 regression)', () => {
	afterEach(() => {
		vi.doUnmock('../src/tools/check-mta-sts');
		vi.resetModules();
	});

	it('accepts a retry that correctly measures a genuine absence (score 0), not just score > 0', async () => {
		// First attempt throws (safeCheck's catch -> checkStatus:'error', score:0, shouldRetry() fires).
		// The retry itself succeeds and genuinely measures the control absent (missingControl -> score 0,
		// checkStatus 'completed'/undefined) -- the better measurement, and must replace the transient
		// error rather than being discarded by a `score > 0` gate.
		vi.resetModules();
		const { buildCheckResult, createFinding } = await import('../src/lib/scoring');
		const genuineAbsence = buildCheckResult('mta_sts', [
			createFinding('mta_sts', 'MTA-STS not configured', 'high', 'No MTA-STS policy was published for example.com.', { missingControl: true }),
		]);
		vi.doMock('../src/tools/check-mta-sts', () => ({
			checkMtaSts: vi
				.fn()
				.mockRejectedValueOnce(new Error('Simulated transient check failure'))
				.mockResolvedValue(genuineAbsence),
		}));
		mockAllChecks();
		const { scanDomain } = await import('../src/tools/scan-domain');
		const result = await scanDomain('example.com');

		const mtaSts = result.checks.find((c) => c.category === 'mta_sts');
		expect(mtaSts).toBeDefined();
		// The retry's real measurement won -- not the discarded transient error.
		expect(mtaSts!.score).toBe(0);
		expect(mtaSts!.checkStatus).not.toBe('error');
		expect(mtaSts!.findings.some((f) => f.title === 'MTA-STS not configured')).toBe(true);
	});
});
