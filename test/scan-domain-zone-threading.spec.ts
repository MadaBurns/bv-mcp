// SPDX-License-Identifier: BUSL-1.1

/**
 * Task 2 wiring proof: `resolveZoneApex` is computed ONCE per scan in
 * `scanDomain()` and threaded as the 5th `CheckRunner` arg into the
 * ns/caa/dnssec/mta_sts dispatch closures (and forwarded from there into the
 * four worker wrappers). The package check bodies still IGNORE `zone` at this
 * step (Tasks 3-6 consume it) — so this test does not assert any behavior
 * change. It proves the plumbing compiles and actually executes: a non-apex
 * scan target with no NS records of its own forces `resolveZoneApex` to walk
 * up to the registrable-domain ancestor that does own an NS RRset, which is
 * only observable if the zone-apex resolution genuinely ran.
 */

import { describe, it, expect, afterEach, beforeEach, vi } from 'vitest';
import { setupFetchMock, createDohResponse, txtResponse, nsResponse, caaResponse, dnssecResponse, httpResponse } from './helpers/dns-mock';
import { IN_MEMORY_CACHE } from '../src/lib/cache';

const { restore } = setupFetchMock();

beforeEach(() => IN_MEMORY_CACHE.clear());
afterEach(() => restore());

/**
 * Multi-dispatch fetch mock mirroring `test/scan-domain.spec.ts`'s
 * `mockAllChecks`, with one deliberate difference: the NS branch returns
 * records ONLY for `example.com` (the registrable floor), never for the
 * scanned subdomain `sub.example.com`. That forces `resolveZoneApex`'s
 * ancestor walk to fire — the observable proof that it ran at all.
 */
function mockAllChecksWithNsWalk(nsQueryNames: Set<string>) {
	globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

		if (url.includes('cloudflare-dns.com')) {
			const name = new URL(url).searchParams.get('name') ?? '';

			if (url.includes('type=NS')) {
				nsQueryNames.add(name);
				if (name === 'example.com') {
					return Promise.resolve(nsResponse('example.com', ['ns1.example.com.', 'ns2.example.com.']));
				}
				// The subdomain owns no NS of its own — empty NOERROR answer.
				return Promise.resolve(createDohResponse([{ name, type: 2 }], []));
			}

			if (url.includes('type=TXT')) {
				if (url.includes('_dmarc.')) return Promise.resolve(txtResponse('_dmarc.sub.example.com', ['v=DMARC1; p=reject']));
				if (url.includes('_domainkey.'))
					return Promise.resolve(txtResponse('default._domainkey.sub.example.com', ['v=DKIM1; k=rsa; p=MIGf']));
				if (url.includes('_mta-sts.')) return Promise.resolve(txtResponse('_mta-sts.sub.example.com', ['v=STSv1; id=20240101']));
				if (url.includes('_smtp._tls.'))
					return Promise.resolve(txtResponse('_smtp._tls.sub.example.com', ['v=TLSRPTv1; rua=mailto:tls@example.com']));
				if (url.includes('default._bimi.'))
					return Promise.resolve(txtResponse('default._bimi.sub.example.com', ['v=BIMI1; l=https://sub.example.com/logo.svg']));
				return Promise.resolve(txtResponse('sub.example.com', ['v=spf1 include:_spf.google.com -all']));
			}

			if (url.includes('type=CAA')) {
				return Promise.resolve(caaResponse('sub.example.com', ['0 issue "letsencrypt.org"']));
			}

			if (url.includes('type=A')) {
				return Promise.resolve(dnssecResponse('sub.example.com', true));
			}

			return Promise.resolve(createDohResponse([], []));
		}

		if (url.includes('mta-sts.') && url.includes('.well-known')) {
			return Promise.resolve(httpResponse('version: STSv1\nmode: enforce\nmx: *.sub.example.com\nmax_age: 86400'));
		}

		return Promise.resolve(httpResponse('OK'));
	});
}

describe('scan-domain zone threading (Task 2 no-op wiring)', () => {
	it('resolves the zone apex once per scan and threads it into ns/caa/dnssec/mta_sts without breaking the scan', async () => {
		const nsQueryNames = new Set<string>();
		mockAllChecksWithNsWalk(nsQueryNames);

		const { scanDomain } = await import('../src/tools/scan-domain');
		const result = await scanDomain('sub.example.com');

		// The wiring path executes end-to-end — the scan completes and each
		// zone-sensitive check produced a result (no throw from the new 5th
		// CheckRunner arg or the wrapper signature changes).
		expect(result.domain).toBe('sub.example.com');
		for (const category of ['ns', 'caa', 'dnssec', 'mta_sts'] as const) {
			const check = result.checks.find((c) => c.category === category);
			expect(check, `expected a ${category} check result`).toBeDefined();
		}

		// Observable proof resolveZoneApex actually ran: it walked from the
		// non-apex scanned label (no NS of its own) up to the registrable-domain
		// ancestor that owns an NS RRset. Without the Step 3(c) `zone` computation
		// in scanDomain(), only 'sub.example.com' would ever be NS-queried (the
		// apex short-circuit probe, reused by the ns check via the shared cache).
		expect(nsQueryNames.has('sub.example.com')).toBe(true);
		expect(nsQueryNames.has('example.com')).toBe(true);
	});
});
