// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, afterEach, beforeEach, vi } from 'vitest';
import { IN_MEMORY_CACHE } from '../src/lib/cache';
import { setupFetchMock, createDohResponse, txtResponse, nsResponse, caaResponse, dnssecResponse, httpResponse } from './helpers/dns-mock';

/**
 * #952/SQ-15 repair — the queue-clock extension `safeCheck` adds to a check's
 * per-check timer (so DNS-pool queueing isn't charged against it, #952) was
 * originally wired to ALL 19 `CHECK_DISPATCH` entries via one shared
 * `dnsSemaphore.saturatedMs()` closure, including `ssl` and `http_security` —
 * raw-`fetch` checks that ignore `dnsOptions` entirely and never wait on the
 * DNS pool. That let a check UNRELATED to DNS keep its declared timeout
 * unenforced whenever ANY OTHER check in the same scan queued on the shared
 * pool — reproducible on a plain single scan, not just `batch_scan`.
 *
 * This reproduces that on a compressed timeline: `dnsConcurrency: 1` forces
 * every DNS-consuming category to serialize through one slot (guaranteed
 * contention within a single scan), 10ms DoH latency, and `ssl`'s own raw
 * HTTPS fetches mocked at 300ms — well past the 150ms per-check budget.
 *
 * Pre-repair (SQ-11 candidate 110c0f4a3): `ssl` completes despite its own
 * fetch taking 300ms against a 150ms budget, because the shared semaphore's
 * GLOBAL saturation (accrued by the DNS checks queued ahead of it) extended
 * `ssl`'s timer even though `ssl` itself was never queued on that pool.
 * Post-repair: `ssl` times out at its declared budget (restoring the
 * pre-#952 behaviour for the one category the fix should never have touched),
 * while the genuinely DNS-queued categories still get #952's extension.
 */

const { restore } = setupFetchMock();
beforeEach(() => IN_MEMORY_CACHE.clear());
afterEach(() => restore());

const DOH_LATENCY_MS = 10;
const RAW_FETCH_LATENCY_MS = 300;
const PER_CHECK_TIMEOUT_MS = 150;

function mockContendedFetch() {
	globalThis.fetch = vi.fn().mockImplementation(async (input: string | URL | Request) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
		if (url.includes('cloudflare-dns.com')) {
			const name = decodeURIComponent(/name=([^&]+)/.exec(url)?.[1] ?? '');
			const domain = name.split('.').slice(-2).join('.');
			await new Promise((resolve) => setTimeout(resolve, DOH_LATENCY_MS));
			if (url.includes('type=TXT')) {
				if (url.includes('_dmarc.')) return txtResponse(`_dmarc.${domain}`, ['v=DMARC1; p=reject']);
				if (url.includes('_domainkey.')) return txtResponse(`default._domainkey.${domain}`, ['v=DKIM1; k=rsa; p=MIGf']);
				return txtResponse(domain, ['v=spf1 -all']);
			}
			if (url.includes('type=NS')) return nsResponse(domain, [`ns1.${domain}.`, `ns2.${domain}.`]);
			if (url.includes('type=CAA')) return caaResponse(domain, ['0 issue "letsencrypt.org"']);
			if (url.includes('type=A')) return dnssecResponse(domain, true);
			return createDohResponse([], []);
		}
		// `ssl`/`http_security`'s own raw-fetch legs (robots.txt, https://, http://) —
		// never routed through dnsSemaphore, so they must never be extended by it.
		await new Promise((resolve) => setTimeout(resolve, RAW_FETCH_LATENCY_MS));
		return httpResponse('OK');
	});
}

describe('safeCheck queue-clock scope (#952/SQ-15)', () => {
	it('still enforces the ssl per-check budget under DNS-pool contention', { timeout: 30_000 }, async () => {
		const { scanDomain } = await import('../src/tools/scan-domain');
		mockContendedFetch();

		const result = await scanDomain('example.com', undefined, {
			dnsConcurrency: 1,
			perCheckTimeoutMs: PER_CHECK_TIMEOUT_MS,
			scanTimeoutMs: 10_000,
			forceRefresh: true,
		});

		const byCategory = new Map(result.checks.map((c) => [c.category, c]));
		// The defect: ssl (never queues on the DNS pool) must still time out at its
		// own declared budget, not be extended by unrelated checks' pool queueing.
		expect(byCategory.get('ssl')?.checkStatus).toBe('timeout');
		// The #952 fix must still hold for checks that DO share the DNS pool: with
		// dnsConcurrency:1 forcing serialization, at least one DNS-based category
		// would have dropped to 'timeout' pre-#952 purely from queueing, not from
		// slow work of its own. Confirm the extension still applies to a DNS check.
		expect(byCategory.get('dkim')?.checkStatus).not.toBe('timeout');
	});
});
