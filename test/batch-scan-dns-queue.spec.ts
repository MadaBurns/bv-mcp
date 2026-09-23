import { describe, it, expect, afterEach, beforeEach, vi } from 'vitest';
import { IN_MEMORY_CACHE } from '../src/lib/cache';
import { setupFetchMock, createDohResponse, txtResponse, nsResponse, caaResponse, dnssecResponse, httpResponse } from './helpers/dns-mock';

/**
 * #952 — batch_scan shares ONE 5-slot DoH semaphore across its concurrent scans.
 * Measured before the fix (real scanDomain, 3 domains, ~118 DoH queries per scan,
 * default 8s per-check / 15s scan budgets): at 150ms DoH latency every single scan
 * measured all 19 categories, while the batch lost 2-4 categories per domain to
 * `checkStatus: 'timeout'` because the per-check clock kept running while the
 * check's queries sat QUEUED on the shared pool. This spec reproduces that on a
 * compressed timeline (10ms latency, 375ms per-check budget — SQ-162 lowered
 * these from 40ms/1.5s, same ~1:37.5 ratio, after confirming the negative
 * control still times out 5-14 of 19 categories per domain at this scale) so
 * it stays fast.
 */

const { restore } = setupFetchMock();
beforeEach(() => IN_MEMORY_CACHE.clear());
afterEach(() => restore());

const LATENCY_MS = 10;
const PER_CHECK_TIMEOUT_MS = 375;

function mockSlowDoh() {
	globalThis.fetch = vi.fn().mockImplementation(async (input: string | URL | Request) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
		if (!url.includes('cloudflare-dns.com')) return httpResponse('OK');
		const name = decodeURIComponent(/name=([^&]+)/.exec(url)?.[1] ?? '');
		const domain = name.split('.').slice(-2).join('.');
		await new Promise((resolve) => setTimeout(resolve, LATENCY_MS));
		if (url.includes('type=TXT')) {
			if (url.includes('_dmarc.')) return txtResponse(`_dmarc.${domain}`, ['v=DMARC1; p=reject']);
			if (url.includes('_domainkey.')) return txtResponse(`default._domainkey.${domain}`, ['v=DKIM1; k=rsa; p=MIGf']);
			return txtResponse(domain, ['v=spf1 -all']);
		}
		if (url.includes('type=NS')) return nsResponse(domain, [`ns1.${domain}.`, `ns2.${domain}.`]);
		if (url.includes('type=CAA')) return caaResponse(domain, ['0 issue "letsencrypt.org"']);
		if (url.includes('type=A')) return dnssecResponse(domain, true);
		return createDohResponse([], []);
	});
}

function degraded(statuses: Record<string, string>): string[] {
	return Object.entries(statuses)
		.filter(([, status]) => status !== 'completed')
		.map(([category, status]) => `${category}:${status}`);
}

describe('batch_scan shared DNS pool (#952)', () => {
	it('does not time out checks on semaphore queueing that a single scan measures fine', { timeout: 60_000 }, async () => {
		const { batchScan } = await import('../src/tools/batch-scan');
		const { scanDomain } = await import('../src/tools/scan-domain');
		const runtimeOptions = { perCheckTimeoutMs: PER_CHECK_TIMEOUT_MS };
		mockSlowDoh();

		// Control: the same domain, same latency, same budget, scanned alone.
		const single = await scanDomain('example.com', undefined, { ...runtimeOptions, forceRefresh: true });
		expect(single.checks.filter((c) => c.checkStatus === 'timeout' || c.checkStatus === 'error').map((c) => c.category)).toEqual([]);

		IN_MEMORY_CACHE.clear();
		const batch = await batchScan(['example.com', 'example.net', 'example.org'], { force_refresh: true, concurrency: 3, runtimeOptions });
		expect(batch.map((item) => degraded(item.checkStatuses))).toEqual([[], [], []]);
		expect(batch.map((item) => item.inconclusiveCategories)).toEqual([[], [], []]);
	});
});

describe('Semaphore.saturatedMs', () => {
	it('accrues only while a caller is queued', async () => {
		const { Semaphore } = await import('../src/lib/semaphore');
		const sem = new Semaphore(1);
		const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

		await sem.run(() => sleep(50));
		expect(sem.saturatedMs()).toBe(0);

		await Promise.all([sem.run(() => sleep(100)), sem.run(() => sleep(100))]);
		const queued = sem.saturatedMs();
		expect(queued).toBeGreaterThanOrEqual(80);
		expect(queued).toBeLessThan(180);

		await sem.run(() => sleep(50));
		expect(sem.saturatedMs()).toBe(queued);
	});

	it('stops accruing when the only queued caller aborts', async () => {
		const { Semaphore } = await import('../src/lib/semaphore');
		const sem = new Semaphore(1);
		const release = await sem.acquire();
		const controller = new AbortController();
		const waiting = sem.acquire(controller.signal).catch(() => undefined);
		await new Promise((resolve) => setTimeout(resolve, 30));
		controller.abort();
		await waiting;
		const atAbort = sem.saturatedMs();
		await new Promise((resolve) => setTimeout(resolve, 50));
		expect(sem.saturatedMs()).toBe(atAbort);
		release();
	});
});
