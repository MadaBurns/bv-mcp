// Analytics gap (2026-05-09): scan_domain dispatched a tool_call event without
// `cacheStatus`, leaving blob8 = 'n/a' in Analytics Engine. The orchestrator DOES
// have a top-level `cache:<domain>` lookup (scan-domain.ts:187) that returns
// `{ ...cached, cached: true }` on hit — we just weren't threading that flag
// through to the analytics emit. As a result, the cache-effectiveness query in
// .dev/analytics-30d.mjs reported 0% hit rate for the highest-volume tool.
//
// Fix: pass `cacheStatus: result.cached ? 'hit' : 'miss'` from the scan_domain
// dispatch case in handlers/tools.ts.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { setupFetchMock, txtResponse, nsResponse, caaResponse, dnssecResponse, httpResponse, createDohResponse } from './helpers/dns-mock';
import { IN_MEMORY_CACHE } from '../src/lib/cache';

const { restore } = setupFetchMock();

// Same liberal DNS mock used in test/handlers-tools.spec.ts — every record type
// returns plausible content so `scan_domain` completes successfully on a cold path.
function mockAllChecks() {
	globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
		if (url.includes('cloudflare-dns.com')) {
			// Generic TXT response — scan_domain only needs the orchestrator path
			// to complete; per-check correctness isn't under test here. The DKIM/
			// DMARC/MTA-STS branches are intentionally omitted; their absence still
			// lets the orchestrator finish (each leaf check just emits a missing-
			// control finding). What we're asserting is the cacheStatus dimension.
			if (url.includes('type=TXT') || url.includes('type=16')) {
				return Promise.resolve(txtResponse('example.com', ['v=spf1 -all']));
			}
			if (url.includes('type=NS')) return Promise.resolve(nsResponse('example.com', ['ns1.example.com.']));
			if (url.includes('type=CAA')) return Promise.resolve(caaResponse('example.com', ['0 issue "letsencrypt.org"']));
			if (url.includes('type=A')) return Promise.resolve(dnssecResponse('example.com', true));
			return Promise.resolve(createDohResponse([], []));
		}
		if (url.includes('mta-sts.') && url.includes('.well-known')) {
			return Promise.resolve(httpResponse('version: STSv1\nmode: enforce\nmx: *.example.com\nmax_age: 86400'));
		}
		return Promise.resolve(httpResponse('OK'));
	});
}

interface CapturedEvent {
	toolName: string;
	cacheStatus?: 'hit' | 'miss' | 'n/a';
	[k: string]: unknown;
}

function makeAnalyticsCapture(): { client: import('../src/lib/analytics').AnalyticsClient; events: CapturedEvent[] } {
	const events: CapturedEvent[] = [];
	const client = {
		enabled: true,
		emitRequestEvent: () => {},
		emitToolEvent: (evt: CapturedEvent) => events.push(evt),
		emitRateLimitEvent: () => {},
		emitSessionEvent: () => {},
		emitDegradationEvent: () => {},
	} as unknown as import('../src/lib/analytics').AnalyticsClient;
	return { client, events };
}

beforeEach(() => {
	mockAllChecks();
	IN_MEMORY_CACHE.clear();
});

afterEach(() => {
	restore();
	vi.restoreAllMocks();
	IN_MEMORY_CACHE.clear();
});

describe('scan_domain → tool_call analytics event', () => {
	it('emits cacheStatus="miss" on a cold call', async () => {
		const { handleToolsCall } = await import('../src/handlers/tools');
		const { client, events } = makeAnalyticsCapture();
		await handleToolsCall(
			{ name: 'scan_domain', arguments: { domain: 'cold.example.com' } },
			undefined,
			{ analytics: client },
		);
		const scanEvents = events.filter((e) => e.toolName === 'scan_domain');
		expect(scanEvents).toHaveLength(1);
		expect(scanEvents[0].cacheStatus).toBe('miss');
	});

	it('emits cacheStatus="hit" on the second call (cache primed)', async () => {
		const { handleToolsCall } = await import('../src/handlers/tools');
		const { client, events } = makeAnalyticsCapture();
		// First call primes the in-memory cache for cache:<domain>.
		await handleToolsCall(
			{ name: 'scan_domain', arguments: { domain: 'warm.example.com' } },
			undefined,
			{ analytics: client },
		);
		events.length = 0;
		// Second call should hit the cache and emit cacheStatus='hit'.
		await handleToolsCall(
			{ name: 'scan_domain', arguments: { domain: 'warm.example.com' } },
			undefined,
			{ analytics: client },
		);
		const scanEvents = events.filter((e) => e.toolName === 'scan_domain');
		expect(scanEvents).toHaveLength(1);
		expect(scanEvents[0].cacheStatus).toBe('hit');
	});

	it('emits cacheStatus="miss" when force_refresh bypasses the cache', async () => {
		const { handleToolsCall } = await import('../src/handlers/tools');
		const { client, events } = makeAnalyticsCapture();
		// Prime cache.
		await handleToolsCall(
			{ name: 'scan_domain', arguments: { domain: 'forced.example.com' } },
			undefined,
			{ analytics: client },
		);
		events.length = 0;
		// force_refresh skips cache → must report 'miss', not 'hit'.
		await handleToolsCall(
			{ name: 'scan_domain', arguments: { domain: 'forced.example.com', force_refresh: true } },
			undefined,
			{ analytics: client },
		);
		const scanEvents = events.filter((e) => e.toolName === 'scan_domain');
		expect(scanEvents).toHaveLength(1);
		expect(scanEvents[0].cacheStatus).toBe('miss');
	});
});
