import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { setupFetchMock } from './helpers/dns-mock';

let fetchMock: { restore: () => void };
beforeEach(() => {
	fetchMock = setupFetchMock();
});
afterEach(() => {
	fetchMock?.restore();
	vi.restoreAllMocks();
	vi.resetModules();
});

function makeMessage(body: unknown) {
	return { body, ack: vi.fn(), retry: vi.fn() };
}

describe('handleAnalyticsQueue', () => {
	it('batch-inserts one statement per message and acks each', async () => {
		const { handleAnalyticsQueue } = await import('../src/lib/analytics-queue-consumer');
		const batchFn = vi.fn(async (stmts: unknown[]) => stmts.map(() => ({ success: true })));
		const bind = vi.fn(() => ({}));
		const prepare = vi.fn(() => ({ bind }));
		const db = { prepare, batch: batchFn } as unknown as D1Database;
		const m1 = makeMessage({
			ip: '192.0.2.1',
			ipHash: 'i_a',
			ipMasked: '192.0.2.xxx',
			toolName: 'check_spf',
			domain: 'a.com',
			responseMs: 5,
			rateLimited: false,
			piiLevel: 'coarse',
			country: 'NZ',
			region: null,
			city: null,
			latitude: null,
			longitude: null,
			asn: null,
			asOrg: null,
			ptrHostname: null,
			keyHash: null,
			clientType: null,
			colo: null,
			sessionHash: null,
			userAgent: null,
			method: 'tools/call',
			transport: 'json',
			status: 'pass',
		});
		const batch = { queue: 'mcp-analytics-queue', messages: [m1] } as unknown as MessageBatch<unknown>;

		await handleAnalyticsQueue(batch, { INTELLIGENCE_DB: db });

		expect(batchFn).toHaveBeenCalledTimes(1);
		expect(batchFn.mock.calls[0][0]).toHaveLength(1);
		expect(m1.ack).toHaveBeenCalledTimes(1);
	});

	it('skips PTR at coarse level (no reverse-DNS subrequest)', async () => {
		const { handleAnalyticsQueue } = await import('../src/lib/analytics-queue-consumer');
		const ptr = vi.fn();
		vi.doMock('../src/lib/dns', () => ({ queryPtrRecords: ptr }));
		const db = {
			prepare: () => ({ bind: () => ({}) }),
			batch: vi.fn(async () => [{ success: true }]),
		} as unknown as D1Database;
		const msg = makeMessage({
			ip: '192.0.2.1',
			ipHash: 'i_a',
			ipMasked: '192.0.2.xxx',
			toolName: 't',
			domain: 'a.com',
			responseMs: 1,
			rateLimited: false,
			piiLevel: 'coarse',
			country: null,
			region: null,
			city: null,
			latitude: null,
			longitude: null,
			asn: null,
			asOrg: null,
			ptrHostname: null,
			keyHash: null,
			clientType: null,
			colo: null,
			sessionHash: null,
			userAgent: null,
			method: null,
			transport: null,
			status: null,
		});
		await handleAnalyticsQueue({ queue: 'mcp-analytics-queue', messages: [msg] } as unknown as MessageBatch<unknown>, { INTELLIGENCE_DB: db });
		expect(ptr).not.toHaveBeenCalled();
	});
});
