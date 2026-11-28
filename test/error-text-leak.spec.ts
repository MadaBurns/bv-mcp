// SPDX-License-Identifier: BUSL-1.1

/**
 * Internal database / queue / scan failures must never reach the caller as raw
 * error text. Each case injects an error carrying a marker string and asserts the
 * marker is absent from the returned result, while the detail is still logged.
 */

import { describe, it, expect, vi, afterEach } from 'vitest';

const MARKER = 'LEAKMARKER_internal_detail_9f3a';

afterEach(() => vi.restoreAllMocks());

function makeDb(on: 'run' | 'first' | 'none'): D1Database {
	const fail = async () => {
		throw new Error(MARKER);
	};
	return {
		prepare() {
			const stmt: Record<string, unknown> = {
				bind: () => stmt,
				run: on === 'run' ? fail : async () => ({ success: true, meta: {} }),
				first: on === 'first' ? fail : async () => null,
				all: async () => ({ results: [], success: true, meta: {} }),
			};
			return stmt;
		},
	} as unknown as D1Database;
}

function expectNoLeak(value: unknown) {
	expect(JSON.stringify(value)).not.toContain(MARKER);
}

function logSpy() {
	return vi.spyOn(console, 'log').mockImplementation(() => undefined);
}

function logged(spy: ReturnType<typeof logSpy>) {
	return spy.mock.calls.some((c) => JSON.stringify(c).includes(MARKER));
}

describe('error text allowlist: internal failures', () => {
	it('brand_audit_batch_start: persistence failure', async () => {
		const spy = logSpy();
		const { brandAuditBatchStart } = await import('../src/tools/brand-audit-batch-start');
		const result = await brandAuditBatchStart(['example.com'], {}, 'pk', {
			db: makeDb('run'),
			queue: { send: vi.fn() },
		} as never);
		expectNoLeak(result);
		expect(logged(spy)).toBe(true);
	});

	it('brand_audit_batch_start: enqueue failure', async () => {
		const spy = logSpy();
		const { brandAuditBatchStart } = await import('../src/tools/brand-audit-batch-start');
		const result = await brandAuditBatchStart(['example.com'], {}, 'pk', {
			db: makeDb('none'),
			queue: { send: vi.fn().mockRejectedValue(new Error(MARKER)) },
		} as never);
		expectNoLeak(result);
		expect(logged(spy)).toBe(true);
	});

	it('register_brand_audit_watch: persistence failure', async () => {
		const spy = logSpy();
		const { registerBrandAuditWatch } = await import('../src/tools/brand-audit-watch');
		const result = await registerBrandAuditWatch({ domain: 'example.com', interval: 'daily' }, 'pk', { db: makeDb('run') } as never);
		expectNoLeak(result);
		expect(logged(spy)).toBe(true);
	});

	it('brand_audit_status: read failure', async () => {
		const spy = logSpy();
		const { brandAuditStatus } = await import('../src/tools/brand-audit-status');
		const result = await brandAuditStatus('audit-1', 'pk', { db: makeDb('first') } as never);
		expectNoLeak(result);
		expect(logged(spy)).toBe(true);
	});

	it('discover_brand_domains_start: persistence and enqueue failures', async () => {
		const spy = logSpy();
		const { discoverBrandDomainsStart } = await import('../src/tools/discover-brand-domains-start');
		const persist = await discoverBrandDomainsStart('example.com', {}, 'pk', {
			db: makeDb('run'),
			queue: { send: vi.fn() },
		} as never);
		expectNoLeak(persist);
		const enqueue = await discoverBrandDomainsStart('example.com', {}, 'pk', {
			db: makeDb('none'),
			queue: { send: vi.fn().mockRejectedValue(new Error(MARKER)) },
		} as never);
		expectNoLeak(enqueue);
		expect(logged(spy)).toBe(true);
	});

	it('batch_scan: scan failure', async () => {
		const spy = logSpy();
		const { batchScan } = await import('../src/tools/batch-scan');
		const results = await batchScan(['example.com'], {
			scanFn: (async () => {
				throw new Error(MARKER);
			}) as never,
		});
		expectNoLeak(results);
		expect(logged(spy)).toBe(true);
	});

	it('compare_domains: scan failure', async () => {
		const spy = logSpy();
		const { compareDomains } = await import('../src/tools/compare-domains');
		const result = await compareDomains(['example.com', 'example.org'], {
			scanFn: (async () => {
				throw new Error(MARKER);
			}) as never,
		});
		expectNoLeak(result);
		expect(logged(spy)).toBe(true);
	});

	it('async batch scan: stored job error', async () => {
		const spy = logSpy();
		const store = new Map<string, string>();
		const kv = {
			get: async (k: string, type?: string) => {
				const v = store.get(k) ?? null;
				return type === 'json' && v ? JSON.parse(v) : v;
			},
			put: async (k: string, v: string) => void store.set(k, v),
			delete: async (k: string) => void store.delete(k),
		} as unknown as KVNamespace;
		const { startAsyncBatchScan, processAsyncBatchMessage, getAsyncBatchJob } = await import('../src/tools/batch-scan-async');
		const job = await startAsyncBatchScan({ domains: ['example.com'], idempotencyKey: 'leak-key-1' }, 'principal-a', {
			kv,
			queue: { send: async () => undefined },
		});
		await processAsyncBatchMessage(
			{ version: 1, jobId: job.jobId, principalId: 'principal-a' },
			{
				kv,
				runBatchScan: (async () => {
					throw new Error(MARKER);
				}) as never,
			},
		);
		expectNoLeak(await getAsyncBatchJob(job.jobId, 'principal-a', kv));
		expect(logged(spy)).toBe(true);
	});
});
