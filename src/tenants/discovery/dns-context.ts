// SPDX-License-Identifier: BUSL-1.1

import { queryDns } from '../../lib/dns-transport';
import type { DohResponse, RecordTypeName } from '../../lib/dns-types';
import { Semaphore } from '../../lib/semaphore';

export type DiscoveryDnsQuery = (
	name: string,
	type: RecordTypeName,
	opts?: { signal?: AbortSignal },
) => Promise<DohResponse>;

export interface DiscoveryDnsContext {
	query: DiscoveryDnsQuery;
	metrics(): { queries: number; cacheHits: number; errors: number };
}

export interface DiscoveryDnsContextOptions {
	maxConcurrent?: number;
	baseQuery?: DiscoveryDnsQuery;
	/**
	 * Caller-supplied abort signal forwarded into every `baseQuery` call so the
	 * underlying `queryDns` → `fetch` chain can be cancelled when the audit
	 * budget fires. Once the context holds a signal, every probe inherits
	 * cancellation without per-probe code changes.
	 */
	signal?: AbortSignal;
}

export function createDiscoveryDnsContext(options: DiscoveryDnsContextOptions = {}): DiscoveryDnsContext {
	const discoveryCache = new Map<string, Promise<DohResponse>>();
	const transportCache = new Map<string, Promise<DohResponse>>();
	const semaphore = new Semaphore(normalizeMaxConcurrent(options.maxConcurrent));
	const counters = {
		queries: 0,
		cacheHits: 0,
		errors: 0,
	};
	const contextSignal = options.signal;

	const baseQuery =
		options.baseQuery ??
		((name: string, type: RecordTypeName, opts?: { signal?: AbortSignal }) =>
			queryDns(name, type, false, { queryCache: transportCache, dnsSemaphore: semaphore, signal: opts?.signal }));

	const query: DiscoveryDnsQuery = (name, type) => {
		counters.queries++;
		// Fast-fail when the context signal is already aborted — saves a wasted
		// fetch on every probe call after the audit budget has fired.
		if (contextSignal?.aborted) {
			counters.errors++;
			return Promise.reject(new Error('discovery dns context aborted'));
		}
		const normalizedName = normalizeDnsName(name);
		const cacheKey = `${normalizedName}:${type}`;
		const existing = discoveryCache.get(cacheKey);
		if (existing) {
			counters.cacheHits++;
			return existing;
		}

		const call = () => baseQuery(normalizedName, type, contextSignal ? { signal: contextSignal } : undefined);
		const runQuery = options.baseQuery ? () => semaphore.run(call) : call;
		const promise = runQuery().catch((err) => {
			counters.errors++;
			discoveryCache.delete(cacheKey);
			throw err;
		});
		discoveryCache.set(cacheKey, promise);
		return promise;
	};

	return {
		query,
		metrics: () => ({ ...counters }),
	};
}

function normalizeDnsName(name: string): string {
	return name.trim().toLowerCase().replace(/\.+$/, '');
}

function normalizeMaxConcurrent(maxConcurrent: number | undefined): number {
	if (maxConcurrent === undefined || !Number.isFinite(maxConcurrent)) return 6;
	return Math.max(1, Math.trunc(maxConcurrent));
}
