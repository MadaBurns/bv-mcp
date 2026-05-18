// SPDX-License-Identifier: BUSL-1.1

import { queryDns } from '../../lib/dns-transport';
import type { DohResponse, RecordTypeName } from '../../lib/dns-types';
import { Semaphore } from '../../lib/semaphore';

export type DiscoveryDnsQuery = (name: string, type: RecordTypeName) => Promise<DohResponse>;

export interface DiscoveryDnsContext {
	query: DiscoveryDnsQuery;
	metrics(): { queries: number; cacheHits: number; errors: number };
}

export interface DiscoveryDnsContextOptions {
	maxConcurrent?: number;
	baseQuery?: DiscoveryDnsQuery;
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

	const baseQuery =
		options.baseQuery ??
		((name: string, type: RecordTypeName) => queryDns(name, type, false, { queryCache: transportCache, dnsSemaphore: semaphore }));

	const query: DiscoveryDnsQuery = (name, type) => {
		counters.queries++;
		const normalizedName = normalizeDnsName(name);
		const cacheKey = `${normalizedName}:${type}`;
		const existing = discoveryCache.get(cacheKey);
		if (existing) {
			counters.cacheHits++;
			return existing;
		}

		const runQuery = options.baseQuery ? () => semaphore.run(() => baseQuery(normalizedName, type)) : () => baseQuery(normalizedName, type);
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
