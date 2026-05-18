// SPDX-License-Identifier: BUSL-1.1

/**
 * Phase 2 of the AbortSignal-into-fetch refactor (.dev/abort-signal-plan.md).
 *
 * `createDiscoveryDnsContext({ signal })` must forward the caller's signal into
 * every `baseQuery` call so the underlying `queryDns` can cancel in-flight
 * fetches. Once the context holds a signal, every probe that uses
 * `dnsContext.query(...)` inherits cancellation without per-probe code changes.
 */

import { describe, expect, it, vi } from 'vitest';
import { createDiscoveryDnsContext } from '../src/tenants/discovery/dns-context';
import type { DohResponse, RecordTypeName } from '../src/lib/dns-types';

describe('DiscoveryDnsContext — AbortSignal propagation (Phase 2)', () => {
	it('forwards the context signal into baseQuery on every call', async () => {
		const controller = new AbortController();
		const dohResponse: DohResponse = {
			Status: 0,
			TC: false,
			RD: true,
			RA: true,
			AD: false,
			CD: false,
			Question: [],
			Answer: [],
		};
		const baseQuery = vi.fn(
			async (_name: string, _type: RecordTypeName, opts?: { signal?: AbortSignal }) => {
				// The signal arg is what the context should forward. Assert the
				// caller's signal is the same instance the context received.
				expect(opts?.signal).toBe(controller.signal);
				return dohResponse;
			},
		);

		const ctx = createDiscoveryDnsContext({ baseQuery, signal: controller.signal });
		await ctx.query('example.com', 'A');
		expect(baseQuery).toHaveBeenCalledOnce();
	});

	it('rejects new queries once the context signal aborts', async () => {
		const controller = new AbortController();
		controller.abort();
		const baseQuery = vi.fn(async () => ({}) as DohResponse);
		const ctx = createDiscoveryDnsContext({ baseQuery, signal: controller.signal });

		await expect(ctx.query('example.com', 'A')).rejects.toThrow(/abort/i);
		// Fast-fail: baseQuery should NOT be invoked once the signal is already
		// aborted at call time — saves a wasted fetch.
		expect(baseQuery).not.toHaveBeenCalled();
	});

	it('does not break the no-signal case (back-compat)', async () => {
		const dohResponse: DohResponse = {
			Status: 0,
			TC: false,
			RD: true,
			RA: true,
			AD: false,
			CD: false,
			Question: [],
			Answer: [],
		};
		const baseQuery = vi.fn(async () => dohResponse);
		const ctx = createDiscoveryDnsContext({ baseQuery });
		const result = await ctx.query('example.com', 'A');
		expect(result).toBe(dohResponse);
	});
});
