// SPDX-License-Identifier: BUSL-1.1

/**
 * Phase 1 of the AbortSignal-into-fetch refactor (.dev/abort-signal-plan.md).
 *
 * `queryDns` must accept a caller-supplied `AbortSignal` so the discoverer's
 * budget-driven AbortController can cancel in-flight DoH fetches. Without
 * this, the fetch keeps running on the Worker's CPU budget and the
 * orchestrator's `signal.aborted` phase-boundary checks never get a turn —
 * the catch handler races CF's CPU kill and usually loses.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import { queryDns } from '../src/lib/dns';
import { setupFetchMock } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => {
	restore();
});

describe('queryDns — AbortSignal propagation (Phase 1)', () => {
	it('rejects when the caller-supplied AbortSignal aborts mid-fetch', async () => {
		const controller = new AbortController();
		const fetchMock = vi.fn((_url: string, init?: RequestInit) => {
			return new Promise<Response>((_resolve, reject) => {
				const onAbort = () => reject(new DOMException('aborted by caller', 'AbortError'));
				if (init?.signal?.aborted) {
					onAbort();
					return;
				}
				init?.signal?.addEventListener('abort', onAbort, { once: true });
			});
		});
		globalThis.fetch = fetchMock as unknown as typeof globalThis.fetch;

		const promise = queryDns('example.com', 'TXT', false, {
			retries: 0,
			confirmWithSecondaryOnEmpty: false,
			signal: controller.signal,
		});
		setTimeout(() => controller.abort(), 5);

		await expect(promise).rejects.toThrow(/abort|aborted/i);
	});

	it('forwards an already-aborted signal so fetch never starts useful work', async () => {
		const controller = new AbortController();
		controller.abort();
		const fetchMock = vi.fn((_url: string, init?: RequestInit) => {
			return new Promise<Response>((_resolve, reject) => {
				if (init?.signal?.aborted) {
					reject(new DOMException('aborted by caller', 'AbortError'));
					return;
				}
				_resolve({} as Response);
			});
		});
		globalThis.fetch = fetchMock as unknown as typeof globalThis.fetch;

		await expect(
			queryDns('example.com', 'TXT', false, {
				retries: 0,
				confirmWithSecondaryOnEmpty: false,
				signal: controller.signal,
			}),
		).rejects.toThrow(/abort|aborted/i);
	});

	it('does NOT retry when the abort is from the caller (vs internal timeout)', async () => {
		// Internal AbortSignal.timeout → retry per existing semantics.
		// Caller-supplied signal abort → propagate immediately, no retry.
		const controller = new AbortController();
		const fetchMock = vi.fn((_url: string, init?: RequestInit) => {
			return new Promise<Response>((_resolve, reject) => {
				const onAbort = () => reject(new DOMException('aborted by caller', 'AbortError'));
				if (init?.signal?.aborted) {
					onAbort();
					return;
				}
				init?.signal?.addEventListener('abort', onAbort, { once: true });
			});
		});
		globalThis.fetch = fetchMock as unknown as typeof globalThis.fetch;

		setTimeout(() => controller.abort(), 5);
		await expect(
			queryDns('example.com', 'TXT', false, {
				retries: 3,
				confirmWithSecondaryOnEmpty: false,
				signal: controller.signal,
			}),
		).rejects.toThrow(/abort|aborted/i);

		// One attempt only: caller-abort short-circuits the retry loop.
		expect(fetchMock).toHaveBeenCalledTimes(1);
	});
});
