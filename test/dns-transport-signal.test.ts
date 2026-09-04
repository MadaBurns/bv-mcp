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

describe('queryDns — AbortSignal propagation into the secondary confirmation (PR #903 review)', () => {
	/** Primary (Cloudflare) answers EMPTY; the secondary (Google) hangs, honouring whatever signal it was given. */
	function mockEmptyPrimaryHangingSecondary() {
		const secondaryInits: RequestInit[] = [];
		globalThis.fetch = vi.fn((url: string, init?: RequestInit) => {
			const host = new URL(url).hostname;
			if (host === 'dns.google') {
				secondaryInits.push(init ?? {});
				return new Promise<Response>((_resolve, reject) => {
					const onAbort = () => reject(init?.signal?.reason ?? new DOMException('aborted', 'AbortError'));
					if (init?.signal?.aborted) return onAbort();
					init?.signal?.addEventListener('abort', onAbort, { once: true });
				});
			}
			return Promise.resolve(
				new Response(
					JSON.stringify({
						Status: 0,
						TC: false,
						RD: true,
						RA: true,
						AD: false,
						CD: false,
						Question: [{ name: 'example.com', type: 16 }],
						Answer: [],
					}),
					{
						status: 200,
					},
				),
			);
		}) as unknown as typeof globalThis.fetch;
		return secondaryInits;
	}

	it('a caller signal aborts a hanging secondary confirmation, and the query REJECTS (never a confirmed-empty answer)', async () => {
		const secondaryInits = mockEmptyPrimaryHangingSecondary();
		const controller = new AbortController();
		const started = Date.now();
		const promise = queryDns('example.com', 'TXT', false, {
			retries: 0,
			timeoutMs: 3000,
			confirmWithSecondaryOnEmpty: true,
			signal: controller.signal,
		});
		setTimeout(() => controller.abort(), 30);

		await expect(promise).rejects.toThrow(/aborted by caller/i);
		// Cut by the caller, not by the secondary's own 3s timer.
		expect(Date.now() - started).toBeLessThan(1000);
		expect(secondaryInits.length).toBe(1);
		expect(secondaryInits[0].signal?.aborted).toBe(true);
	});

	it('without a caller signal the secondary confirmation keeps its own timeout (behaviour preserved)', async () => {
		const secondaryInits = mockEmptyPrimaryHangingSecondary();
		const started = Date.now();
		const result = await queryDns('example.com', 'TXT', false, { retries: 0, timeoutMs: 80, confirmWithSecondaryOnEmpty: true });
		// Secondary timed out → unconfirmed → the primary's empty answer stands.
		expect(result.Answer ?? []).toEqual([]);
		expect(Date.now() - started).toBeGreaterThanOrEqual(60);
		expect(secondaryInits.length).toBe(1);
	});
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
