// SPDX-License-Identifier: BUSL-1.1

/**
 * Promise-based counting semaphore for concurrency control.
 *
 * Used to cap concurrent outbound DoH fetches per isolate,
 * preventing DNS/KV resource exhaustion during batch scans.
 *
 * Workers-compatible: uses only Promises and setTimeout, no Node.js APIs.
 */

export interface SemaphoreOptions {
	/**
	 * Maximum milliseconds a caller waits in the queue before rejection.
	 *
	 * ⚠️ DELIBERATELY UNUSED ON THE DoH PATH — do not wire this into the scan or
	 * batch semaphores to withdraw queries orphaned by a per-check timeout (#941).
	 * It looks like the cheap fix and is actively harmful:
	 *
	 * 1. `SemaphoreTimeoutError` is NOT abort-classified by `dns-transport`, so it
	 *    falls through to the generic retry arm and is retried once — the effective
	 *    queue budget becomes 2 × maxWaitMs, never one.
	 * 2. It then surfaces as a generic `DnsQueryError` → `checkStatus: 'error'` with
	 *    score 0, which satisfies `shouldRetry()` in scan-domain.ts and re-runs the
	 *    WHOLE check, re-issuing every one of its DoH queries. That ADDS subrequests
	 *    to the ceiling this was meant to protect.
	 * 3. Worst: several package checks swallow a rejected query into an empty-record
	 *    verdict (see the TXT catch in check-dkim.ts), so rejecting a DoH query while
	 *    a check is still LIVE can turn a transient into a scored `missingControl` —
	 *    the fail-open class the scoring doctrine exists to prevent. Today the only
	 *    signal that can reject a live query is the scan-level abort, which fires at
	 *    the same instant the result snapshot is taken, so nothing captures it.
	 *
	 * The option itself is correct and unit-tested (`test/dns-semaphore.spec.ts`);
	 * it is retained for callers that want a genuine queue deadline. It is simply
	 * the wrong instrument for per-check DoH withdrawal.
	 */
	maxWaitMs?: number;
}

/** Thrown when a queued caller exceeds maxWaitMs. */
export class SemaphoreTimeoutError extends Error {
	constructor(maxWaitMs: number) {
		super(`Semaphore acquisition timed out after ${maxWaitMs}ms`);
		this.name = 'SemaphoreTimeoutError';
	}
}

interface Waiter {
	resolve: (release: () => void) => void;
	reject: (err: Error) => void;
	timer?: ReturnType<typeof setTimeout>;
	signal?: AbortSignal;
	onAbort?: () => void;
}

function abortError(): Error {
	const error = new Error('Semaphore acquisition aborted');
	error.name = 'AbortError';
	return error;
}

export class Semaphore {
	private _active = 0;
	private readonly _queue: Waiter[] = [];
	private readonly maxConcurrent: number;
	private readonly maxWaitMs?: number;

	constructor(maxConcurrent: number, options?: SemaphoreOptions) {
		this.maxConcurrent = maxConcurrent;
		this.maxWaitMs = options?.maxWaitMs;
	}

	get active(): number {
		return this._active;
	}

	get waiting(): number {
		return this._queue.length;
	}

	/** Acquire a semaphore slot. Returns a release function. */
	acquire(signal?: AbortSignal): Promise<() => void> {
		if (signal?.aborted) return Promise.reject(abortError());
		if (this._active < this.maxConcurrent) {
			this._active++;
			return Promise.resolve(() => this.release());
		}

		return new Promise<() => void>((resolve, reject) => {
			const waiter: Waiter = { resolve, reject, signal };
			waiter.onAbort = () => {
				const idx = this._queue.indexOf(waiter);
				if (idx !== -1) {
					this._queue.splice(idx, 1);
					if (waiter.timer !== undefined) clearTimeout(waiter.timer);
					reject(abortError());
				}
			};
			signal?.addEventListener('abort', waiter.onAbort, { once: true });

			if (this.maxWaitMs !== undefined) {
				waiter.timer = setTimeout(() => {
					const idx = this._queue.indexOf(waiter);
					if (idx !== -1) {
						this._queue.splice(idx, 1);
						if (waiter.signal && waiter.onAbort) waiter.signal.removeEventListener('abort', waiter.onAbort);
						reject(new SemaphoreTimeoutError(this.maxWaitMs!));
					}
				}, this.maxWaitMs);
			}

			this._queue.push(waiter);
		});
	}

	/** Run an async function within a semaphore-controlled slot. */
	async run<T>(fn: () => Promise<T>, signal?: AbortSignal): Promise<T> {
		const release = await this.acquire(signal);
		try {
			return await fn();
		} finally {
			release();
		}
	}

	/** Wait for all active and queued tasks to finish. */
	async drain(): Promise<void> {
		while (this._active > 0 || this._queue.length > 0) {
			await new Promise((r) => setTimeout(r, 5));
		}
	}

	private release(): void {
		if (this._queue.length > 0) {
			const next = this._queue.shift()!;
			if (next.timer !== undefined) clearTimeout(next.timer);
			if (next.signal && next.onAbort) next.signal.removeEventListener('abort', next.onAbort);
			// Don't decrement — we're handing the slot to the next waiter
			next.resolve(() => this.release());
		} else {
			this._active--;
		}
	}
}
