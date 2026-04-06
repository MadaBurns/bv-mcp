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
	/** Maximum milliseconds a caller waits in the queue before rejection. */
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
	acquire(): Promise<() => void> {
		if (this._active < this.maxConcurrent) {
			this._active++;
			return Promise.resolve(() => this.release());
		}

		return new Promise<() => void>((resolve, reject) => {
			const waiter: Waiter = { resolve, reject };

			if (this.maxWaitMs !== undefined) {
				waiter.timer = setTimeout(() => {
					const idx = this._queue.indexOf(waiter);
					if (idx !== -1) {
						this._queue.splice(idx, 1);
						reject(new SemaphoreTimeoutError(this.maxWaitMs!));
					}
				}, this.maxWaitMs);
			}

			this._queue.push(waiter);
		});
	}

	/** Run an async function within a semaphore-controlled slot. */
	async run<T>(fn: () => Promise<T>): Promise<T> {
		const release = await this.acquire();
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
			// Don't decrement — we're handing the slot to the next waiter
			next.resolve(() => this.release());
		} else {
			this._active--;
		}
	}
}
