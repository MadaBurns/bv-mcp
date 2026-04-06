// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { Semaphore, SemaphoreTimeoutError } from '../src/lib/semaphore';

describe('Semaphore', () => {
	beforeEach(() => {
		vi.restoreAllMocks();
	});

	it('allows up to maxConcurrent executions', async () => {
		const sem = new Semaphore(2);
		const order: string[] = [];
		let resolveA!: () => void;
		let resolveB!: () => void;

		const promiseA = sem.acquire().then((release) => {
			order.push('A-start');
			return new Promise<void>((r) => {
				resolveA = () => { order.push('A-end'); release(); r(); };
			});
		});

		const promiseB = sem.acquire().then((release) => {
			order.push('B-start');
			return new Promise<void>((r) => {
				resolveB = () => { order.push('B-end'); release(); r(); };
			});
		});

		// Let microtasks flush
		await new Promise((r) => setTimeout(r, 10));
		expect(order).toEqual(['A-start', 'B-start']);
		expect(sem.active).toBe(2);
		expect(sem.waiting).toBe(0);

		resolveA!();
		resolveB!();
		await Promise.all([promiseA, promiseB]);
	});

	it('queues the (N+1)th caller until one completes', async () => {
		const sem = new Semaphore(1);
		const order: string[] = [];
		let resolveFirst!: () => void;

		const first = sem.run(async () => {
			order.push('first-start');
			await new Promise<void>((r) => { resolveFirst = r; });
			order.push('first-end');
		});

		// Give first task time to start
		await new Promise((r) => setTimeout(r, 10));
		expect(sem.active).toBe(1);
		expect(sem.waiting).toBe(0);

		const secondPromise = sem.run(async () => {
			order.push('second-start');
			return 'second-result';
		});

		await new Promise((r) => setTimeout(r, 10));
		expect(sem.waiting).toBe(1);
		expect(order).toEqual(['first-start']);

		resolveFirst();
		await first;
		const secondResult = await secondPromise;

		expect(secondResult).toBe('second-result');
		expect(order).toEqual(['first-start', 'first-end', 'second-start']);
	});

	it('releases waiters in FIFO order', async () => {
		const sem = new Semaphore(1);
		const order: string[] = [];
		let resolveFirst!: () => void;

		const first = sem.run(async () => {
			await new Promise<void>((r) => { resolveFirst = r; });
		});

		// Give first task time to start
		await new Promise((r) => setTimeout(r, 10));

		const second = sem.run(async () => { order.push('B'); });
		const third = sem.run(async () => { order.push('C'); });

		await new Promise((r) => setTimeout(r, 10));
		expect(sem.waiting).toBe(2);

		resolveFirst();
		await first;
		await second;
		await third;

		expect(order).toEqual(['B', 'C']);
	});

	it('rejects pending caller after maxWaitMs', async () => {
		const sem = new Semaphore(1, { maxWaitMs: 50 });
		let resolveFirst!: () => void;

		const first = sem.run(async () => {
			await new Promise<void>((r) => { resolveFirst = r; });
		});

		await new Promise((r) => setTimeout(r, 10));

		await expect(sem.run(async () => 'should not run')).rejects.toThrow(SemaphoreTimeoutError);

		resolveFirst();
		await first;
	});

	it('tracks active count and queue depth', async () => {
		const sem = new Semaphore(2);
		expect(sem.active).toBe(0);
		expect(sem.waiting).toBe(0);

		let resolveA!: () => void;
		let resolveB!: () => void;

		const a = sem.run(() => new Promise<void>((r) => { resolveA = r; }));
		const b = sem.run(() => new Promise<void>((r) => { resolveB = r; }));

		await new Promise((r) => setTimeout(r, 10));
		expect(sem.active).toBe(2);

		const c = sem.run(async () => 'c');
		await new Promise((r) => setTimeout(r, 10));
		expect(sem.waiting).toBe(1);

		resolveA();
		await a;
		await c;
		expect(sem.active).toBe(1);

		resolveB();
		await b;
		expect(sem.active).toBe(0);
	});

	it('decrements active count even if task throws', async () => {
		const sem = new Semaphore(2);
		await expect(sem.run(async () => { throw new Error('boom'); })).rejects.toThrow('boom');
		expect(sem.active).toBe(0);
	});

	it('drain() waits for all active and queued tasks to complete', async () => {
		const sem = new Semaphore(1);
		const results: number[] = [];

		let resolveFirst!: () => void;
		const first = sem.run(async () => {
			await new Promise<void>((r) => { resolveFirst = r; });
			results.push(1);
		});

		await new Promise((r) => setTimeout(r, 10));

		const second = sem.run(async () => { results.push(2); });

		// drain should wait for both
		const drainPromise = sem.drain();

		// Release first so both can complete
		resolveFirst();
		await first;
		await second;
		await drainPromise;

		expect(results).toEqual([1, 2]);
		expect(sem.active).toBe(0);
		expect(sem.waiting).toBe(0);
	});

	it('run() returns the result of the function', async () => {
		const sem = new Semaphore(5);
		const result = await sem.run(async () => 42);
		expect(result).toBe(42);
	});
});
