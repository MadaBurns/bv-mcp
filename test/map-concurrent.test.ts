// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import { mapConcurrent } from '../src/lib/map-concurrent';

describe('mapConcurrent', () => {
	it('returns an empty array without calling the worker for empty input', async () => {
		let calls = 0;

		const result = await mapConcurrent([], 2, async () => {
			calls++;
			return 'unexpected';
		});

		expect(result).toEqual([]);
		expect(calls).toBe(0);
	});

	it('preserves result order while bounding concurrency', async () => {
		let active = 0;
		let maxActive = 0;
		const result = await mapConcurrent([1, 2, 3, 4, 5], 2, async (item) => {
			active++;
			maxActive = Math.max(maxActive, active);
			await new Promise((resolve) => setTimeout(resolve, 5));
			active--;
			return item * 10;
		});

		expect(result).toEqual([10, 20, 30, 40, 50]);
		expect(maxActive).toBe(2);
	});

	it.each([0, -1, Number.NaN, Number.POSITIVE_INFINITY, 1.8])(
		'processes work with one active worker for limit %s',
		async (limit) => {
			let active = 0;
			let maxActive = 0;
			const result = await mapConcurrent([1, 2, 3], limit, async (item) => {
				active++;
				maxActive = Math.max(maxActive, active);
				await new Promise((resolve) => setTimeout(resolve, 1));
				active--;
				return item * 2;
			});

			expect(result).toEqual([2, 4, 6]);
			expect(maxActive).toBeLessThanOrEqual(1);
		},
	);

	it('fails fast when the worker throws', async () => {
		let itemTwoFinished = false;

		await expect(
			mapConcurrent([1, 2, 3], 2, async (item) => {
				if (item === 1) {
					await new Promise((resolve) => setTimeout(resolve, 5));
					throw new Error('boom');
				}
				if (item === 2) {
					await new Promise((resolve) => setTimeout(resolve, 25));
					itemTwoFinished = true;
					return item;
				}
				return item;
			}),
		).rejects.toThrow('boom');

		// mapConcurrent rejects on the first worker failure; already-started work may continue after rejection.
		expect(itemTwoFinished).toBe(false);
	});
});
