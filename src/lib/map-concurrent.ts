// SPDX-License-Identifier: BUSL-1.1

export async function mapConcurrent<T, R>(
	items: readonly T[],
	limit: number,
	fn: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
	const out: R[] = new Array(items.length);
	let next = 0;
	const workerCount = Math.max(1, Math.min(Number.isFinite(limit) ? Math.floor(limit) : 1, items.length));

	async function worker(): Promise<void> {
		while (true) {
			const index = next++;
			if (index >= items.length) return;
			out[index] = await fn(items[index], index);
		}
	}

	await Promise.all(Array.from({ length: workerCount }, () => worker()));
	return out;
}
