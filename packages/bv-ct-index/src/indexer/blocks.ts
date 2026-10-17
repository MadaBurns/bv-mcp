// SPDX-License-Identifier: BUSL-1.1
/**
 * R2 reads of sorted-run blocks (codec.ts). Every read is a range GET of whole blocks, and every fault
 * throws: a missing object or a short body must never read as an empty block.
 */

import type { BlockIndexEntry } from '../types';

/** The catalog lists a run whose R2 object is gone. */
export class MissingRunObjectError extends Error {
	constructor(readonly r2Key: string) {
		super(`run object missing from R2: ${r2Key}`);
		this.name = 'MissingRunObjectError';
	}
}

/** One R2 range GET. */
export async function readRange(bucket: R2Bucket, r2Key: string, offset: number, length: number): Promise<Uint8Array> {
	const object = await bucket.get(r2Key, { range: { offset, length } });
	if (object === null) throw new MissingRunObjectError(r2Key);
	const bytes = new Uint8Array(await object.arrayBuffer());
	if (bytes.byteLength !== length) throw new Error(`short read of ${r2Key} at ${offset}: ${bytes.byteLength} of ${length} bytes`);
	return bytes;
}

/** Runs at most `max` tasks at once; a finished task hands its slot straight to the next waiter. */
export function limiter(max: number): <T>(task: () => Promise<T>) => Promise<T> {
	let active = 0;
	const waiting: Array<() => void> = [];
	return async (task) => {
		if (active < max) active++;
		else await new Promise<void>((resolve) => waiting.push(resolve));
		try {
			return await task();
		} finally {
			const next = waiting.shift();
			if (next) next();
			else active--;
		}
	};
}

/**
 * A `streamRun` block reader that fetches consecutive blocks together, one range GET of up to `windowBytes`
 * (at least one whole block), and serves the following blocks from it. A compaction job reads whole runs, so
 * this cuts Class B GETs by the blocks per window while holding one window per open run.
 */
export function windowedBlockReader(
	bucket: R2Bucket,
	r2Key: string,
	blockIndex: readonly BlockIndexEntry[],
	windowBytes: number,
	onGet: () => void,
): (entry: BlockIndexEntry) => Promise<Uint8Array> {
	const position = new Map(blockIndex.map((entry, i) => [entry.offset, i]));
	let window: { offset: number; bytes: Uint8Array } | null = null;
	return async (entry) => {
		const inWindow =
			window !== null && entry.offset >= window.offset && entry.offset + entry.length <= window.offset + window.bytes.byteLength;
		if (!inWindow) {
			let end = entry.offset + entry.length;
			for (let i = (position.get(entry.offset) ?? blockIndex.length) + 1; i < blockIndex.length; i++) {
				const next = blockIndex[i]!;
				if (next.offset !== end || next.offset + next.length - entry.offset > windowBytes) break;
				end = next.offset + next.length;
			}
			window = { offset: entry.offset, bytes: await readRange(bucket, r2Key, entry.offset, end - entry.offset) };
			onGet();
		}
		const start = entry.offset - window!.offset;
		return window!.bytes.subarray(start, start + entry.length);
	};
}
