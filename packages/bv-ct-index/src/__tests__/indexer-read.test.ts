// SPDX-License-Identifier: BUSL-1.1
/**
 * The read seam (createReader): suffix scans across apexes and tiers, cursor pagination, block-precise and
 * bounded-concurrency R2 reads, and fault handling (throw, never an empty page).
 */

import { beforeEach, describe, expect, it } from 'vitest';
import { apexOf } from '../codec';
import { runCompactionJob } from '../indexer/compact';
import { MissingRunObjectError } from '../indexer/blocks';
import { runCompactionCron } from '../indexer/plan';
import { READ_CONCURRENCY, createReader } from '../indexer/read';
import type { NameObservation } from '../types';
import {
	DAY_MS,
	HOUR_MS,
	T,
	T_S,
	applyCatalog,
	catalog,
	cronAndDrain,
	expectedRows,
	ingest,
	obs,
	sib,
	testEnv,
	withFault,
} from './indexer-harness';

beforeEach(applyCatalog);

const at = (day: number, hh: number, mm: number) => Math.floor(T / DAY_MS) * DAY_MS + day * DAY_MS + hh * HOUR_MS + mm * 60_000;

/** An INDEX binding that records every GET and how many were in flight at once. */
function countingBucket(bucket: R2Bucket, before?: () => Promise<void>) {
	const stats = { gets: 0, inFlight: 0, maxInFlight: 0 };
	const wrapped = withFault(bucket, 'get', async (...args: unknown[]) => {
		stats.gets++;
		stats.inFlight++;
		stats.maxInFlight = Math.max(stats.maxInFlight, stats.inFlight);
		try {
			await before?.();
			await new Promise((resolve) => setTimeout(resolve, 5));
			return await bucket.get(...(args as [string, R2GetOptions]));
		} finally {
			stats.inFlight--;
		}
	});
	return { bucket: wrapped, stats };
}

describe('createReader().scan', () => {
	it('answers a public-suffix scan (govt.nz) across many apexes and tiers, and nothing outside it', async () => {
		const env = testEnv();
		const inside = [
			obs('dia.govt.nz'),
			obs('www.dia.govt.nz'),
			obs('mail.ird.govt.nz'),
			obs('*.health.govt.nz'),
			obs('stats.govt.nz'),
			obs('a.b.c.police.govt.nz'),
			obs('govt.nz'),
		];
		const outside = [obs('xgovt.nz'), obs('govt.nz.example.com'), obs('dia.govt.nz.evil.org'), obs('govt.com'), obs('stats.nz')];
		await ingest(env, at(0, 1, 5), [...inside.slice(0, 4), ...outside]);
		await cronAndDrain(env, at(0, 2, 17));
		await ingest(env, at(0, 2, 30), inside.slice(4));
		expect((await catalog()).map((run) => run.tier).sort()).toEqual([0, 1]);

		const page = await createReader(env, () => at(0, 3, 0)).scan('govt.nz', { limit: 100 });
		expect(page.names).toEqual(expectedRows(inside, T_S));
		expect(new Set(page.names.map((row) => apexOf(row.name) ?? row.name)).size).toBeGreaterThanOrEqual(5);
		expect(page.truncated).toBe(false);
	});

	it('pages through three pages with an opaque cursor, merging rows across tiers without gaps or repeats', async () => {
		const env = testEnv();
		const a = Array.from({ length: 15 }, (_, i) => obs(`h${i}.example.com`, { issuer: 'A', firstSeen: T_S - i }));
		const b = Array.from({ length: 15 }, (_, i) => obs(`h${i + 10}.example.com`, { issuer: 'B', notAfter: T_S + 90 * 86_400 }));
		await ingest(env, at(0, 1, 5), [...a, obs('h1.other.com')]);
		await cronAndDrain(env, at(0, 2, 17));
		await ingest(env, at(0, 2, 30), b);
		const expected = expectedRows([...a, ...b], T_S);
		expect(expected).toHaveLength(25);

		const reader = createReader(env, () => at(0, 3, 0));
		const pages = [];
		let cursor: string | null = null;
		do {
			const page = await reader.scan('example.com', { limit: 10, cursor });
			pages.push(page);
			cursor = page.cursor;
		} while (cursor !== null);
		expect(pages.map((page) => [page.names.length, page.truncated, page.cursor === null])).toEqual([
			[10, true, false],
			[10, true, false],
			[5, false, true],
		]);
		expect(pages.flatMap((page) => page.names)).toEqual(expected);
		expect(pages[0]!.cursor).not.toContain('\x01');

		const whole = await reader.scan('example.com', { limit: 25 });
		expect([whole.names.length, whole.truncated, whole.cursor]).toEqual([25, false, null]);
	});

	it('refuses a bad domain, limit or cursor with RangeError', async () => {
		const env = testEnv();
		await ingest(env, at(0, 1, 5), [obs('a.example.com'), obs('b.example.com'), obs('a.other.com'), obs('b.other.com')]);
		const reader = createReader(env, () => at(0, 2, 0));
		const foreign = (await reader.scan('other.com', { limit: 1 })).cursor;
		expect(foreign).not.toBeNull();

		await expect(reader.scan('example.com', { limit: 0 })).rejects.toThrow(RangeError);
		await expect(reader.scan('bad domain', { limit: 1 })).rejects.toThrow(RangeError);
		await expect(reader.scan('example.com', { limit: 1, cursor: '!!' })).rejects.toThrow(RangeError);
		await expect(reader.scan('example.com', { limit: 1, cursor: foreign })).rejects.toThrow(RangeError);
		await expect(reader.siblings('bad apex', { limit: 1 })).rejects.toThrow(RangeError);
	});

	it('fetches only the blocks that can hold the range, at most READ_CONCURRENCY at a time', async () => {
		const env = testEnv();
		const filler = Array.from({ length: 3_000 }, (_, i) => obs(`host-${i}.zone-${i % 37}.filler${i % 5}.com`));
		await ingest(env, at(0, 1, 0), [...filler, obs('www.needle.com')]);
		expect((await catalog())[0]!.rows).toBe(3_001);

		const one = countingBucket(env.INDEX);
		const page = await createReader(testEnv({ INDEX: one.bucket }), () => at(0, 2, 0)).scan('needle.com', { limit: 10 });
		expect(page.names.map((row) => row.name)).toEqual(['www.needle.com']);
		expect(one.stats.gets).toBe(1);

		for (let i = 0; i < 10; i++) await ingest(env, at(0, 1, 10 + i), [obs(`run${i}.needle.com`)]);
		const many = countingBucket(env.INDEX);
		const all = await createReader(testEnv({ INDEX: many.bucket }), () => at(0, 2, 0)).scan('needle.com', { limit: 100 });
		expect(all.names).toHaveLength(11);
		expect(many.stats.gets).toBe(11);
		expect(many.stats.maxInFlight).toBeLessThanOrEqual(READ_CONCURRENCY);
		expect(many.stats.maxInFlight).toBeGreaterThan(1);
	});
});

describe('createReader faults', () => {
	it('throws on a run object missing from R2, for scans and sibling reads, rather than return an empty page', async () => {
		const env = testEnv();
		await ingest(env, at(0, 1, 5), [obs('www.example.com')], [sib('example.com', 'other.org')]);
		for (const run of await catalog()) await env.INDEX.delete(run.r2_key);
		const reader = createReader(env, () => at(0, 2, 0));
		await expect(reader.scan('example.com', { limit: 10 })).rejects.toThrow(MissingRunObjectError);
		await expect(reader.siblings('example.com', { limit: 10 })).rejects.toThrow(MissingRunObjectError);
	});

	it('throws on a D1 failure', async () => {
		const env = testEnv({
			CURSORS: withFault(testEnv().CURSORS, 'prepare', () => {
				throw new Error('injected D1 failure');
			}),
		});
		const reader = createReader(env, () => at(0, 2, 0));
		await expect(reader.scan('example.com', { limit: 10 })).rejects.toThrow('injected D1 failure');
		await expect(reader.meta()).rejects.toThrow('injected D1 failure');
	});

	it('re-reads the catalog once when a compaction swap deletes an input between the catalog query and the GET', async () => {
		const env = testEnv();
		const names: NameObservation[] = [obs('a.example.com'), obs('b.example.com', { issuer: 'X' })];
		await ingest(env, at(0, 1, 5), names.slice(0, 1));
		await ingest(env, at(0, 1, 20), names.slice(1));
		const [job] = (await runCompactionCron(env, at(0, 2, 17))).jobs;
		let compacted = false;
		const racing = countingBucket(env.INDEX, async () => {
			if (compacted) return;
			compacted = true;
			expect(await runCompactionJob(env, job!, undefined, at(0, 2, 17))).toBe('applied');
		});

		const page = await createReader(testEnv({ INDEX: racing.bucket }), () => at(0, 3, 0)).scan('example.com', { limit: 10 });
		expect(compacted).toBe(true);
		expect(page.names).toEqual(expectedRows(names, T_S));
		expect((await catalog()).map((run) => run.tier)).toEqual([1]);
	});
});
