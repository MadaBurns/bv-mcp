// SPDX-License-Identifier: BUSL-1.1
/** Real D1 clock with controlled R2 publication boundaries. */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { indexEntries } from '../indexer/write';
import { createReader } from '../indexer/read';
import { applyCatalog, batchBody, catalog, fakeBatch, objectKeys, obs, sib, testEnv, withFault, T } from './indexer-harness';

beforeEach(applyCatalog);
afterEach(() => vi.restoreAllMocks());
const sqlNow = async () =>
	(await testEnv().CURSORS.prepare("SELECT strftime('%Y-%m-%dT%H:%M:%fZ','now') AS at").first<{ at: string }>())!.at;
const timestamps = async () =>
	(await testEnv().CURSORS.prepare('SELECT generation, created_at FROM runs ORDER BY id').all<{ generation: number; created_at: string }>()).results;

describe('T0 publication clock', () => {
	it('uses D1 time after both puts while metadata and keys retain invocation time', async () => {
		const env = testEnv();
		const invocation = Date.UTC(2000, 0, 1);
		vi.spyOn(Date, 'now').mockReturnValue(invocation);
		let release!: () => void;
		const held = new Promise<void>((resolve) => { release = resolve; });
		let reached!: () => void;
		const waiting = new Promise<void>((resolve) => { reached = resolve; });
		let puts = 0;
		const INDEX = withFault(env.INDEX, 'put', async (...args: unknown[]) => {
			if (++puts === 2) { reached(); await held; }
			return env.INDEX.put(...args as Parameters<typeof env.INDEX.put>);
		});
		const batch = fakeBatch('bv-ct-index-entries', [batchBody([obs('api.example.com')], [sib('example.com', 'example.org')])]);
		const writing = indexEntries(batch, { ...env, INDEX });
		try {
			await waiting;
			expect(await catalog()).toEqual([]);
			expect(batch.ackedAll).toBe(false);
			const lower = await sqlNow();
			await env.CURSORS.prepare("INSERT INTO meta (k,v) VALUES ('current_generation','2')").run();
			release();
			await writing;
			const upper = await sqlNow();
			const rows = await timestamps();
			expect(rows).toHaveLength(2);
			for (const row of rows) {
				expect(row.generation).toBe(2);
				expect(row.created_at).toMatch(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/);
				expect(row.created_at >= lower && row.created_at <= upper).toBe(true);
			}
			const keys = await objectKeys();
			expect(keys).toHaveLength(2);
			expect(keys.every((key) => key.includes(`/${invocation}-`))).toBe(true);
			expect(await createReader(env).meta()).toMatchObject({
				indexStartedAt: new Date(invocation).toISOString(), freshThrough: new Date(invocation).toISOString(),
			});
			expect((await env.CURSORS.prepare('SELECT day FROM ops_ledger').all<{ day: string }>()).results).toEqual([{ day: '2000-01-01' }]);
			expect(batch.ackedAll).toBe(true);
		} finally { release(); await writing; }
	});

	it.each(['put', 'batch'] as const)('keeps production-clock %s failures unacknowledged and retries with unique keys', async (stage) => {
		const env = testEnv();
		const batch = fakeBatch('bv-ct-index-entries', [batchBody([obs('api.example.com')])]);
		const failure = () => Promise.reject(new Error('injected publication failure'));
		const failing = stage === 'put'
			? { ...env, INDEX: withFault(env.INDEX, 'put', failure) }
			: { ...env, CURSORS: withFault(env.CURSORS, 'batch', failure) };
		await expect(indexEntries(batch, failing)).rejects.toThrow('injected publication failure');
		expect(batch.ackedAll).toBe(false);
		expect(await catalog()).toEqual([]);
		const abandoned = await objectKeys();
		expect(abandoned).toHaveLength(stage === 'put' ? 0 : 1);
		await indexEntries(batch, env);
		expect(batch.ackedAll).toBe(true);
		const committed = await catalog();
		expect(committed).toHaveLength(1);
		expect(abandoned.includes(committed[0]!.r2_key)).toBe(false);
		const created = (await timestamps())[0]!.created_at;
		expect(Number.isFinite(Date.parse(created))).toBe(true);
		expect((await createReader(env).scan('example.com', { limit: 10 })).names.map((row) => row.name)).toEqual(['api.example.com']);
	});

	it.each([0, T])('preserves explicit valid clock override %i', async (now) => {
		await indexEntries(fakeBatch('bv-ct-index-entries', [batchBody([obs('api.example.com')])]), testEnv(), now);
		expect((await timestamps()).map((row) => row.created_at)).toEqual([new Date(now).toISOString()]);
	});

	it.each([NaN, Infinity, -Infinity, 8.64e15 + 1])('rejects invalid clock before any binding effect (%s)', async (now) => {
		let calls = 0;
		const env = testEnv();
		const CURSORS = withFault(env.CURSORS, 'prepare', (...args: unknown[]) => {
			calls++;
			return env.CURSORS.prepare(...args as Parameters<typeof env.CURSORS.prepare>);
		});
		const batch = fakeBatch('bv-ct-index-entries', [batchBody([obs('api.example.com')])]);
		await expect(indexEntries(batch, { ...env, CURSORS }, now)).rejects.toThrow(RangeError);
		expect(calls).toBe(0);
		expect(batch.ackedAll).toBe(false);
		expect(await objectKeys()).toEqual([]);
	});
});
