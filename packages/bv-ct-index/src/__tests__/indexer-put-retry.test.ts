// SPDX-License-Identifier: BUSL-1.1
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { runCompactionJob, runCompactionBatch, PUT_CONCURRENCY, PUT_BUDGET_BYTES } from '../indexer/compact';
import type { JobStats } from '../indexer/compact';
import { runCompactionCron } from '../indexer/plan';
import { applyCatalog, catalog, fakeBatch, ingest, obs, testEnv, withFault, T, DAY_MS, HOUR_MS } from './indexer-harness';
const MESSAGE = 'put: We encountered an internal error. Please try again. (10001)';
const at = (hour: number, minute: number) => Math.floor(T / DAY_MS) * DAY_MS + hour * HOUR_MS + minute * 60000;
const SMALL = { targetRawBytes: 8 * 1024 };
beforeEach(applyCatalog);
afterEach(() => vi.restoreAllMocks());
async function setup() {
	const env = testEnv();
	for (const [tag, minute] of [['a', 5], ['b', 6]] as const)
		await ingest(env, at(1, minute), Array.from({ length: 400 }, (_, i) => obs(`${tag}-${i}.zone${i % 5}.example.com`)));
	const { jobs } = await runCompactionCron(env, at(2, 17));
	expect(jobs).toHaveLength(1);
	return { env, job: jobs[0]! };
}
describe('immutable compaction PUT retry', () => {
	it.each([1, 2])('retries %i verified transient failures with identical key, bytes reference and absent options; accounts every attempt', async (failures) => {
		const { env, job } = await setup();
		const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
		const seen = new Map<string, {
			ref: Uint8Array;
			copy: Uint8Array;
			calls: number;
		}>();
		const sleeps: number[] = [];
		const before = await env.CURSORS.prepare('SELECT SUM(r2_class_a) AS n FROM ops_ledger').first<{
			n: number;
		}>();
		const wrapped = withFault(env.INDEX, 'put', async (...args: unknown[]) => {
			expect(args).toHaveLength(2);
			const [key, bytes] = args as [
				string,
				Uint8Array
			];
			let state = seen.get(key);
			if (!state) {
				state = { ref: bytes, copy: bytes.slice(), calls: 0 };
				seen.set(key, state);
			}
			expect(bytes).toBe(state.ref);
			expect(bytes).toEqual(state.copy);
			if (++state.calls <= failures) {
				// Ambiguous completion: the immutable object was stored before the binding reported failure.
				await env.INDEX.put(key, bytes);
				throw new Error(MESSAGE);
			}
			return env.INDEX.put(key, bytes);
		});
		const stats: JobStats = { outputs: 0, gets: 0, putMs: 0, ms: 0 };
		expect(await runCompactionJob(testEnv({ INDEX: wrapped }), job, { ...SMALL, putRetrySleep: async (ms) => { sleeps.push(ms); } }, at(2, 17), stats)).toBe('applied');
		expect(seen.size).toBeGreaterThan(PUT_CONCURRENCY);
		expect([...seen.values()].every(x => x.calls === failures + 1)).toBe(true);
		expect(stats.putAttempts).toBe(seen.size * (failures + 1));
		expect(stats.putRetries).toBe(seen.size * failures);
		const events = warn.mock.calls.map(([line]) => JSON.parse(String(line)));
		expect(events).toHaveLength(stats.putRetries!);
		expect(events.every(event => event.event === 'ct_compaction_put_retry' && event.phase === 'attempt' && event.id === job.id && event.planId === job.planId && event.now === job.now && event.category === 'r2-put-internal-10001' && [2, 3].includes(event.nextAttempt) && [1100, 2200].includes(event.delayMs))).toBe(true);
		expect(events.every(event => Object.keys(event).sort().join(',') === 'category,delayMs,event,id,nextAttempt,now,phase,planId')).toBe(true);
		expect(sleeps.filter(x => x === 1100)).toHaveLength(seen.size);
		expect(sleeps.filter(x => x === 2200)).toHaveLength(failures === 2 ? seen.size : 0);
		const after = await env.CURSORS.prepare('SELECT SUM(r2_class_a) AS n FROM ops_ledger').first<{
			n: number;
		}>();
		expect(after!.n - before!.n).toBe(stats.putAttempts);
		expect((await catalog()).every(x => x.tier === 1)).toBe(true);
	});
	it('paces same-key ambiguous committed writes beyond the documented one-write-per-second window', async () => {
		const env = testEnv();
		for (const minute of [5, 6]) await ingest(env, at(1, minute), [obs('single.example.com')]);
		const { jobs } = await runCompactionCron(env, at(2, 17));
		expect(jobs).toHaveLength(1);
		let logicalMs = 0;
		const timestamps: number[] = [];
		const enforceSameKeyRate = (now: number, previous: number) => {
			if (now - previous < 1000) throw new Error('put: Too Many Requests (10058)');
		};
		const wrapped = withFault(env.INDEX, 'put', async (...args: unknown[]) => {
			const [key, bytes] = args as [string, Uint8Array];
			if (timestamps.length) enforceSameKeyRate(logicalMs, timestamps[timestamps.length - 1]!);
			timestamps.push(logicalMs);
			const stored = await env.INDEX.put(key, bytes); // The failure is ambiguous: storage already committed.
			if (timestamps.length < 3) throw new Error(MESSAGE);
			return stored;
		});
		expect(await runCompactionJob(testEnv({ INDEX: wrapped }), jobs[0]!, {
			...SMALL, putRetrySleep: async ms => { logicalMs += ms; },
		}, at(2, 17))).toBe('applied');
		const safeSpacing = (times: number[]) => times.every((time, i) => i === 0 || time - times[i - 1]! >= 1000);
		expect(timestamps).toEqual([0, 1100, 3300]);
		expect(safeSpacing(timestamps)).toBe(true);
		// Negative control: the rejected original policy violates the same-key pacing oracle.
		expect(safeSpacing([0, 100, 350])).toBe(false);
		expect(() => enforceSameKeyRate(100, 0)).toThrow('(10058)');
	});
	it('propagates a 10058 after one handled 10001 without a third PUT or D1 publication', async () => {
		const env = testEnv();
		for (const minute of [5, 6]) await ingest(env, at(1, minute), [obs('single.example.com')]);
		const { jobs } = await runCompactionCron(env, at(2, 17));
		const before = await catalog();
		const limited = new Error('put: Too Many Requests (10058)');
		let calls = 0;
		const wrapped = withFault(env.INDEX, 'put', async (...args: unknown[]) => {
			if (++calls === 1) {
				await env.INDEX.put(...(args as [string, Uint8Array]));
				throw new Error(MESSAGE);
			}
			throw limited;
		});
		const batchCall = vi.fn(async () => { throw new Error('Unexpected catalog mutation'); });
		const delays: number[] = [];
		await expect(runCompactionJob(testEnv({ INDEX: wrapped, CURSORS: withFault(env.CURSORS, 'batch', batchCall) }), jobs[0]!, {
			...SMALL, putRetrySleep: async ms => { delays.push(ms); },
		}, at(2, 17))).rejects.toBe(limited);
		expect(calls).toBe(2);
		expect(delays).toEqual([1100]);
		expect(batchCall).not.toHaveBeenCalled();
		expect(await catalog()).toEqual(before);
		for (const run of before) expect(await env.INDEX.head(run.r2_key)).not.toBeNull();
	});
	it('holds all six output leases through backoff instead of admitting six more outputs', async () => {
		const { env, job } = await setup();
		const attempts = new Map<string, number>();
		const releases: (() => void)[] = [];
		let six!: () => void;
		const sixBlocked = new Promise<void>(r => { six = r; });
		const wrapped = withFault(env.INDEX, 'put', async (...args: unknown[]) => {
			const [key, bytes] = args as [
				string,
				Uint8Array
			];
			const n = (attempts.get(key) ?? 0) + 1;
			attempts.set(key, n);
			if (n === 1)
				throw new Error(MESSAGE);
			return env.INDEX.put(key, bytes);
		});
		let releaseAll = false;
		const running = runCompactionJob(testEnv({ INDEX: wrapped }), job, { ...SMALL, putRetrySleep: async () => {
				if (releaseAll)
					return;
				await new Promise<void>(r => {
					releases.push(r);
					if (releases.length === 6)
						six();
				});
			} }, at(2, 17));
		await sixBlocked;
		expect(attempts.size).toBe(PUT_CONCURRENCY);
		expect([...attempts.values()]).toEqual(Array(6).fill(1));
		releaseAll = true;
		for (const release of releases)
			release();
		expect(await running).toBe('applied');
	});
	it('holds the byte budget throughout backoff before six output slots fill', async () => {
		const env = testEnv();
		let seed = 123456789;
		const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
		const issuer = () => {
			let out = '';
			for (let i = 0; i < 256; i++) {
				seed ^= seed << 13;
				seed ^= seed >>> 17;
				seed ^= seed << 5;
				out += alphabet[(seed >>> 0) & 63];
			}
			return out;
		};
		for (let part = 0; part < 2; part++)
			await ingest(env, at(1, 5 + part), Array.from({ length: 15000 }, (_, i) => obs(`host-${String(part * 15000 + i).padStart(5, '0')}.example.com`, { issuer: issuer() })));
		const { jobs } = await runCompactionCron(env, at(2, 17));
		expect(jobs).toHaveLength(1);
		const sizes = new Map<string, number>();
		const attempts = new Map<string, number>();
		const releases: (() => void)[] = [];
		let over!: () => void;
		const overBudget = new Promise<void>(r => { over = r; });
		let released = false;
		const wrapped = withFault(env.INDEX, 'put', async (...args: unknown[]) => {
			const [key, bytes] = args as [
				string,
				Uint8Array
			];
			sizes.set(key, bytes.byteLength);
			const n = (attempts.get(key) ?? 0) + 1;
			attempts.set(key, n);
			if (n === 1)
				throw new Error(MESSAGE);
			return env.INDEX.put(key, bytes);
		});
		const running = runCompactionJob(testEnv({ INDEX: wrapped }), jobs[0]!, { targetRawBytes: 4 * 1024 * 1024, putRetrySleep: async () => {
				if (released)
					return;
				await new Promise<void>(r => {
					releases.push(r);
					if ([...sizes.values()].reduce((a, b) => a + b, 0) > PUT_BUDGET_BYTES)
						over();
				});
			} }, at(2, 17));
		await overBudget;
		expect(sizes.size).toBeLessThan(PUT_CONCURRENCY);
		expect([...sizes.values()].reduce((a, b) => a + b, 0)).toBeGreaterThan(PUT_BUDGET_BYTES);
		expect([...attempts.values()].every(n => n === 1)).toBe(true);
		released = true;
		for (const release of releases)
			release();
		expect(await running).toBe('applied');
	}, 60000);
	it('reports zero PUT work on duplicate queue delivery and clears reused caller statistics', async () => {
		const { env, job } = await setup();
		expect(await runCompactionJob(env, job, SMALL, at(2, 17))).toBe('applied');
		const reused: JobStats = { outputs: 99, gets: 99, putMs: 99, ms: 99, putAttempts: 99, putRetries: 99 };
		expect(await runCompactionJob(env, job, SMALL, at(2, 17), reused)).toBe('already-applied');
		expect(reused).toEqual({ outputs: 0, gets: 0, putMs: 0, ms: 0, putAttempts: 0, putRetries: 0 });
		const log = vi.spyOn(console, 'log').mockImplementation(() => undefined);
		const batch = fakeBatch('bv-ct-index-compact', [job]);
		await runCompactionBatch(batch, env);
		const done = log.mock.calls.map(([line]) => String(line)).filter(line => line.startsWith('{')).map(line => JSON.parse(line)).find(x => x.event === 'ct_compaction_job_done');
		expect(done).toMatchObject({ outcome: 'already-applied', outputs: 0, putAttempts: 0, putRetries: 0 });
		expect(batch.acked).toEqual(['m0']);
	});
	it('never acknowledges or deletes inputs when a permanent PUT failure escapes the barrier', async () => {
		const { env, job } = await setup();
		const before = await catalog();
		const error = new Error('injected permanent PUT failure');
		const broken = testEnv({ INDEX: withFault(env.INDEX, 'put', async () => { throw error; }) });
		const batch = fakeBatch('bv-ct-index-compact', [job]);
		await expect(runCompactionBatch(batch, broken)).rejects.toBe(error);
		expect(batch.acked).toEqual([]);
		expect(await catalog()).toEqual(before);
		for (const run of before)
			expect(await env.INDEX.head(run.r2_key)).not.toBeNull();
	});
	it('exhausts only three attempts, retaining inputs/catalog/ledger and never publishing a failed output', async () => {
		const { env, job } = await setup();
		const before = await catalog();
		const ledger = await env.CURSORS.prepare('SELECT * FROM ops_ledger').all();
		const error = new Error(MESSAGE);
		const counts = new Map<string, number>();
		const delays: number[] = [];
		const wrapped = withFault(env.INDEX, 'put', async (...args: unknown[]) => { const key = args[0] as string; counts.set(key, (counts.get(key) ?? 0) + 1); throw error; });
		await expect(runCompactionJob(testEnv({ INDEX: wrapped }), job, { ...SMALL, putRetrySleep: async (ms) => { delays.push(ms); } }, at(2, 17))).rejects.toBe(error);
		expect(Math.max(...counts.values())).toBe(3);
		expect(delays.every(ms => ms === 1100 || ms === 2200)).toBe(true);
		expect(await catalog()).toEqual(before);
		expect((await env.CURSORS.prepare('SELECT * FROM ops_ledger').all()).results).toEqual(ledger.results);
		for (const run of before)
			expect(await env.INDEX.head(run.r2_key)).not.toBeNull();
	});
	it.each([new Error('put: We encountered an internal error. Please try again. (10002)'), new Error('get: We encountered an internal error. Please try again. (10001)'), new TypeError(MESSAGE), new RangeError(MESSAGE), { message: MESSAGE, code: 10001 }, new Error('Network connection lost.'), new Error('put: Permission denied (10001)'), new Error('put: Too Many Requests (10058)')])('does not retry unverified error shapes %#', async (error) => {
		const { env, job } = await setup();
		const before = await catalog();
		const sleep = vi.fn(async () => { });
		const attempts = new Map<string, number>();
		const wrapped = withFault(env.INDEX, 'put', async (...args: unknown[]) => { const key = args[0] as string; attempts.set(key, (attempts.get(key) ?? 0) + 1); throw error; });
		await expect(runCompactionJob(testEnv({ INDEX: wrapped }), job, { ...SMALL, putRetrySleep: sleep }, at(2, 17))).rejects.toBe(error);
		expect(sleep).not.toHaveBeenCalled();
		expect([...attempts.values()].every(n => n === 1)).toBe(true);
		expect(await catalog()).toEqual(before);
	});
	it('leaves a terminally failed queue message unacked and never retries an ambiguous D1 batch', async () => {
		const { env, job } = await setup();
		const before = await catalog();
		const failure = new Error('injected ambiguous D1 outcome');
		const batchCall = vi.fn(async () => { throw failure; });
		const broken = testEnv({ CURSORS: withFault(env.CURSORS, 'batch', batchCall) });
		const batch = fakeBatch('bv-ct-index-compact', [job]);
		await expect(runCompactionBatch(batch, broken)).rejects.toBe(failure);
		expect(batchCall).toHaveBeenCalledTimes(1);
		expect(batch.acked).toEqual([]);
		expect(await catalog()).toEqual(before);
	});
});
