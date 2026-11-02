// SPDX-License-Identifier: BUSL-1.1
import { beforeEach, describe, expect, it } from 'vitest';
import bench from '../../bench/src/index';
import { encodeRun, serializeBlockIndex } from '../codec';
import { MAX_WINDOW_BYTES, MIN_WINDOW_BYTES, READ_BUDGET_BYTES } from '../indexer/compact';
import { applyCatalog, obs, testEnv, withFault } from './indexer-harness';

beforeEach(applyCatalog);

describe('production-window merge benchmark', () => {
	it('uses production window budgets, preserves block-mode output, and counts whole retained windows', async () => {
		const env = testEnv();
		let blocks = 0;
		let largestWindow = 0;
		for (let input = 0; input < 2; input++) {
			const rows = Array.from({ length: 1500 }, (_, i) => obs(`host-${String(i).padStart(5, '0')}-${'x'.repeat(60)}.example.test`, {
				notAfter: 2_000_000_000,
				issuer: `issuer-${input}`,
			}));
			const encoded = await encodeRun(rows);
			expect(encoded.blockIndex.length).toBeGreaterThan(1);
			blocks += encoded.blockIndex.length;
			largestWindow = Math.max(largestWindow, encoded.bytes.byteLength);
			const key = `runs/g1/test-${input}.run`;
			await env.INDEX.put(key, encoded.bytes);
			await env.CURSORS.prepare('INSERT INTO runs (id, generation, tier, r2_key, rows, bytes, block_index) VALUES (?1, 1, 1, ?1, ?2, ?3, ?4)')
				.bind(key, rows.length, encoded.bytes.byteLength, serializeBlockIndex(encoded.blockIndex)).run();
		}
		const lengths: number[] = [];
		const bucket = withFault(env.INDEX, 'get', async (...args: unknown[]) => {
			const options = args[1] as { range?: { length?: number } };
			if (options?.range?.length !== undefined) lengths.push(options.range.length);
			return env.INDEX.get(...args as [string, R2GetOptions]);
		});
		const request = async (mode: string) => {
			const response = await bench.fetch(new Request(`https://example.test/merge?inputs=2&fetch=${mode}&write=0`, {
				method: 'POST', headers: { authorization: 'Bearer synthetic-bench-key' },
			}), { BENCH: bucket, BENCH_DB: env.CURSORS, BENCH_KEY: 'synthetic-bench-key' });
			expect(response.status).toBe(200);
			return response.json<Record<string, number | boolean>>();
		};
		const window = await request('window');
		expect(window.windowBytes).toBe(Math.min(MAX_WINDOW_BYTES, Math.max(MIN_WINDOW_BYTES, Math.floor(READ_BUDGET_BYTES / 2))));
		expect(window.productionReadPath).toBe(true);
		expect(window.blockReads).toBe(2);
		expect(lengths).toHaveLength(2);
		expect(Math.max(...lengths)).toBe(largestWindow);
		expect(window.peakInputBytesAccounted).toBeGreaterThanOrEqual(largestWindow);
		const block = await request('block');
		expect(block.blockReads).toBe(blocks);
		expect(block.productionReadPath).toBe(false);
		expect(window.outputRows).toBe(block.outputRows);
		expect(window.outputBytes).toBe(block.outputBytes);
		const object = await request('object');
		expect(object.outputRows).toBe(window.outputRows);
		expect(object.outputBytes).toBe(window.outputBytes);
		expect(object.productionReadPath).toBe(false);
	});
	it('fails closed on a truncated production window instead of reporting a passing merge', async () => {
		const env = testEnv();
		const encoded = await encodeRun([obs('host.example.test', { notAfter: 2_000_000_000 })]);
		const key = 'runs/g1/short.run';
		await env.INDEX.put(key, encoded.bytes);
		await env.CURSORS.prepare('INSERT INTO runs (id, generation, tier, r2_key, rows, bytes, block_index) VALUES (?1, 1, 1, ?1, 1, ?2, ?3)')
			.bind(key, encoded.bytes.byteLength, serializeBlockIndex(encoded.blockIndex)).run();
		const bucket = withFault(env.INDEX, 'get', async () => ({ arrayBuffer: async () => new ArrayBuffer(1) }));
		const response = await bench.fetch(new Request('https://example.test/merge?inputs=4&fetch=window', {
			method: 'POST', headers: { authorization: 'Bearer synthetic-bench-key' },
		}), { BENCH: bucket, BENCH_DB: env.CURSORS, BENCH_KEY: 'synthetic-bench-key' });
		expect(response.status).toBe(503);
		const body = await response.json<{ error: string; pass?: unknown }>();
		expect(body.error).toContain('short read');
		expect(body.pass).toBeUndefined();
	});

});
