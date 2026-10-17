// SPDX-License-Identifier: BUSL-1.1
/**
 * The contract v2 surface: reversed-label keys and ranges, apexOf, the merge rule, the sorted-run block
 * codec with TSV escaping, the streaming k-way merge, and the D1 block index and catalog migration.
 */

import { env } from 'cloudflare:workers';
import { describe, expect, it } from 'vitest';
import catalogSql from '../../migrations/0002_catalog.sql?raw';
import {
	BLOCK_TARGET_BYTES,
	apexOf,
	decodeBlock,
	encodeRun,
	isSiblingRow,
	mergeObservations,
	mergeSortedRuns,
	nameKey,
	parseBlockIndex,
	rangeFor,
	serializeBlockIndex,
	siblingKey,
	streamRun,
} from '../codec';
import type { Env } from '../index';
import type { BlockIndexEntry, NameObservation, RunDescriptor, RunRow, SiblingObservation } from '../types';

const MAX = String.fromCharCode(0xffff);
const DAY = 86_400;
const NOW = 1_760_000_000;

function obs(name: string, overrides: Partial<NameObservation> = {}): NameObservation {
	const k = nameKey(name);
	return {
		key: k.key,
		name: k.name,
		apex: apexOf(k.name) ?? k.name,
		firstSeen: NOW - 10 * DAY,
		notAfter: NOW + 80 * DAY,
		issuer: 'R11',
		wildcard: k.wildcard,
		...overrides,
	};
}

function sib(apex: string, sibling: string, overrides: Partial<SiblingObservation> = {}): SiblingObservation {
	return { key: siblingKey(apex, sibling), apex, sibling, firstSeen: NOW - DAY, notAfter: NOW + 60 * DAY, ...overrides };
}

const inRange = (key: string, range: { lo: string; hi: string }) => key >= range.lo && key <= range.hi;
const byKey = (a: RunRow, b: RunRow) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0);

/** Deterministic Fisher-Yates, so a failure reproduces. */
function shuffled<T>(items: T[], seed = 7): T[] {
	const out = [...items];
	let state = seed;
	for (let i = out.length - 1; i > 0; i--) {
		state = (state * 1_103_515_245 + 12_345) % 2 ** 31;
		const j = state % (i + 1);
		[out[i], out[j]] = [out[j]!, out[i]!];
	}
	return out;
}

/** About 120 bytes of TSV per row, so 3,000 rows span several 64 KB blocks. */
function manyNames(count: number, tag = 'h'): NameObservation[] {
	return Array.from({ length: count }, (_, i) =>
		obs(`${tag}-${i}.zone-${i % 37}.example${i % 5}.com`, { firstSeen: NOW - i, notAfter: NOW + i, issuer: `Issuer ${i % 7}` }),
	);
}

async function inflateText(bytes: Uint8Array): Promise<string> {
	return new Response(new Blob([bytes]).stream().pipeThrough(new DecompressionStream('deflate-raw'))).text();
}

async function deflateText(text: string): Promise<Uint8Array> {
	return new Uint8Array(await new Response(new Blob([text]).stream().pipeThrough(new CompressionStream('deflate-raw'))).arrayBuffer());
}

async function collect<T>(rows: AsyncIterable<T>): Promise<T[]> {
	const out: T[] = [];
	for await (const row of rows) out.push(row);
	return out;
}

const blockOf = (bytes: Uint8Array, entry: BlockIndexEntry) => bytes.subarray(entry.offset, entry.offset + entry.length);

describe('nameKey', () => {
	it('reverses the labels and joins them with \\x01', () => {
		expect(nameKey('www.dia.govt.nz')).toEqual({ key: 'nz\x01govt\x01dia\x01www', name: 'www.dia.govt.nz', wildcard: false });
		expect(nameKey('example.com').key).toBe('com\x01example');
		expect(nameKey('nz').key).toBe('nz');
	});

	it('lowercases and strips one trailing dot', () => {
		expect(nameKey('WWW.Example.COM.')).toEqual({ key: 'com\x01example\x01www', name: 'www.example.com', wildcard: false });
	});

	it('folds *.example.com into example.com with wildcard=true', () => {
		expect(nameKey('*.example.com')).toEqual({ key: 'com\x01example', name: 'example.com', wildcard: true });
		expect(nameKey('*.Example.COM.').key).toBe(nameKey('example.com').key);
	});

	it('refuses a name that could forge a key inside another range', () => {
		for (const bad of [
			'',
			'.',
			'*.',
			'a..b.com',
			'evil\x01com.example.org',
			'nul\x00.com',
			'tab\t.com',
			'line\n.com',
			'sp ace.com',
			'ünï.com',
			`x${MAX}.com`,
		]) {
			expect(() => nameKey(bad), JSON.stringify(bad)).toThrow(RangeError);
		}
	});
});

describe('siblingKey', () => {
	it("is 's\\x00' + the reversed apex + '\\x00' + the sibling", () => {
		expect(siblingKey('Example.com', 'other.org.')).toBe('s\x00com\x01example\x00other.org');
	});

	it('keeps every sibling of an apex under one prefix, apart from that apex name keys', () => {
		const prefix = 's\x00com\x01example\x00';
		expect(siblingKey('example.com', 'a.net').startsWith(prefix)).toBe(true);
		expect(siblingKey('example.com', 'zz.org').startsWith(prefix)).toBe(true);
		expect(inRange(siblingKey('example.com', 'a.net'), rangeFor('example.com'))).toBe(false);
	});
});

describe('rangeFor', () => {
	it('is the key of the domain up to key + \\x01\\uffff', () => {
		expect(rangeFor('govt.nz')).toEqual({ lo: 'nz\x01govt', hi: `nz\x01govt\x01${MAX}` });
		expect(rangeFor('Example.COM.')).toEqual({ lo: 'com\x01example', hi: `com\x01example\x01${MAX}` });
		expect(rangeFor('*.example.com')).toEqual(rangeFor('example.com'));
	});

	it('covers govt.nz itself, dia.govt.nz and www.dia.govt.nz, but NOT xgovt.nz', () => {
		const range = rangeFor('govt.nz');
		for (const name of ['govt.nz', 'dia.govt.nz', 'www.dia.govt.nz', '*.dia.govt.nz', 'a.b.c.digital.govt.nz', '~.govt.nz']) {
			expect(inRange(nameKey(name).key, range), name).toBe(true);
		}
		for (const name of ['xgovt.nz', 'govtx.nz', 'gov.nz', 'nz', 'dia.govt.nzx', 'govt.nz.example.com', 'dia.govt.com']) {
			expect(inRange(nameKey(name).key, range), name).toBe(false);
		}
	});

	it('is one contiguous stretch of the sorted keyspace', () => {
		const names = [
			'xgovt.nz',
			'www.dia.govt.nz',
			'gov.nz',
			'govt.nz',
			'a.govtx.nz',
			'dia.govt.nz',
			'zz.nz',
			'aa.nz',
			'z.digital.govt.nz',
			'example.com',
		];
		const inside = names
			.map((name) => nameKey(name).key)
			.sort()
			.map((key) => inRange(key, rangeFor('govt.nz')));
		const first = inside.indexOf(true);
		const last = inside.lastIndexOf(true);
		expect(inside.slice(first, last + 1).every(Boolean)).toBe(true);
		expect(inside.filter(Boolean)).toHaveLength(4);
	});
});

describe('apexOf', () => {
	it('uses the PSL private section, as bv-mcp does', () => {
		expect(apexOf('foo.workers.dev')).toBe('foo.workers.dev');
		expect(apexOf('api.foo.workers.dev')).toBe('foo.workers.dev');
	});

	it('finds the registrable domain beneath multi-label public suffixes', () => {
		expect(apexOf('dia.govt.nz')).toBe('dia.govt.nz');
		expect(apexOf('www.dia.govt.nz')).toBe('dia.govt.nz');
		expect(apexOf('a.b.example.co.uk')).toBe('example.co.uk');
	});

	it('has no apex for a public suffix itself, which is why suffix queries are key ranges', () => {
		expect(apexOf('govt.nz')).toBeNull();
	});
});

describe('mergeObservations', () => {
	const a = obs('www.example.com', { firstSeen: 100, notAfter: 5_000, issuer: 'R11' });
	const b = obs('*.www.example.com', { firstSeen: 50, notAfter: 9_000, issuer: 'E5' });
	const c = obs('www.example.com', { firstSeen: 300, notAfter: 9_000, issuer: 'ZeroSSL' });

	it('takes firstSeen=min, notAfter=max, issuer from the larger notAfter, and ORs wildcard', () => {
		expect(b.key).toBe(a.key);
		expect(mergeObservations(a, b)).toEqual({ ...a, firstSeen: 50, notAfter: 9_000, issuer: 'E5', wildcard: true });
	});

	it('is idempotent', () => {
		for (const row of [a, b, c]) expect(mergeObservations(row, row)).toEqual(row);
		const ab = mergeObservations(a, b);
		expect(mergeObservations(ab, b)).toEqual(ab);
		expect(mergeObservations(ab, ab)).toEqual(ab);
	});

	it('is commutative, including when notAfter ties', () => {
		expect(mergeObservations(a, b)).toEqual(mergeObservations(b, a));
		expect(mergeObservations(b, c)).toEqual(mergeObservations(c, b));
	});

	it('gives the same row for every order of three observations', () => {
		const orders = [
			[a, b, c],
			[a, c, b],
			[b, a, c],
			[b, c, a],
			[c, a, b],
			[c, b, a],
		];
		const results = orders.map(([x, y, z]) => mergeObservations(mergeObservations(x!, y!), z!));
		for (const result of results) expect(result).toEqual(results[0]);
		expect(results[0]).toEqual({ ...a, firstSeen: 50, notAfter: 9_000, issuer: 'ZeroSSL', wildcard: true });
	});

	it('merges sibling rows by the same rule', () => {
		const s1 = sib('example.com', 'other.org', { firstSeen: 10, notAfter: 100 });
		const s2 = sib('example.com', 'other.org', { firstSeen: 5, notAfter: 50 });
		expect(mergeObservations(s1, s2)).toEqual({ ...s1, firstSeen: 5, notAfter: 100 });
		expect(mergeObservations(s2, s1)).toEqual(mergeObservations(s1, s2));
		expect(mergeObservations(s1, s1)).toEqual(s1);
	});

	it('leaves its inputs untouched and refuses rows with different keys', () => {
		const snapshot = structuredClone([a, b]);
		mergeObservations(a, b);
		expect([a, b]).toEqual(snapshot);
		expect(() => mergeObservations(a, obs('api.example.com'))).toThrow(RangeError);
	});
});

describe('encodeRun / decodeBlock', () => {
	it('round-trips every row in key order across several ~64 KB blocks', async () => {
		const rows = manyNames(3_000);
		const sorted = [...rows].sort(byKey);
		const run = await encodeRun(shuffled(rows));

		expect(run.rows).toBe(3_000);
		expect(run.keyLo).toBe(sorted[0]!.key);
		expect(run.keyHi).toBe(sorted.at(-1)!.key);
		expect(run.blockIndex.length).toBeGreaterThanOrEqual(4);

		const decoded: RunRow[] = [];
		for (const entry of run.blockIndex) decoded.push(...(await decodeBlock(blockOf(run.bytes, entry))));
		expect(decoded).toEqual(sorted);
	});

	it('lays blocks end to end, each at most 64 KB before deflate-raw, each decoding alone from its byte range', async () => {
		const sorted = manyNames(3_000).sort(byKey);
		const run = await encodeRun(sorted);
		let offset = 0;
		let rowsBefore = 0;
		for (const [i, entry] of run.blockIndex.entries()) {
			expect(entry.offset).toBe(offset);
			const block = blockOf(run.bytes, entry);
			const rawBytes = new TextEncoder().encode(await inflateText(block)).byteLength;
			expect(rawBytes).toBeLessThanOrEqual(BLOCK_TARGET_BYTES);
			if (i < run.blockIndex.length - 1) expect(rawBytes).toBeGreaterThan(BLOCK_TARGET_BYTES - 200);

			const rows = await decodeBlock(block);
			expect(rows[0]!.key).toBe(entry.firstKey);
			expect(rows).toEqual(sorted.slice(rowsBefore, rowsBefore + rows.length));
			rowsBefore += rows.length;
			offset += entry.length;
		}
		expect(offset).toBe(run.bytes.byteLength);
		expect(rowsBefore).toBe(3_000);
	});

	it('decodes one middle block given only its own bytes', async () => {
		const sorted = manyNames(3_000).sort(byKey);
		const run = await encodeRun(sorted);
		const middle = run.blockIndex[2]!;
		const alone = await decodeBlock(new Uint8Array(blockOf(run.bytes, middle)));
		const start = sorted.findIndex((row) => row.key === middle.firstKey);
		expect(alone).toEqual(sorted.slice(start, start + alone.length));
		expect(alone.at(-1)!.key < run.blockIndex[3]!.firstKey).toBe(true);
	});

	it('merges input rows that share a key, so a run holds one row per key', async () => {
		const plain = obs('a.example.com', { notAfter: NOW + 1, issuer: 'R10' });
		const wild = obs('*.a.example.com', { notAfter: NOW + 2, issuer: 'R11' });
		const run = await encodeRun([plain, wild]);
		expect(run.rows).toBe(1);
		expect(await decodeBlock(run.bytes)).toEqual([mergeObservations(plain, wild)]);
	});

	it('round-trips a sibling run', async () => {
		const rows = [sib('example.com', 'zeta.org'), sib('example.com', 'alpha.net'), sib('dia.govt.nz', 'digital.govt.nz')];
		const run = await encodeRun(rows);
		const decoded = await decodeBlock(run.bytes);
		expect(decoded).toEqual([...rows].sort(byKey));
		expect(decoded.every(isSiblingRow)).toBe(true);
		// Sibling keys sort by reversed apex: com before nz.
		expect(run.keyLo).toBe(siblingKey('example.com', 'alpha.net'));
		expect(run.keyHi).toBe(siblingKey('dia.govt.nz', 'digital.govt.nz'));
	});

	it('encodes an empty run as no blocks', async () => {
		expect(await encodeRun([])).toEqual({ bytes: new Uint8Array(0), blockIndex: [], keyLo: '', keyHi: '', rows: 0 });
	});

	it('refuses a truncated block rather than return partial rows', async () => {
		const run = await encodeRun(manyNames(200));
		await expect(decodeBlock(run.bytes.subarray(0, run.bytes.byteLength - 8))).rejects.toThrow();
	});
});

describe('TSV escaping', () => {
	const nasty = 'Tab\there, new\nline, cr\rhere, back\\slash, literal \\t and \\n';

	it('escapes tab, newline, carriage return and backslash, so each row stays one line of 7 columns', async () => {
		const row = obs('x.example.com', { issuer: nasty });
		const run = await encodeRun([row, obs('y.example.com')]);
		const lines = (await inflateText(run.bytes)).split('\n');
		expect(lines).toHaveLength(3);
		expect(lines[2]).toBe('');
		expect(lines[0]!.split('\t')).toHaveLength(7);
		expect(lines[0]).toContain('Tab\\there, new\\nline, cr\\rhere, back\\\\slash, literal \\\\t and \\\\n');
		expect(await decodeBlock(run.bytes)).toEqual([row, obs('y.example.com')]);
	});

	it('refuses a row with an unknown escape or the wrong column count', async () => {
		await expect(decodeBlock(await deflateText('com\x01example\texample.com\texample.com\t1\t2\tbad\\q\t0\n'))).rejects.toThrow(RangeError);
		await expect(decodeBlock(await deflateText('com\x01example\texample.com\t1\n'))).rejects.toThrow(RangeError);
		await expect(decodeBlock(await deflateText('com\x01example\texample.com\texample.com\tsoon\t2\tR11\t0\n'))).rejects.toThrow(RangeError);
	});

	it('refuses to write a non-integer epoch', async () => {
		await expect(encodeRun([obs('x.example.com', { notAfter: Number.NaN })])).rejects.toThrow(RangeError);
	});
});

describe('mergeSortedRuns', () => {
	// Three overlapping runs. a: newest notAfter and issuer from run 2, oldest firstSeen and the wildcard from run 3.
	// b: expired in run 1, renewed in run 2. c: expired everywhere, dropped. d: run 1 only. e: notAfter == now, kept.
	const run1 = [
		obs('a.example.com', { firstSeen: 100, notAfter: NOW + 10, issuer: 'R10' }),
		obs('b.example.com', { firstSeen: 200, notAfter: NOW - 5, issuer: 'R10' }),
		obs('d.example.com', { firstSeen: 300, notAfter: NOW + 5, issuer: 'R10' }),
		...manyNames(1_500, 'one'),
	];
	const run2 = [
		obs('a.example.com', { firstSeen: 150, notAfter: NOW + 20, issuer: 'R11' }),
		obs('b.example.com', { firstSeen: 400, notAfter: NOW + 30, issuer: 'E6' }),
		obs('c.example.com', { firstSeen: 400, notAfter: NOW - 1, issuer: 'E6' }),
		...manyNames(1_500, 'one').map((row) => ({ ...row, notAfter: row.notAfter + 50, issuer: 'Renewed' })),
	];
	const run3 = [
		obs('*.a.example.com', { firstSeen: 50, notAfter: NOW - 100, issuer: 'Old CA' }),
		obs('c.example.com', { firstSeen: 10, notAfter: NOW - 2, issuer: 'Old CA' }),
		obs('e.example.com', { firstSeen: 600, notAfter: NOW, issuer: 'R11' }),
		...manyNames(1_500, 'three'),
	];

	async function encoded() {
		const runs = await Promise.all([run1, run2, run3].map((rows) => encodeRun(rows)));
		const fetched: string[] = [];
		const inputs = runs.map((run, i) =>
			streamRun(run.blockIndex, async (entry) => {
				fetched.push(`${i}@${entry.offset}`);
				return blockOf(run.bytes, entry);
			}),
		);
		return { runs, inputs, fetched };
	}

	it('merges overlaps across three runs and drops rows that expired before now', async () => {
		const { inputs } = await encoded();
		const out = await collect(mergeSortedRuns(inputs, NOW));
		const find = (name: string) => out.find((row) => !isSiblingRow(row) && row.name === name);

		expect(find('a.example.com')).toEqual(obs('a.example.com', { firstSeen: 50, notAfter: NOW + 20, issuer: 'R11', wildcard: true }));
		expect(find('b.example.com')).toEqual(obs('b.example.com', { firstSeen: 200, notAfter: NOW + 30, issuer: 'E6' }));
		expect(find('c.example.com')).toBeUndefined();
		expect(find('d.example.com')).toEqual(run1[2]);
		expect(find('e.example.com')).toEqual(run3[2]);

		// The 1,500 'one-' names overlap in runs 1 and 2: run 2's later notAfter and issuer win.
		const renewed = out.filter((row) => !isSiblingRow(row) && row.name.startsWith('one-'));
		expect(renewed).toHaveLength(1_500);
		expect(renewed.every((row) => !isSiblingRow(row) && row.issuer === 'Renewed')).toBe(true);
		// 'three-' rows: i = 0 has notAfter == now and survives, none expired.
		expect(out.filter((row) => !isSiblingRow(row) && row.name.startsWith('three-'))).toHaveLength(1_500);

		expect(out).toHaveLength(4 + 1_500 + 1_500);
		for (let i = 1; i < out.length; i++) expect(out[i - 1]!.key < out[i]!.key).toBe(true);
	});

	it('streams block by block: the first row needs one block per run, and no block is fetched twice', async () => {
		const { runs, inputs, fetched } = await encoded();
		const totalBlocks = runs.reduce((sum, run) => sum + run.blockIndex.length, 0);
		expect(totalBlocks).toBeGreaterThanOrEqual(6);

		const merged = mergeSortedRuns(inputs, NOW);
		const first = await merged.next();
		expect(first.done).toBe(false);
		expect(fetched).toHaveLength(3);

		let rest = 0;
		for await (const _ of merged) rest++;
		expect(rest).toBeGreaterThan(0);
		expect(fetched).toHaveLength(totalBlocks);
		expect(new Set(fetched).size).toBe(totalBlocks);
	});

	it('accepts plain arrays and folds duplicate keys inside one input', async () => {
		const x1 = obs('x.example.com', { notAfter: NOW + 1 });
		const x2 = obs('x.example.com', { notAfter: NOW + 9, issuer: 'Later' });
		expect(await collect(mergeSortedRuns([[x1, x2], []], NOW))).toEqual([mergeObservations(x1, x2)]);
	});

	it('refuses an input whose keys go backwards', async () => {
		await expect(collect(mergeSortedRuns([[obs('b.example.com'), obs('a.example.com')]], NOW))).rejects.toThrow(RangeError);
	});

	it('closes every input when the caller stops early', async () => {
		const closed: number[] = [];
		const source = (id: number) =>
			(function* () {
				try {
					yield obs(`n${id}.example.com`);
					yield obs(`z${id}.example.com`);
				} finally {
					closed.push(id);
				}
			})();
		for await (const _ of mergeSortedRuns([source(1), source(2)], NOW)) break;
		expect(closed.sort()).toEqual([1, 2]);
	});
});

describe('serializeBlockIndex / parseBlockIndex', () => {
	it('round-trips a real block index plus a large offset and a sibling key', async () => {
		const run = await encodeRun(manyNames(3_000));
		const entries = [...run.blockIndex, { firstKey: siblingKey('example.com', 'other.org'), offset: 2 ** 40, length: 70_000 }];
		expect(parseBlockIndex(serializeBlockIndex(entries))).toEqual(entries);
		expect(parseBlockIndex(serializeBlockIndex([]))).toEqual([]);
	});

	it('reads the bytes as an ArrayBuffer, a view and a number array', () => {
		const entries = [{ firstKey: 'com\x01example', offset: 0, length: 12_345 }];
		const bytes = serializeBlockIndex(entries);
		expect(parseBlockIndex(bytes.slice().buffer)).toEqual(entries);
		expect(parseBlockIndex(new DataView(bytes.buffer))).toEqual(entries);
		expect(parseBlockIndex([...bytes])).toEqual(entries);
	});

	it('refuses a wrong version, a truncated index and trailing bytes', () => {
		const bytes = serializeBlockIndex([{ firstKey: 'com\x01example', offset: 1, length: 2 }]);
		expect(() => parseBlockIndex(Uint8Array.of(9, ...bytes.subarray(1)))).toThrow(RangeError);
		expect(() => parseBlockIndex(bytes.subarray(0, bytes.length - 1))).toThrow(RangeError);
		expect(() => parseBlockIndex(Uint8Array.of(...bytes, 0))).toThrow(RangeError);
		expect(() => serializeBlockIndex([{ firstKey: 'k', offset: -1, length: 1 }])).toThrow(RangeError);
	});
});

describe('migrations/0002_catalog.sql on D1', () => {
	it('creates runs, meta and ops_ledger; a runs row keeps its keys and block index, and range queries find it', async () => {
		const db = (env as unknown as Env).CURSORS;
		const statements = catalogSql
			.split(';')
			.map((statement) => statement.trim())
			.filter((statement) => statement.replace(/^--.*$/gm, '').trim() !== '');
		await db.batch(statements.map((statement) => db.prepare(statement)));

		const insert = db.prepare(
			'INSERT INTO runs (id, generation, tier, key_lo, key_hi, r2_key, rows, bytes, block_index, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
		);
		const names = await encodeRun(manyNames(3_000));
		const siblings = await encodeRun([sib('example.com', 'alpha.net'), sib('example.com', 'zeta.org')]);
		await db.batch([
			insert.bind(
				't0-names',
				1,
				0,
				names.keyLo,
				names.keyHi,
				't0/names.run',
				names.rows,
				names.bytes.byteLength,
				serializeBlockIndex(names.blockIndex),
				'2026-10-17T00:00:00Z',
			),
			insert.bind(
				't0-siblings',
				1,
				0,
				siblings.keyLo,
				siblings.keyHi,
				't0/siblings.run',
				siblings.rows,
				siblings.bytes.byteLength,
				serializeBlockIndex(siblings.blockIndex),
				'2026-10-17T00:00:00Z',
			),
		]);

		const row = await db.prepare('SELECT * FROM runs WHERE id = ?').bind('t0-names').first<RunDescriptor>();
		expect(row).toMatchObject({ generation: 1, tier: 0, key_lo: names.keyLo, key_hi: names.keyHi, rows: 3_000 });
		expect(parseBlockIndex(row!.block_index)).toEqual(names.blockIndex);

		// The read path's overlap query: D1's text order must agree with the codec's key order.
		const overlapping = (range: { lo: string; hi: string }) =>
			db
				.prepare('SELECT id FROM runs WHERE generation = ? AND key_lo <= ? AND key_hi >= ? ORDER BY id')
				.bind(1, range.hi, range.lo)
				.all<{ id: string }>()
				.then((result) => result.results.map((r) => r.id));
		expect(await overlapping(rangeFor('example0.com'))).toEqual(['t0-names']);
		expect(await overlapping(rangeFor('govt.nz'))).toEqual([]);
		// Sibling keys carry '\x00': it must survive binding, storage and comparison.
		const siblingPrefix = siblingKey('example.com', 'a.net').slice(0, -'a.net'.length);
		expect(await overlapping({ lo: siblingPrefix, hi: `${siblingPrefix}${MAX}` })).toEqual(['t0-siblings']);
		const siblingRow = await db.prepare('SELECT key_lo FROM runs WHERE id = ?').bind('t0-siblings').first<{ key_lo: string }>();
		expect(siblingRow?.key_lo).toBe(siblings.keyLo);

		await expect(insert.bind('bad-tier', 1, 4, 'a', 'b', 'k', 0, 0, null, 'now').run()).rejects.toThrow();
		await db.prepare("INSERT INTO meta (k, v) VALUES ('current_generation', '1')").run();
		await db.prepare("INSERT INTO ops_ledger (day, r2_class_a, r2_class_b, d1_rows) VALUES ('2026-10-17', 1, 2, 3)").run();
		expect(await db.prepare('SELECT killed FROM ops_ledger').first<{ killed: number }>()).toEqual({ killed: 0 });
	});
});
