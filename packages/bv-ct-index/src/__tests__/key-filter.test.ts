// SPDX-License-Identifier: BUSL-1.1
/**
 * The per-run key filter (codec KEY_FILTER_VERSION) and the interval index (codec runSplitKey) that the catalog query
 * (read.ts catalogQuery) prunes with: the entry rule, no false negatives over the SQ-400 production runs, the SQL bit
 * test, the size cap, and the interval index against a brute-force overlap oracle.
 */

import { beforeEach, describe, expect, it } from 'vitest';
import {
	KEY_FILTER_BITS_PER_ENTRY,
	KEY_FILTER_MAX_ENTRIES,
	encodeRun,
	keyFilterEntries,
	keyFilterHashes,
	keyFilterProbe,
	nameKey,
	rangeFor,
	runSplitKey,
	siblingKey,
} from '../codec';
import { catalogQuery, keyFilterSql } from '../indexer/read';
import type { ScanQuery } from '../indexer/read';
import { T0_KEY_FILTER_BITS } from '../indexer/write';
import type { NameObservation } from '../types';
import { SQ400_RUN_KEYS } from './fixtures/sq400-run-keys';
import { T_S, applyCatalog, testEnv } from './indexer-harness';

beforeEach(applyCatalog);

const SEP = '\x01';
const MAX = String.fromCharCode(0xffff);
const BYTE_VALUES = Uint8Array.from({ length: 256 }, (_, i) => i);

/** A name row for a key; only the key matters to the filter. */
function row(key: string): NameObservation {
	const name = key.split(SEP).reverse().join('.');
	return { key, name, apex: name, firstSeen: T_S, notAfter: T_S + 86_400, issuer: 'R11', wildcard: false };
}

/** The domain keys a lookup can ask for that a key lies under: its label prefixes of two labels or more. */
function lookupKeys(key: string): string[] {
	const labels = key.split(SEP);
	return labels.slice(1).map((_, i) => labels.slice(0, i + 2).join(SEP));
}

/** How many of `probes` the filter rejects, through the reader's own SQL bit test. */
async function rejected(filter: Uint8Array, probes: readonly string[]): Promise<number> {
	const hashes = [0, 1, 2, 3, 4, 5].map((i) => `json_extract(value, '$[${i}]')`);
	const result = await testEnv()
		.CURSORS.prepare(`SELECT COUNT(*) AS n FROM json_each(?2) WHERE NOT ${keyFilterSql('?1', '?3', hashes)}`)
		.bind(filter, JSON.stringify(probes.map(keyFilterHashes)), BYTE_VALUES)
		.first<{ n: number }>();
	return Number(result!.n);
}

/** A deterministic pseudo-random source (mulberry32), so a failure reproduces. */
function random(seed: number): () => number {
	let state = seed;
	return () => {
		state = (state + 0x6d2b79f5) | 0;
		let t = Math.imul(state ^ (state >>> 15), 1 | state);
		t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
		return ((t ^ (t >>> 14)) >>> 0) / 4_294_967_296;
	};
}

describe('key filter entries', () => {
	it('enters two labels, three under a two-letter TLD with a short second label, and the apex part of a sibling key', () => {
		expect(keyFilterEntries(nameKey('www.example.com').key)).toEqual([`com${SEP}example`]);
		expect(keyFilterEntries(nameKey('www.example.co.nz').key)).toEqual([`nz${SEP}co`, `nz${SEP}co${SEP}example`]);
		expect(keyFilterEntries(nameKey('a.dia.govt.nz').key)).toEqual([`nz${SEP}govt`, `nz${SEP}govt${SEP}dia`]);
		expect(keyFilterEntries(nameKey('a.parliament.nz').key)).toEqual([`nz${SEP}parliament`]);
		expect(keyFilterEntries(nameKey('localhost').key)).toEqual([]);
		const prefix = siblingKey('example.com', 'a').slice(0, -1);
		expect(keyFilterEntries(siblingKey('example.com', 'other.org'))).toEqual([prefix]);

		expect(keyFilterProbe(rangeFor('example.com').lo)).toBe(`com${SEP}example`);
		expect(keyFilterProbe(rangeFor('www.example.com').lo)).toBe(`com${SEP}example`);
		expect(keyFilterProbe(rangeFor('example.co.nz').lo)).toBe(`nz${SEP}co${SEP}example`);
		expect(keyFilterProbe(rangeFor('govt.nz').lo)).toBe(`nz${SEP}govt`);
		expect(keyFilterProbe(rangeFor('nz').lo)).toBeNull();
		expect(keyFilterProbe(prefix)).toBe(prefix);
	});

	it('gives every lookup a key lies under a probe among that key own entries', () => {
		const next = random(401);
		const pick = (labels: readonly string[]) => labels[Math.floor(next() * labels.length)]!;
		const tlds = ['nz', 'uk', 'au', 'io', 'com', 'org', 'dev', 'x'];
		const seconds = ['co', 'com', 'govt', 'gov', 'ac', 'school', 'example', 'a', 'amazonaws'];
		for (let i = 0; i < 5_000; i++) {
			const labels = [pick(tlds), pick(seconds)];
			const depth = Math.floor(next() * 5);
			for (let d = 0; d < depth; d++) labels.push(pick(['www', 'a', 'mail', 'xn--bcher-kva', 's3', 'eu-west-1']));
			const key = labels.join(SEP);
			const entries = keyFilterEntries(key);
			for (const domain of lookupKeys(key)) expect(entries, `${domain} over ${key}`).toContain(keyFilterProbe(domain));
		}
	});
});

describe('key filter over the SQ-400 production runs', () => {
	it.each(Object.entries(SQ400_RUN_KEYS))('admits every lookup any key of run %s lies under', async (name, keys) => {
		const bits = name.startsWith('t0') ? T0_KEY_FILTER_BITS : KEY_FILTER_BITS_PER_ENTRY;
		const run = await encodeRun(
			keys.map((key) => row(key.split('.').join(SEP))),
			{ filterBitsPerEntry: bits },
		);
		const probes = [...new Set(keys.flatMap((key) => lookupKeys(key.split('.').join(SEP)).map((domain) => keyFilterProbe(domain)!)))];
		expect(run.rows).toBe(keys.length);
		expect(probes.length).toBeGreaterThan(keys.length / 4);
		expect(await rejected(run.keyFilter!, probes)).toBe(0);
	});

	it('rejects absent apexes at about the false-positive rate its size buys', async () => {
		const absent = Array.from({ length: 4_000 }, (_, i) => `com${SEP}absent-${i}-sq401`);
		for (const [name, keys] of Object.entries(SQ400_RUN_KEYS)) {
			const t0 = name.startsWith('t0');
			const run = await encodeRun(
				keys.map((key) => row(key.split('.').join(SEP))),
				{ filterBitsPerEntry: t0 ? T0_KEY_FILTER_BITS : KEY_FILTER_BITS_PER_ENTRY },
			);
			// Six probes at 16 bits per entry: 0.09% in theory; at 8 bits: 2.2%.
			const admitted = absent.length - (await rejected(run.keyFilter!, absent));
			expect(admitted / absent.length, name).toBeLessThan(t0 ? 0.004 : 0.04);
		}
	});

	it('sizes a filter by its distinct entries: one version byte plus bits per entry, at least 64 bits', async () => {
		const keys = ['com.example.www', 'com.example.mail', 'com.other', 'nz.co.shop.www', 'nz.co.shop', 'nz.co.cafe'];
		const run = await encodeRun(
			keys.map((key) => row(key.split('.').join(SEP))),
			{ filterBitsPerEntry: 16 },
		);
		// Entries: com.example, com.other, nz.co, nz.co.cafe, nz.co.shop = 5 x 16 bits = 80 bits = 10 bytes.
		expect(run.keyFilter!.byteLength).toBe(1 + 10);
		expect((await encodeRun([row(`com${SEP}one`)])).keyFilter!.byteLength).toBe(1 + 8);
	});

	it('stores no filter past KEY_FILTER_MAX_ENTRIES distinct entries', async () => {
		const rows = (n: number) => Array.from({ length: n }, (_, i) => row(`com${SEP}apex${String(i).padStart(6, '0')}`));
		expect((await encodeRun(rows(KEY_FILTER_MAX_ENTRIES))).keyFilter).not.toBeNull();
		expect((await encodeRun(rows(KEY_FILTER_MAX_ENTRIES + 1))).keyFilter).toBeNull();
	});

	it('admits a NULL, an unknown-version and a truncated filter', async () => {
		const sql = (filter: string) => `SELECT ${keyFilterSql(filter, '?2', ['?3'])} AS ok`;
		const db = testEnv().CURSORS;
		for (const filter of [null, Uint8Array.of(9, 0, 0), Uint8Array.of(1)]) {
			expect(await db.prepare(sql('?1')).bind(filter, BYTE_VALUES, 12_345).first('ok')).toBe(1);
		}
		expect(await db.prepare(sql('?1')).bind(Uint8Array.of(1, 0), BYTE_VALUES, 12_345).first('ok')).toBe(0);
	});
});

describe('interval index (key_split)', () => {
	const LABELS = ['a', 'b', 'co', 'com', 'nz', 'zz', 'a-b', 'x1', '0'];

	function randomKey(next: () => number): string {
		const labels = Array.from({ length: 1 + Math.floor(next() * 4) }, () => LABELS[Math.floor(next() * LABELS.length)]!);
		const key = labels.join(SEP);
		return next() < 0.15 ? `s\x00${key}\x00${labels[0]}` : key;
	}

	it('files every run at a split inside its bounds', () => {
		const next = random(7);
		for (let i = 0; i < 5_000; i++) {
			const [lo, hi] = [randomKey(next), randomKey(next)].sort();
			const split = runSplitKey(lo!, hi!)!;
			expect(lo === hi ? split === lo : split > lo! && split <= hi!, JSON.stringify([lo, hi, split])).toBe(true);
		}
		expect(runSplitKey('a', `b${String.fromCharCode(0xff)}`)).toBeNull();
	});

	it.each([11, 12, 13])('finds exactly the overlapping runs of the current generation against brute force (seed %i)', async (seed) => {
		const env = testEnv();
		const next = random(seed);
		const runs = Array.from({ length: 400 }, (_, i) => {
			const [lo, hi] = [randomKey(next), randomKey(next)].sort();
			// Every tenth run has no split, as written before migration 0005; every twentieth is in another generation.
			return { id: `r${i}`, lo: lo!, hi: hi!, split: i % 10 === 3 ? null : runSplitKey(lo!, hi!), generation: i % 20 === 7 ? 2 : 1 };
		});
		const insert = env.CURSORS.prepare(
			"INSERT INTO runs (id, generation, tier, key_lo, key_hi, r2_key, rows, bytes, block_index, created_at, key_split) VALUES (?1, ?2, 1, ?3, ?4, ?1, 1, 1, x'0100', 'x', ?5)",
		);
		await env.CURSORS.batch(runs.map((run) => insert.bind(run.id, run.generation, run.lo, run.hi, run.split)));

		for (let i = 0; i < 300; i++) {
			const domain = randomKey(next)
				.replace(/^s\x00/, '')
				.split('\x00')[0]!;
			const siblings = next() < 0.3;
			const lo = siblings ? `s\x00${domain}\x00` : domain;
			const hi = siblings ? `${lo}${MAX}` : `${domain}${SEP}${MAX}`;
			const after = next() < 0.3 ? `${lo}${SEP}b` : null;
			const query: ScanQuery = { lo, hi, after, limit: 10, siblings, now: 0 };
			const { sql, params } = catalogQuery(query);
			const { results } = await env.CURSORS.prepare(sql)
				.bind(...params)
				.all<{ r2_key: string }>();
			const start = after ?? lo;
			const expected = runs.filter((run) => run.generation === 1 && run.lo <= hi && run.hi >= start).map((run) => run.id);
			expect(results.map((r) => r.r2_key).sort(), JSON.stringify(query)).toEqual(expected.sort());
		}
	});
});
