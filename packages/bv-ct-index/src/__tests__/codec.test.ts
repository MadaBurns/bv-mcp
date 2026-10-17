// SPDX-License-Identifier: BUSL-1.1
/**
 * The shared bv-ct-index surface: partitioning, suffix rollups, R2 key helpers and the segment codec.
 * Pure functions only, so this runs in the package pool and in the root suite alike.
 */

import { describe, expect, it } from 'vitest';
import {
	PARTITIONS,
	SUFFIX_ROLLUPS,
	decodeSegment,
	encodeSegment,
	partBaseKey,
	partDeltaKey,
	partitionOf,
	rollupBaseKey,
	rollupDeltaKey,
	rollupsFor,
} from '../codec';
import type { NameRecord } from '../types';

function record(name: string, apex: string, certHashByte: string, overrides: Partial<NameRecord> = {}): NameRecord {
	return {
		name,
		apex,
		certHash: certHashByte.repeat(16),
		notBefore: 1_760_000_000,
		notAfter: 1_767_776_000,
		issuer: 'R11',
		sanApexes: [],
		...overrides,
	};
}

describe('partitionOf', () => {
	it('is FNV-1a 32-bit: matches the low byte of the published test vectors', () => {
		// fnv1a32('') = 0x811c9dc5, fnv1a32('a') = 0xe40c292c, fnv1a32('foobar') = 0xbf9cf968.
		expect(partitionOf('')).toBe(0xc5);
		expect(partitionOf('a')).toBe(0x2c);
		expect(partitionOf('foobar')).toBe(0x68);
	});

	it('returns stable golden partitions for three apexes', () => {
		// Computed by an independent FNV-1a implementation, not by this module.
		expect(partitionOf('example.com')).toBe(38);
		expect(partitionOf('dia.govt.nz')).toBe(221);
		expect(partitionOf('blackveilsecurity.com')).toBe(233);
	});

	it('lowercases the apex before hashing', () => {
		expect(partitionOf('Example.COM')).toBe(partitionOf('example.com'));
		expect(partitionOf('DIA.GOVT.NZ')).toBe(221);
	});

	it('always returns an integer partition in [0, PARTITIONS), and reaches every partition', () => {
		expect(PARTITIONS).toBe(256);
		const seen = new Set<number>();
		for (let i = 0; i < 20_000; i++) {
			const p = partitionOf(`host${i}.example${i % 97}.com`);
			expect(Number.isInteger(p)).toBe(true);
			expect(p).toBeGreaterThanOrEqual(0);
			expect(p).toBeLessThan(PARTITIONS);
			seen.add(p);
		}
		expect(seen.size).toBe(PARTITIONS);
	});
});

describe('rollupsFor', () => {
	it('puts an apex beneath an allowlisted suffix into that rollup', () => {
		expect(rollupsFor('dia.govt.nz')).toEqual(['govt.nz']);
		expect(rollupsFor('Agency.GOV')).toEqual(['gov']);
	});

	it('returns no rollup for an apex beneath no allowlisted suffix', () => {
		expect(rollupsFor('example.com')).toEqual([]);
	});

	it("matches on a '.' boundary only, and not the suffix itself", () => {
		expect(rollupsFor('notgovt.nz')).toEqual([]);
		expect(rollupsFor('govt.nz')).toEqual([]);
	});

	it('only ever names allowlisted suffixes', () => {
		for (const suffix of SUFFIX_ROLLUPS) expect(rollupsFor(`x.${suffix}`)).toContain(suffix);
	});
});

describe('R2 key helpers', () => {
	it('zero-pads partitions to 2 lowercase hex digits', () => {
		expect(partBaseKey(0)).toBe('part/00/base.ndjson.gz');
		expect(partBaseKey(10)).toBe('part/0a/base.ndjson.gz');
		expect(partBaseKey(255)).toBe('part/ff/base.ndjson.gz');
		expect(partDeltaKey(5, 1_760_000_000_000, 'k3x9')).toBe('part/05/delta/1760000000000-k3x9.ndjson.gz');
	});

	it('refuses a partition no reader would ever list', () => {
		for (const p of [-1, 256, 1.5, Number.NaN]) {
			expect(() => partBaseKey(p)).toThrow(RangeError);
			expect(() => partDeltaKey(p, 1, 'r')).toThrow(RangeError);
		}
	});

	it('builds rollup keys under the suffix', () => {
		expect(rollupBaseKey('govt.nz')).toBe('rollup/govt.nz/base.ndjson.gz');
		expect(rollupDeltaKey('govt.nz', 1_760_000_000_000, 'k3x9')).toBe('rollup/govt.nz/delta/1760000000000-k3x9.ndjson.gz');
	});
});

describe('encodeSegment / decodeSegment', () => {
	it('round-trips every record and returns them sorted by (apex, name, certHash)', async () => {
		const input = [
			record('www.example.com', 'example.com', 'bb'),
			record('dia.govt.nz', 'dia.govt.nz', 'aa', { issuer: 'DigiCert', sanApexes: ['digital.govt.nz'] }),
			record('api.example.com', 'example.com', 'cc'),
			record('www.example.com', 'example.com', 'aa', { notAfter: 1_770_000_000 }),
			record('a.blackveilsecurity.com', 'blackveilsecurity.com', 'dd'),
		];
		const snapshot = structuredClone(input);

		const bytes = await encodeSegment(input);
		const decoded = await decodeSegment(bytes);

		expect(decoded).toEqual([snapshot[4], snapshot[1], snapshot[2], snapshot[3], snapshot[0]]);
		// Sorting works on a copy: the caller's array keeps its order.
		expect(input).toEqual(snapshot);
	});

	it('writes gzip (magic bytes 1f 8b) around NDJSON, one record per line', async () => {
		const records = [record('b.example.com', 'example.com', 'bb'), record('a.example.com', 'example.com', 'aa')];
		const bytes = await encodeSegment(records);
		expect([bytes[0], bytes[1]]).toEqual([0x1f, 0x8b]);

		const text = await new Response(new Blob([bytes]).stream().pipeThrough(new DecompressionStream('gzip'))).text();
		const lines = text.split('\n');
		expect(lines).toHaveLength(3);
		expect(lines[2]).toBe('');
		expect(JSON.parse(lines[0]!).name).toBe('a.example.com');
		expect(JSON.parse(lines[1]!).name).toBe('b.example.com');
	});

	it('keeps only NameRecord fields, so extra properties never reach a segment', async () => {
		const withExtra = { ...record('a.example.com', 'example.com', 'aa'), leafDer: 'not-a-segment-field' } as NameRecord;
		const [decoded] = await decodeSegment(await encodeSegment([withExtra]));
		expect(decoded).toEqual(record('a.example.com', 'example.com', 'aa'));
	});

	it('round-trips an empty segment', async () => {
		expect(await decodeSegment(await encodeSegment([]))).toEqual([]);
	});
});
