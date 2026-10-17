// SPDX-License-Identifier: BUSL-1.1
/**
 * bv-ct-index partitioning, R2 key layout and segment codec (US-12 contract, "Shared surface").
 *
 * R2 layout (pp = partition as zero-padded lowercase hex):
 *   part/<pp>/base.ndjson.gz
 *   part/<pp>/delta/<ts>-<rand>.ndjson.gz
 *   rollup/<suffix>/base.ndjson.gz
 *   rollup/<suffix>/delta/<ts>-<rand>.ndjson.gz
 *
 * A segment is NDJSON, one NameRecord per line, sorted by (apex, name, certHash), gzipped with
 * CompressionStream. Workers-runtime APIs only.
 */

import type { NameRecord } from './types';

export const PARTITIONS = 256;

/**
 * Allowlisted public suffixes. A record whose apex ends in '.' + suffix is ALSO written to
 * rollup/<suffix>/, because a query for the suffix itself (govt.nz) spans many apexes and so many
 * partitions.
 */
export const SUFFIX_ROLLUPS: readonly string[] = ['govt.nz', 'gov.uk', 'gov.au', 'gc.ca', 'gov'];

const FNV_OFFSET_BASIS = 0x811c9dc5;
const FNV_PRIME = 0x01000193;
const PARTITION_HEX_WIDTH = (PARTITIONS - 1).toString(16).length;
const encoder = new TextEncoder();

/** FNV-1a 32-bit over the UTF-8 bytes of the lowercased apex, mod PARTITIONS. */
export function partitionOf(apex: string): number {
	let hash = FNV_OFFSET_BASIS;
	for (const byte of encoder.encode(apex.toLowerCase())) {
		hash = Math.imul(hash ^ byte, FNV_PRIME);
	}
	return (hash >>> 0) % PARTITIONS;
}

/** The rollups a record with this apex also belongs to. */
export function rollupsFor(apex: string): string[] {
	const lower = apex.toLowerCase();
	return SUFFIX_ROLLUPS.filter((suffix) => lower.endsWith(`.${suffix}`));
}

function partitionHex(p: number): string {
	// An out-of-range or fractional p would build a key that no reader or compactor ever lists.
	if (!Number.isInteger(p) || p < 0 || p >= PARTITIONS) throw new RangeError(`partition out of range: ${p}`);
	return p.toString(16).padStart(PARTITION_HEX_WIDTH, '0');
}

export function partBaseKey(p: number): string {
	return `part/${partitionHex(p)}/base.ndjson.gz`;
}

export function partDeltaKey(p: number, ts: number, rand: string): string {
	return `part/${partitionHex(p)}/delta/${ts}-${rand}.ndjson.gz`;
}

export function rollupBaseKey(suffix: string): string {
	return `rollup/${suffix}/base.ndjson.gz`;
}

export function rollupDeltaKey(suffix: string, ts: number, rand: string): string {
	return `rollup/${suffix}/delta/${ts}-${rand}.ndjson.gz`;
}

/** Code-unit order, not localeCompare: the order must not depend on the runtime's locale. */
function compareText(a: string, b: string): number {
	return a < b ? -1 : a > b ? 1 : 0;
}

function compareRecords(a: NameRecord, b: NameRecord): number {
	return compareText(a.apex, b.apex) || compareText(a.name, b.name) || compareText(a.certHash, b.certHash);
}

/** Only the NameRecord fields, in a fixed order, so a segment's bytes do not depend on how a record was built. */
function serialize(r: NameRecord): string {
	return JSON.stringify({
		name: r.name,
		apex: r.apex,
		certHash: r.certHash,
		notBefore: r.notBefore,
		notAfter: r.notAfter,
		issuer: r.issuer,
		sanApexes: r.sanApexes,
	});
}

/** Sorts a copy by (apex, name, certHash) and returns it as gzipped NDJSON. */
export async function encodeSegment(records: NameRecord[]): Promise<Uint8Array> {
	const lines = [...records].sort(compareRecords).map((r) => `${serialize(r)}\n`);
	const gzipped = new Blob(lines).stream().pipeThrough(new CompressionStream('gzip'));
	return new Uint8Array(await new Response(gzipped).arrayBuffer());
}

export async function decodeSegment(bytes: Uint8Array): Promise<NameRecord[]> {
	const text = await new Response(new Blob([bytes]).stream().pipeThrough(new DecompressionStream('gzip'))).text();
	const records: NameRecord[] = [];
	for (const line of text.split('\n')) {
		if (line !== '') records.push(JSON.parse(line) as NameRecord);
	}
	return records;
}
