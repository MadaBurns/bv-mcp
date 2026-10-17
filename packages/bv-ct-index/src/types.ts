// SPDX-License-Identifier: BUSL-1.1
/**
 * Shared bv-ct-index data shapes (US-12 contract v2, "Data model" and "Read seam").
 *
 * The tailer, indexer/compactor and query API are built in parallel against these. Changing one is a
 * contract change.
 */

// key = reversed labels joined by '\x01', e.g. 'nz\x01govt\x01dia\x01www' — every domain/suffix is a contiguous key range
export interface NameObservation {
	key: string;
	name: string;
	apex: string;
	firstSeen: number;
	notAfter: number /* epoch s, max seen */;
	issuer: string;
	wildcard: boolean;
}
export interface SiblingObservation {
	key: string /* 's\x00' + reversed(apex) + '\x00' + sibling */;
	apex: string;
	sibling: string;
	firstSeen: number;
	notAfter: number;
}
// merge rule (idempotent, order-free): firstSeen=min, notAfter=max, issuer=from the row with the larger notAfter; drop rows with notAfter < now on any rewrite
export interface ObservationBatch {
	logId: string;
	startIndex: number;
	endIndex: number;
	names: NameObservation[];
	siblings: SiblingObservation[];
}

export interface ScanPage {
	names: NameObservation[];
	truncated: boolean;
	cursor: string | null;
}
export interface IndexReader {
	scan(domain: string, opts: { limit: number; cursor?: string | null }): Promise<ScanPage>; // all names == domain or under it, merged across tiers, expired dropped
	siblings(apex: string, opts: { limit: number }): Promise<{ siblings: SiblingObservation[]; truncated: boolean }>;
	meta(): Promise<{ indexStartedAt: string | null; freshThrough: string | null; generation: number }>;
}

/** One row of a sorted run. A run holds one kind only: name keys never start with the sibling prefix 's\x00'. */
export type RunRow = NameObservation | SiblingObservation;

/** One deflate-raw block of a run: the key of its first row, and its byte range in the R2 object. */
export interface BlockIndexEntry {
	firstKey: string;
	offset: number;
	length: number;
}

/**
 * One row of the D1 `runs` catalog table (migrations/0002_catalog.sql), column for column, so
 * `prepare(...).all<RunDescriptor>()` returns it as is. `block_index` holds `serializeBlockIndex` output;
 * read it back with `parseBlockIndex`, which accepts every shape D1 hands a BLOB back as.
 */
export interface RunDescriptor {
	id: string;
	generation: number;
	tier: 0 | 1 | 2 | 3;
	/** Smallest and largest row key in the run, both inclusive. */
	key_lo: string;
	key_hi: string;
	r2_key: string;
	rows: number;
	bytes: number;
	block_index: ArrayBuffer | ArrayBufferView | number[];
	/** ISO timestamp. */
	created_at: string;
}
