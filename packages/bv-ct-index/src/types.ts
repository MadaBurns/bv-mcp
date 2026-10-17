// SPDX-License-Identifier: BUSL-1.1
/**
 * Shared bv-ct-index data shapes (US-12 contract, "Shared surface").
 *
 * The tailer (src/tailer/), indexer and compactor (src/indexer/) and query API (src/api/)
 * are built in parallel against these. Changing one is a contract change.
 */

/** One (name, certificate) observation from a CT log entry. */
export interface NameRecord {
	/** A DNS name on the certificate. */
	name: string;
	/** Registrable domain (eTLD+1) of `name`. `partitionOf(apex)` selects the partition. */
	apex: string;
	/** First 16 bytes of sha256(leaf certificate DER), lowercase hex. */
	certHash: string;
	/** Epoch seconds. */
	notBefore: number;
	/** Epoch seconds. */
	notAfter: number;
	/** Issuer CN, or O when there is no CN. */
	issuer: string;
	/** The OTHER registrable domains on the same certificate, at most 32. */
	sanApexes: string[];
}

/** One Queue message from the tailer to the indexer: records parsed from one log, starting at `startIndex`. */
export interface EntryBatch {
	logId: string;
	startIndex: number;
	records: NameRecord[];
}

export interface IndexMeta {
	/** ISO timestamp of the first ingest. The index is forward-only from here. */
	indexStartedAt: string;
	logsTracked: number;
	lastCompactedAt: string | null;
}

/**
 * The read seam between the indexer and the query API. The indexer ticket implements it over R2;
 * the API ticket takes it by injection.
 *
 * Each read returns base plus pending deltas merged, deduped on (name, certHash) keeping the
 * greatest `notAfter`, with expired records (`notAfter` before now) dropped.
 */
export interface IndexReader {
	/** Records for one partition, `0 <= p < PARTITIONS`. */
	readPartition(p: number): Promise<NameRecord[]>;
	/** Records for one allowlisted public suffix in `SUFFIX_ROLLUPS`. */
	readRollup(suffix: string): Promise<NameRecord[]>;
	/** Null before the first ingest. */
	readMeta(): Promise<IndexMeta | null>;
}
