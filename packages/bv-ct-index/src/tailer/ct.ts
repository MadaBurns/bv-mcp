// SPDX-License-Identifier: BUSL-1.1
/**
 * CT log formats the tailer reads: the Chrome log list v3, RFC 6962 get-entries leaves, and c2sp
 * static-ct-api checkpoints and data tiles. Pure functions over bytes and JSON; no I/O.
 */

export const LOG_LIST_URL = 'https://www.gstatic.com/ct/log_list/v3/log_list.json';
/** Entries per full static-ct data tile. */
export const TILE_WIDTH = 256;
/** Contract v2: these operators' logs are not tailed (SQ-350: every final cert also has an SCT from another operator). */
const EXCLUDED_OPERATOR = /^(geomys|ipng)\b/i;
const TAILED_STATES = ['usable', 'qualified'];

export interface TailedLog {
	/** The log list's base64 log_id; the log_cursors primary key. */
	logId: string;
	kind: 'rfc6962' | 'static';
	/** RFC 6962 base URL, or the static-ct monitoring prefix. Ends with '/'. */
	url: string;
}

interface ListedLog {
	log_id?: unknown;
	url?: unknown;
	monitoring_url?: unknown;
	state?: Record<string, unknown>;
	temporal_interval?: { end_exclusive?: unknown };
}

function tailable(log: ListedLog, now: number): boolean {
	if (!Object.keys(log.state ?? {}).some((state) => TAILED_STATES.includes(state))) return false;
	// A shard's interval bounds its certs' notAfter, not when it is written to: today's certs land in the
	// shards that end next year, so only shards whose interval has already ended are skipped.
	const end = log.temporal_interval?.end_exclusive;
	return typeof end !== 'string' || Date.parse(end) > now;
}

function tailedLog(log: ListedLog, kind: TailedLog['kind'], url: unknown): TailedLog | null {
	if (typeof log.log_id !== 'string' || typeof url !== 'string' || !url.startsWith('https://')) return null;
	return { logId: log.log_id, kind, url: url.endsWith('/') ? url : `${url}/` };
}

/**
 * The logs to tail from a parsed Chrome log list v3: RFC 6962 `logs` and static-ct `tiled_logs` that are
 * usable or qualified and whose temporal interval has not ended, minus the Geomys and IPng operators.
 * Sorted by log id, so the rotation order is stable.
 */
export function selectLogs(list: unknown, now: number): TailedLog[] {
	const operators = (list as { operators?: unknown })?.operators;
	if (!Array.isArray(operators)) throw new TypeError('log list has no operators array');
	const logs: TailedLog[] = [];
	for (const operator of operators as Array<{ name?: unknown; logs?: ListedLog[]; tiled_logs?: ListedLog[] }>) {
		if (typeof operator.name === 'string' && EXCLUDED_OPERATOR.test(operator.name)) continue;
		for (const log of operator.logs ?? []) {
			const tailed = tailable(log, now) ? tailedLog(log, 'rfc6962', log.url) : null;
			if (tailed) logs.push(tailed);
		}
		for (const log of operator.tiled_logs ?? []) {
			const tailed = tailable(log, now) ? tailedLog(log, 'static', log.monitoring_url) : null;
			if (tailed) logs.push(tailed);
		}
	}
	return logs.sort((a, b) => (a.logId < b.logId ? -1 : a.logId > b.logId ? 1 : 0));
}

function fromBase64(text: string): Uint8Array {
	const binary = atob(text);
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
	return bytes;
}

/** Bounds-checked big-endian reader over TLS presentation-language structures. */
class Reader {
	pos = 0;
	constructor(readonly bytes: Uint8Array) {}

	private take(length: number): number {
		const at = this.pos;
		if (at + length > this.bytes.length) throw new RangeError('CT entry is truncated');
		this.pos += length;
		return at;
	}
	uint(width: 1 | 2 | 3): number {
		const at = this.take(width);
		let value = 0;
		for (let i = 0; i < width; i++) value = value * 256 + this.bytes[at + i]!;
		return value;
	}
	skip(length: number): void {
		this.take(length);
	}
	/** An opaque<..> vector with a `width`-byte length prefix, as a view (no copy). */
	vector(width: 2 | 3): Uint8Array {
		const length = this.uint(width);
		const at = this.take(length);
		return this.bytes.subarray(at, at + length);
	}
}

const X509_ENTRY = 0;
const PRECERT_ENTRY = 1;

/**
 * The TBSCertificate of an RFC 6962 get-entries `leaf_input` (a MerkleTreeLeaf, RFC 6962 section 3.4), or
 * null for an x509_entry. Only the 12-byte header is decoded for an x509 entry.
 */
export function precertTbsFromLeafInput(leafInput: string): Uint8Array | null {
	// version(1) leaf_type(1) timestamp(8) entry_type(2): 12 bytes, exactly 16 base64 characters.
	const header = new Reader(fromBase64(leafInput.slice(0, 16)));
	if (header.uint(1) !== 0 || header.uint(1) !== 0) throw new RangeError('not a v1 timestamped_entry leaf');
	header.skip(8);
	const entryType = header.uint(2);
	if (entryType === X509_ENTRY) return null;
	if (entryType !== PRECERT_ENTRY) throw new RangeError(`unknown CT entry type ${entryType}`);
	const leaf = new Reader(fromBase64(leafInput));
	leaf.skip(12 + 32); // header, issuer_key_hash
	return leaf.vector(3);
}

/**
 * The entries of a static-ct-api data tile (c2sp.org/static-ct-api, TileLeaf): each precert entry's
 * TBSCertificate, or null for an x509 entry. Throws if the tile does not parse to the end.
 */
export function parseDataTile(tile: Uint8Array): Array<Uint8Array | null> {
	const reader = new Reader(tile);
	const entries: Array<Uint8Array | null> = [];
	while (reader.pos < tile.length) {
		reader.skip(8); // timestamp
		const entryType = reader.uint(2);
		if (entryType === X509_ENTRY) {
			reader.vector(3); // certificate
			reader.vector(2); // extensions
			reader.vector(2); // chain fingerprints
			entries.push(null);
		} else if (entryType === PRECERT_ENTRY) {
			reader.skip(32); // issuer_key_hash
			const tbs = reader.vector(3);
			reader.vector(2); // extensions
			reader.vector(3); // pre_certificate
			reader.vector(2); // chain fingerprints
			entries.push(tbs);
		} else {
			throw new RangeError(`unknown CT entry type ${entryType} in data tile`);
		}
	}
	return entries;
}

/** The c2sp tlog-tiles path of tile `index`: 3-digit groups, all but the last prefixed with 'x' (1234067 -> x001/x234/067). */
export function tilePath(index: number): string {
	const digits = String(index);
	const groups = digits.padStart(Math.ceil(digits.length / 3) * 3, '0').match(/\d{3}/g)!;
	return groups.map((group, i) => (i < groups.length - 1 ? `x${group}` : group)).join('/');
}

/** The tree size on the second line of a c2sp checkpoint note. */
export function checkpointTreeSize(checkpoint: string): number {
	const line = checkpoint.split('\n')[1] ?? '';
	const size = Number(line);
	if (!/^\d+$/.test(line) || !Number.isSafeInteger(size)) throw new RangeError(`bad checkpoint tree size ${JSON.stringify(line)}`);
	return size;
}
