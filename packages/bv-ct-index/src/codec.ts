// SPDX-License-Identifier: BUSL-1.1
/**
 * bv-ct-index keyspace and sorted-run codec (US-12 contract v2, "Data model" and "Storage").
 *
 * Keyspace: ONE global order. A name's key is its labels reversed and joined by '\x01'
 * (www.dia.govt.nz -> 'nz\x01govt\x01dia\x01www'), so a domain and everything under it, apex or public
 * suffix alike, is one contiguous key range (`rangeFor`). Sibling rows use the 's\x00' prefix and live in
 * runs of their own. Keys are printable ASCII apart from the two separators, so JS code-unit order,
 * UTF-8 byte order and D1's BINARY text order all agree, and catalog range queries match codec ranges.
 *
 * A run is one R2 object: key-sorted TSV rows, cut into blocks of ~64 KB before compression, each
 * block compressed independently with deflate-raw, so any block can be range-read and decoded alone.
 * The block index (first key, offset, length per block) is stored in the D1 `runs` row.
 * Workers-runtime APIs only.
 */

import { parse } from 'tldts';
import type { BlockIndexEntry, NameObservation, RunRow, SiblingObservation } from './types';

/** Joins reversed labels inside a key. */
export const LABEL_SEPARATOR = '\x01';
/** Prefix of every sibling key. No name label may contain '\x00', so no name key starts with it. */
export const SIBLING_PREFIX = 's\x00';
/** A block is closed before it would pass this many uncompressed bytes (a single larger row gets a block to itself). */
export const BLOCK_TARGET_BYTES = 64 * 1024;

const BLOCK_INDEX_VERSION = 1;
/** One DNS label as stored: printable ASCII only (SAN dNSNames are IA5String; IDNs arrive as xn-- A-labels). */
const LABEL = /^[\x21-\x7e]+$/;
const EPOCH = /^-?\d+$/;
const encoder = new TextEncoder();
const strictDecoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: false });

/**
 * A fresh copy of `text`. A key parsed from a block is a slice of that block's whole decoded text, and V8 keeps
 * the parent alive for as long as the slice lives. Held keys (block index entries, run bounds) must not pin it:
 * one pinned input block per output block grew a job's heap with its whole output (SQ-363).
 */
function detached(text: string): string {
	return text.split('').join('');
}

/** Code-unit order, not localeCompare: the order must not depend on the runtime's locale. */
function compareText(a: string, b: string): number {
	return a < b ? -1 : a > b ? 1 : 0;
}

/**
 * Lowercases, strips one trailing dot and checks every label. A label holding a separator, a control
 * character or non-ASCII text could forge a key inside another domain's range, so it is refused
 * rather than stored. Callers at the CT-log boundary skip and count such names.
 */
function normalizeHost(raw: string): string {
	let host = raw.toLowerCase();
	if (host.endsWith('.')) host = host.slice(0, -1);
	for (const label of host.split('.')) {
		if (!LABEL.test(label)) throw new RangeError(`not a storable DNS name: ${JSON.stringify(raw)}`);
	}
	return host;
}

function reverseLabels(host: string): string {
	return host.split('.').reverse().join(LABEL_SEPARATOR);
}

/**
 * The key of a certificate name. A wildcard `*.x` folds into x: it gets x's key and name, with
 * `wildcard: true`.
 */
export function nameKey(name: string): { key: string; name: string; wildcard: boolean } {
	const wildcard = name.startsWith('*.');
	const host = normalizeHost(wildcard ? name.slice(2) : name);
	return { key: reverseLabels(host), name: host, wildcard };
}

/** The key of a sibling row: 's\x00' + reversed(apex) + '\x00' + sibling. */
export function siblingKey(apex: string, sibling: string): string {
	return `${SIBLING_PREFIX}${reverseLabels(normalizeHost(apex))}\x00${normalizeHost(sibling)}`;
}

/**
 * The key range of `domain` and every name under it, inclusive at both ends: lo is the domain's own key,
 * hi is that key + '\x01\uffff'. govt.nz covers dia.govt.nz and www.dia.govt.nz but not xgovt.nz.
 * Labels are ASCII, so no child key can sort above hi. The only sibling keys inside a name range are
 * under a one-letter TLD `s`, which is never delegated.
 */
export function rangeFor(domain: string): { lo: string; hi: string } {
	const { key } = nameKey(domain);
	return { lo: key, hi: `${key}${LABEL_SEPARATOR}\uffff` };
}

/** The registrable domain, with private suffixes enabled, as bv-mcp computes it (src/lib/public-suffix.ts). */
export function apexOf(name: string): string | null {
	return parse(name, { allowPrivateDomains: true }).domain ?? null;
}

export function isSiblingRow(row: RunRow): row is SiblingObservation {
	return row.key.startsWith(SIBLING_PREFIX);
}

/** The fields a merge takes from the later row, as a tie-break when both rows have the same notAfter. */
function tieFields(row: RunRow): string[] {
	return isSiblingRow(row) ? [row.apex, row.sibling] : [row.issuer, row.apex, row.name];
}

function laterOf(a: RunRow, b: RunRow): RunRow {
	if (a.notAfter !== b.notAfter) return a.notAfter > b.notAfter ? a : b;
	const fa = tieFields(a);
	const fb = tieFields(b);
	for (let i = 0; i < fa.length; i++) {
		const order = compareText(fa[i]!, fb[i]!);
		if (order !== 0) return order > 0 ? a : b;
	}
	return a;
}

/**
 * Merges two rows with the same key: firstSeen = min, notAfter = max, issuer (and the other fields) from
 * the row with the larger notAfter, ties broken by field order. `wildcard` is ORed: a cert listing both
 * x and *.x yields two observations of x, and the wildcard must survive the fold. Every field is a
 * min, a max or an OR over a total order, so the merge is idempotent, commutative and associative.
 * Returns a new row holding only the contract fields.
 */
export function mergeObservations(a: NameObservation, b: NameObservation): NameObservation;
export function mergeObservations(a: SiblingObservation, b: SiblingObservation): SiblingObservation;
export function mergeObservations(a: RunRow, b: RunRow): RunRow;
export function mergeObservations(a: RunRow, b: RunRow): RunRow {
	if (a.key !== b.key) throw new RangeError(`cannot merge rows with different keys: ${JSON.stringify(a.key)}, ${JSON.stringify(b.key)}`);
	const later = laterOf(a, b);
	const firstSeen = Math.min(a.firstSeen, b.firstSeen);
	if (isSiblingRow(later)) {
		return { key: later.key, apex: later.apex, sibling: later.sibling, firstSeen, notAfter: later.notAfter };
	}
	const wildcard = (a as NameObservation).wildcard || (b as NameObservation).wildcard;
	return { key: later.key, name: later.name, apex: later.apex, firstSeen, notAfter: later.notAfter, issuer: later.issuer, wildcard };
}

const ESCAPES: Record<string, string> = { '\\': '\\\\', '\t': '\\t', '\n': '\\n', '\r': '\\r' };
const UNESCAPES: Record<string, string> = { '\\': '\\', t: '\t', n: '\n', r: '\r' };

/** Escapes backslash, tab, newline and carriage return, so a field never splits a row or a column. */
function escapeField(value: string): string {
	return value.replace(/[\\\t\n\r]/g, (c) => ESCAPES[c]!);
}

function unescapeField(value: string): string {
	return value.replace(/\\([\s\S]?)/g, (_, c: string) => {
		const plain = UNESCAPES[c];
		if (plain === undefined) throw new RangeError(`bad escape in run row: ${JSON.stringify(value)}`);
		return plain;
	});
}

function epochText(value: number): string {
	if (!Number.isSafeInteger(value)) throw new RangeError(`epoch seconds must be an integer: ${value}`);
	return String(value);
}

function parseEpoch(text: string): number {
	const value = Number(text);
	if (!EPOCH.test(text) || !Number.isSafeInteger(value)) throw new RangeError(`bad epoch field in run row: ${JSON.stringify(text)}`);
	return value;
}

/** Name rows have 7 columns, sibling rows 5; the key comes first so the TSV text sorts by key. */
function rowLine(row: RunRow): string {
	const fields = isSiblingRow(row)
		? [row.key, row.apex, row.sibling, epochText(row.firstSeen), epochText(row.notAfter)]
		: [row.key, row.name, row.apex, epochText(row.firstSeen), epochText(row.notAfter), row.issuer, row.wildcard ? '1' : '0'];
	return `${fields.map(escapeField).join('\t')}\n`;
}

function parseRow(line: string): RunRow {
	const f = line.split('\t').map(unescapeField);
	const key = f[0]!;
	if (key.startsWith(SIBLING_PREFIX)) {
		if (f.length !== 5) throw new RangeError(`sibling row needs 5 columns, got ${f.length}`);
		return { key, apex: f[1]!, sibling: f[2]!, firstSeen: parseEpoch(f[3]!), notAfter: parseEpoch(f[4]!) };
	}
	if (f.length !== 7 || (f[6] !== '0' && f[6] !== '1')) throw new RangeError(`malformed name row: ${JSON.stringify(line)}`);
	return {
		key,
		name: f[1]!,
		apex: f[2]!,
		firstSeen: parseEpoch(f[3]!),
		notAfter: parseEpoch(f[4]!),
		issuer: f[5]!,
		wildcard: f[6] === '1',
	};
}

async function deflateRaw(chunks: Uint8Array[]): Promise<Uint8Array> {
	const stream = new Blob(chunks).stream().pipeThrough(new CompressionStream('deflate-raw'));
	return new Uint8Array(await new Response(stream).arrayBuffer());
}

export interface EncodedRun {
	bytes: Uint8Array;
	blockIndex: BlockIndexEntry[];
	/** Smallest and largest row key, both inclusive; '' for an empty run. */
	keyLo: string;
	keyHi: string;
	rows: number;
}

export interface RunWriter {
	/** Await each call: rows must arrive in strictly ascending key order, one row per key. */
	add(row: RunRow): Promise<void>;
	finish(): Promise<EncodedRun>;
}

/**
 * Streaming run encoder: holds the compressed blocks plus one open block, never the decoded rows, so a
 * compaction job can write a merge's output as it streams. `encodeRun` is the in-memory front end.
 */
export function createRunWriter(): RunWriter {
	const blocks: Uint8Array[] = [];
	const blockIndex: BlockIndexEntry[] = [];
	let open: Uint8Array[] = [];
	let openBytes = 0;
	let openFirstKey = '';
	let offset = 0;
	let rows = 0;
	let keyLo = '';
	let keyHi = '';

	async function closeBlock(): Promise<void> {
		if (open.length === 0) return;
		const block = await deflateRaw(open);
		blockIndex.push({ firstKey: openFirstKey, offset, length: block.byteLength });
		blocks.push(block);
		offset += block.byteLength;
		open = [];
		openBytes = 0;
	}

	return {
		async add(row) {
			if (rows > 0 && row.key <= keyHi) {
				throw new RangeError(`run rows out of order: ${JSON.stringify(row.key)} after ${JSON.stringify(keyHi)}`);
			}
			const line = encoder.encode(rowLine(row));
			if (openBytes > 0 && openBytes + line.byteLength > BLOCK_TARGET_BYTES) await closeBlock();
			if (open.length === 0) openFirstKey = detached(row.key);
			open.push(line);
			openBytes += line.byteLength;
			if (rows === 0) keyLo = detached(row.key);
			keyHi = row.key;
			rows++;
		},
		async finish() {
			await closeBlock();
			const bytes = new Uint8Array(offset);
			let at = 0;
			for (const block of blocks) {
				bytes.set(block, at);
				at += block.byteLength;
			}
			return { bytes, blockIndex, keyLo, keyHi: detached(keyHi), rows };
		},
	};
}

/**
 * Encodes one run: sorts a copy by key, merges rows that share a key (`mergeObservations`), and writes the
 * blocks. Expiry is not applied here; `mergeSortedRuns` drops expired rows on rewrite.
 */
export async function encodeRun(rows: NameObservation[] | SiblingObservation[]): Promise<EncodedRun> {
	const sorted = [...(rows as RunRow[])].sort((a, b) => compareText(a.key, b.key));
	const writer = createRunWriter();
	let held: RunRow | undefined;
	for (const row of sorted) {
		if (held?.key === row.key) {
			held = mergeObservations(held, row);
			continue;
		}
		if (held) await writer.add(held);
		held = row;
	}
	if (held) await writer.add(held);
	return writer.finish();
}

/** Decodes one block, e.g. `bytes.subarray(offset, offset + length)` or an R2 range GET body. Throws on any corruption. */
export async function decodeBlock(bytes: Uint8Array): Promise<RunRow[]> {
	const text = await new Response(new Blob([bytes]).stream().pipeThrough(new DecompressionStream('deflate-raw'))).text();
	if (!text.endsWith('\n')) throw new RangeError('run block is empty or truncated');
	return text.slice(0, -1).split('\n').map(parseRow);
}

/**
 * Streams a run's rows block by block. `readBlock` fetches one block's bytes (an R2 range GET in the
 * Worker). Only one decoded block is held at a time.
 */
export async function* streamRun(
	blockIndex: readonly BlockIndexEntry[],
	readBlock: (entry: BlockIndexEntry) => Promise<Uint8Array>,
): AsyncGenerator<RunRow> {
	for (const entry of blockIndex) yield* await decodeBlock(await readBlock(entry));
}

interface MergeHead<T> {
	row: T;
	source: Iterator<T> | AsyncIterator<T>;
	input: number;
}

/**
 * Streaming k-way merge of key-sorted inputs (each typically a `streamRun`). Rows sharing a key, within
 * or across inputs, are folded with `mergeObservations`, and a merged row with notAfter < now is
 * dropped. Holds one row per input; an input whose keys go backwards throws rather than write a run
 * whose block index lies.
 */
export async function* mergeSortedRuns<T extends RunRow>(
	inputs: ReadonlyArray<Iterable<T> | AsyncIterable<T>>,
	now: number,
): AsyncGenerator<T> {
	const heap: MergeHead<T>[] = [];
	const before = (x: MergeHead<T>, y: MergeHead<T>) => {
		const order = compareText(x.row.key, y.row.key);
		return order < 0 || (order === 0 && x.input < y.input);
	};
	const siftDown = (from: number) => {
		for (let i = from; ;) {
			const left = 2 * i + 1;
			const right = left + 1;
			let least = i;
			if (left < heap.length && before(heap[left]!, heap[least]!)) least = left;
			if (right < heap.length && before(heap[right]!, heap[least]!)) least = right;
			if (least === i) return;
			[heap[i], heap[least]] = [heap[least]!, heap[i]!];
			i = least;
		}
	};
	/** Replaces the top row with the next row of its input, or drops the input when it is done. */
	const advanceTop = async () => {
		const top = heap[0]!;
		const next = await top.source.next();
		if (next.done) {
			const last = heap.pop()!;
			if (heap.length > 0) heap[0] = last;
		} else {
			if (next.value.key < top.row.key) {
				throw new RangeError(
					`merge input ${top.input} is not key-sorted: ${JSON.stringify(next.value.key)} after ${JSON.stringify(top.row.key)}`,
				);
			}
			top.row = next.value;
		}
		siftDown(0);
	};

	try {
		for (const [input, iterable] of inputs.entries()) {
			const source = Symbol.asyncIterator in iterable ? iterable[Symbol.asyncIterator]() : iterable[Symbol.iterator]();
			const first = await source.next();
			if (!first.done) heap.push({ row: first.value, source, input });
		}
		for (let i = Math.floor(heap.length / 2) - 1; i >= 0; i--) siftDown(i);

		while (heap.length > 0) {
			let merged: T = heap[0]!.row;
			await advanceTop();
			while (heap.length > 0 && heap[0]!.row.key === merged.key) {
				merged = mergeObservations(merged, heap[0]!.row) as T;
				await advanceTop();
			}
			if (merged.notAfter >= now) yield merged;
		}
	} finally {
		// An early stop (or a throw) must still release the inputs, e.g. open R2 bodies.
		await Promise.all(heap.map((head) => head.source.return?.()));
	}
}

function writeVarint(out: number[], value: number): void {
	if (!Number.isSafeInteger(value) || value < 0) throw new RangeError(`block index field must be a non-negative integer: ${value}`);
	let rest = value;
	while (rest >= 0x80) {
		out.push((rest % 0x80) | 0x80);
		rest = Math.floor(rest / 0x80);
	}
	out.push(rest);
}

function readVarint(bytes: Uint8Array, at: { pos: number }): number {
	let value = 0;
	for (let scale = 1; scale <= 2 ** 49; scale *= 0x80) {
		if (at.pos >= bytes.length) throw new RangeError('block index is truncated');
		const byte = bytes[at.pos++]!;
		value += (byte & 0x7f) * scale;
		if (byte < 0x80) return value;
	}
	throw new RangeError('block index varint is too long');
}

/**
 * The D1 `runs.block_index` BLOB: a version byte, the entry count, then per block varint offset,
 * varint length, varint key byte length and the UTF-8 first key. It is read on every query, so it is
 * binary rather than JSON.
 */
export function serializeBlockIndex(entries: readonly BlockIndexEntry[]): Uint8Array {
	const out: number[] = [BLOCK_INDEX_VERSION];
	writeVarint(out, entries.length);
	for (const entry of entries) {
		const key = encoder.encode(entry.firstKey);
		writeVarint(out, entry.offset);
		writeVarint(out, entry.length);
		writeVarint(out, key.byteLength);
		for (const byte of key) out.push(byte);
	}
	return Uint8Array.from(out);
}

/** Parses `serializeBlockIndex` output from any shape D1 returns a BLOB as. Throws on any corruption. */
export function parseBlockIndex(blob: ArrayBuffer | ArrayBufferView | ArrayLike<number>): BlockIndexEntry[] {
	const bytes =
		blob instanceof ArrayBuffer
			? new Uint8Array(blob)
			: ArrayBuffer.isView(blob)
				? new Uint8Array(blob.buffer, blob.byteOffset, blob.byteLength)
				: Uint8Array.from(blob);
	if (bytes[0] !== BLOCK_INDEX_VERSION) throw new RangeError(`unknown block index version: ${bytes[0]}`);
	const at = { pos: 1 };
	const count = readVarint(bytes, at);
	const entries: BlockIndexEntry[] = [];
	for (let i = 0; i < count; i++) {
		const offset = readVarint(bytes, at);
		const length = readVarint(bytes, at);
		const keyBytes = readVarint(bytes, at);
		if (at.pos + keyBytes > bytes.length) throw new RangeError('block index is truncated');
		entries.push({ firstKey: strictDecoder.decode(bytes.subarray(at.pos, at.pos + keyBytes)), offset, length });
		at.pos += keyBytes;
	}
	if (at.pos !== bytes.length) throw new RangeError('block index has trailing bytes');
	return entries;
}
