// SPDX-License-Identifier: BUSL-1.1
/**
 * From parsed precerts to queue messages: NameObservations and SiblingObservations (src/types.ts),
 * deduplicated within a tick with the codec's `mergeObservations`, then cut into ObservationBatch
 * messages under the Queues message size limit.
 */

import { apexOf, mergeObservations, nameKey, siblingKey } from '../codec';
import type { CertDetails, NameObservation, ObservationBatch, QueuedName, QueuedSibling, RunRow, SiblingObservation } from '../types';
import type { CertFacts } from './x509';

/** Contract v2: a cert spanning more apexes than this yields no sibling rows. */
export const MAX_SIBLING_APEXES = 32;
/** The issuer is a CA's name, but it comes from an untrusted log; a longer one is cut rather than carried. */
export const MAX_ISSUER_LENGTH = 256;
/** The serial and signature algorithm also come from the untrusted log; DER allows a 20-byte serial (40 hex). */
export const MAX_SERIAL_LENGTH = 128;
export const MAX_SIG_ALG_LENGTH = 64;
/** Queues caps a message at 128 KB; batches are sent as JSON and kept under this many UTF-8 bytes. */
export const MAX_MESSAGE_BYTES = 120_000;

export interface ObservationSet {
	names: Map<string, NameObservation>;
	siblings: Map<string, SiblingObservation>;
}

/** Why an entry or a name was not indexed. */
export interface SkipCounts {
	/** Names refused by `nameKey` (non-printable-ASCII or empty labels). */
	badNames: number;
	/** Names with no registrable domain (public suffixes, IP literals, non-domains in a CN). */
	noApex: number;
}

export function newObservationSet(): ObservationSet {
	return { names: new Map(), siblings: new Map() };
}

function put<T extends RunRow>(rows: Map<string, T>, row: T): void {
	const held = rows.get(row.key);
	rows.set(row.key, held ? (mergeObservations(held, row) as T) : row);
}

function detailsOf(cert: CertFacts): CertDetails {
	return {
		notBefore: cert.notBefore,
		serial: cert.serial.slice(0, MAX_SERIAL_LENGTH),
		keyType: cert.keyType,
		keyBits: cert.keyBits,
		sigAlg: cert.sigAlg.slice(0, MAX_SIG_ALG_LENGTH),
		sanCount: cert.names.length,
	};
}

/**
 * Adds one precert's observations: a NameObservation per name (wildcards folded by `nameKey`, firstSeen =
 * notBefore), and, when the cert spans 2..32 distinct apexes, a SiblingObservation for each ordered pair.
 * With `withDetails`, each name row also carries the certificate's details (the CERT_DETAILS switch).
 */
export function observeCert(cert: CertFacts, into: ObservationSet, skips: SkipCounts, withDetails = false): void {
	const base = { firstSeen: cert.notBefore, notAfter: cert.notAfter, issuer: cert.issuer.slice(0, MAX_ISSUER_LENGTH) };
	const details = withDetails ? detailsOf(cert) : undefined;
	const apexes = new Set<string>();
	for (const raw of cert.names) {
		const row = nameRow(raw, base, skips);
		if (!row) continue;
		if (details) row.details = details;
		apexes.add(row.apex);
		put(into.names, row);
	}
	if (apexes.size >= 2 && apexes.size <= MAX_SIBLING_APEXES) addSiblings(into, apexes, cert);
}

/** One SAN name as a row, or null (counted in `skips`) when the codec refuses it or it has no registrable apex. */
function nameRow(raw: string, base: Pick<NameObservation, 'firstSeen' | 'notAfter' | 'issuer'>, skips: SkipCounts): NameObservation | null {
	let folded: ReturnType<typeof nameKey>;
	try {
		folded = nameKey(raw);
	} catch {
		skips.badNames++;
		return null;
	}
	const apex = apexOf(folded.name);
	if (!apex) {
		skips.noApex++;
		return null;
	}
	return { key: folded.key, name: folded.name, apex, ...base, wildcard: folded.wildcard };
}

function addSiblings(into: ObservationSet, apexes: ReadonlySet<string>, cert: CertFacts): void {
	for (const apex of apexes) {
		for (const sibling of apexes) {
			if (apex === sibling) continue;
			put(into.siblings, { key: siblingKey(apex, sibling), apex, sibling, firstSeen: cert.notBefore, notAfter: cert.notAfter });
		}
	}
}

/** Field-by-field equality; details, the one nested field, compare by serial (one serial, one certificate). */
function sameRow(a: RunRow, b: RunRow): boolean {
	const left = a as unknown as Record<string, unknown>;
	const right = b as unknown as Record<string, unknown>;
	const serial = (row: Record<string, unknown>) => (row.details as CertDetails | undefined)?.serial;
	if (serial(left) !== serial(right)) return false;
	return Object.keys({ ...left, ...right }).every((field) => field === 'details' || left[field] === right[field]);
}

/**
 * The rows of one log that still add something after the earlier logs of this tick: a row is dropped when
 * merging it into the row already emitted for its key changes nothing, otherwise the merged row is emitted
 * and remembered. Cursors advance in the same order and stop at the first failed send, so a dropped row is
 * always covered by a row from a log whose send succeeded.
 */
export function newRows(set: ObservationSet, emitted: Map<string, RunRow>): { names: NameObservation[]; siblings: SiblingObservation[] } {
	const keep = <T extends RunRow>(rows: Iterable<T>): T[] => {
		const out: T[] = [];
		for (const row of rows) {
			const held = emitted.get(row.key) as T | undefined;
			const merged = held ? (mergeObservations(held, row) as T) : row;
			if (held && sameRow(merged, held)) continue;
			emitted.set(row.key, merged);
			out.push(merged);
		}
		return out;
	};
	return { names: keep(set.names.values()), siblings: keep(set.siblings.values()) };
}

const encoder = new TextEncoder();
const jsonBytes = (value: unknown) => encoder.encode(JSON.stringify(value)).byteLength;

/** A name row as queued: key and apex are left off because the indexer re-derives them from name (SQ-530). */
function queuedName(row: NameObservation): QueuedName {
	const { key: _key, apex: _apex, ...queued } = row;
	return queued;
}

/** A sibling row as queued: key is left off because the indexer re-derives it from apex and sibling (SQ-530). */
function queuedSibling(row: SiblingObservation): QueuedSibling {
	const { key: _key, ...queued } = row;
	return queued;
}

/**
 * Cuts one log's rows into ObservationBatch messages of at most MAX_MESSAGE_BYTES of JSON each, measured on the
 * queued form (no re-derivable keys). Every batch of a log carries that log's whole range for the tick,
 * [startIndex, endIndex).
 */
export function toBatches(
	logId: string,
	startIndex: number,
	endIndex: number,
	rows: { names: NameObservation[]; siblings: SiblingObservation[] },
): ObservationBatch[] {
	const empty = (): ObservationBatch => ({ logId, startIndex, endIndex, names: [], siblings: [] });
	const envelopeBytes = jsonBytes(empty());
	const batches: ObservationBatch[] = [];
	let batch = empty();
	let bytes = envelopeBytes;
	const add = <T>(row: T, list: (target: ObservationBatch) => T[]) => {
		const rowBytes = jsonBytes(row) + 1; // and its comma
		if (bytes + rowBytes > MAX_MESSAGE_BYTES && bytes > envelopeBytes) {
			batches.push(batch);
			batch = empty();
			bytes = envelopeBytes;
		}
		list(batch).push(row);
		bytes += rowBytes;
	};
	for (const row of rows.names) add(queuedName(row), (target) => target.names);
	for (const row of rows.siblings) add(queuedSibling(row), (target) => target.siblings);
	if (bytes > envelopeBytes) batches.push(batch);
	return batches;
}
