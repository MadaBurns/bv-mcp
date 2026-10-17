// SPDX-License-Identifier: BUSL-1.1
/**
 * From parsed precerts to queue messages: NameObservations and SiblingObservations (src/types.ts),
 * deduplicated within a tick with the codec's `mergeObservations`, then cut into ObservationBatch
 * messages under the Queues message size limit.
 */

import { apexOf, mergeObservations, nameKey, siblingKey } from '../codec';
import type { NameObservation, ObservationBatch, RunRow, SiblingObservation } from '../types';
import type { CertFacts } from './x509';

/** Contract v2: a cert spanning more apexes than this yields no sibling rows. */
export const MAX_SIBLING_APEXES = 32;
/** The issuer is a CA's name, but it comes from an untrusted log; a longer one is cut rather than carried. */
export const MAX_ISSUER_LENGTH = 256;
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

/**
 * Adds one precert's observations: a NameObservation per name (wildcards folded by `nameKey`, firstSeen =
 * notBefore), and, when the cert spans 2..32 distinct apexes, a SiblingObservation for each ordered pair.
 */
export function observeCert(cert: CertFacts, into: ObservationSet, skips: SkipCounts): void {
	const issuer = cert.issuer.slice(0, MAX_ISSUER_LENGTH);
	const apexes = new Set<string>();
	for (const raw of cert.names) {
		let folded: ReturnType<typeof nameKey>;
		try {
			folded = nameKey(raw);
		} catch {
			skips.badNames++;
			continue;
		}
		const apex = apexOf(folded.name);
		if (!apex) {
			skips.noApex++;
			continue;
		}
		apexes.add(apex);
		put(into.names, {
			key: folded.key,
			name: folded.name,
			apex,
			firstSeen: cert.notBefore,
			notAfter: cert.notAfter,
			issuer,
			wildcard: folded.wildcard,
		});
	}
	if (apexes.size < 2 || apexes.size > MAX_SIBLING_APEXES) return;
	for (const apex of apexes) {
		for (const sibling of apexes) {
			if (apex === sibling) continue;
			put(into.siblings, { key: siblingKey(apex, sibling), apex, sibling, firstSeen: cert.notBefore, notAfter: cert.notAfter });
		}
	}
}

function sameRow(a: RunRow, b: RunRow): boolean {
	const left = a as unknown as Record<string, unknown>;
	const right = b as unknown as Record<string, unknown>;
	return Object.keys(left).every((field) => left[field] === right[field]);
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

/**
 * Cuts one log's rows into ObservationBatch messages of at most MAX_MESSAGE_BYTES of JSON each. Every
 * batch of a log carries that log's whole range for the tick, [startIndex, endIndex).
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
	const add = (row: RunRow, push: (target: ObservationBatch) => void) => {
		const rowBytes = jsonBytes(row) + 1; // and its comma
		if (bytes + rowBytes > MAX_MESSAGE_BYTES && bytes > envelopeBytes) {
			batches.push(batch);
			batch = empty();
			bytes = envelopeBytes;
		}
		push(batch);
		bytes += rowBytes;
	};
	for (const row of rows.names) add(row, (target) => target.names.push(row));
	for (const row of rows.siblings) add(row, (target) => target.siblings.push(row));
	if (bytes > envelopeBytes) batches.push(batch);
	return batches;
}
