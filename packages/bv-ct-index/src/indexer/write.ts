// SPDX-License-Identifier: BUSL-1.1
/**
 * T0 indexer: the consumer of the `bv-ct-index-entries` queue (batch 100, see wrangler.jsonc).
 *
 * One invocation merges every observation in its batch into one sorted run per keyspace: a run holds one
 * kind only (types.ts RunRow), so names and siblings are two R2 objects, each written by `encodeRun`, and
 * an empty keyspace writes nothing. Both catalog rows, `meta` and the ops ledger then commit in ONE D1 batch,
 * and the messages are acked only after the R2 puts and that batch succeed. Any failure throws, so the queue
 * retries the whole batch; objects of a failed attempt are unreferenced and the weekly garbage sweep removes
 * them.
 *
 * T0 object keys are unique per attempt rather than derived from the messages: a redelivered batch then writes
 * a duplicate run (harmless, the merge rule is idempotent) instead of re-putting an object that a compaction
 * job may already have consumed and be deleting.
 *
 * `meta.fresh_through` is the commit time of the latest indexed batch (ISO 8601, only ever advanced), i.e.
 * "the index has taken in everything the tailer handed over before this instant".
 */

import { apexOf, encodeRun, nameKey, serializeBlockIndex, siblingKey } from '../codec';
import type { Env } from '../index';
import type { CertDetails, NameObservation, SiblingObservation } from '../types';
import { CURRENT_GENERATION_SQL, RUNS_PREFIX, isKilled, ledgerStatement } from './catalog';

/** While the kill switch is on, batches are retried after this delay (the queue drops a message after 3 retries). */
export const KILLED_RETRY_DELAY_SECONDS = 3_600;
/**
 * Key filter bits per entry for T0 runs. Each spans the whole keyspace, so every lookup tests every T0 run (a few
 * hundred at a time): 16 bits keeps false positives near 0.1%, about 20 KB for a 10k-entry run, and T0 runs are few.
 */
export const T0_KEY_FILTER_BITS = 16;

type Fields = Record<string, unknown>;

function isFields(value: unknown): value is Fields {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function epochs(o: Fields): boolean {
	return Number.isSafeInteger(o.firstSeen) && Number.isSafeInteger(o.notAfter);
}

const KEY_TYPES = new Set<unknown>(['rsa', 'ec', 'unknown']);
const SERIAL = /^[0-9a-f]{0,128}$/;
const MAX_SIG_ALG_LENGTH = 64;
const count = (value: unknown) => Number.isSafeInteger(value) && (value as number) >= 0;

/** One check per CertDetails field; a queued details object is kept only when every field passes. */
const DETAIL_CHECKS: Record<keyof CertDetails, (value: unknown) => boolean> = {
	notBefore: Number.isSafeInteger,
	serial: (value) => typeof value === 'string' && SERIAL.test(value),
	keyType: (value) => KEY_TYPES.has(value),
	keyBits: (value) => value === null || count(value),
	sigAlg: (value) => typeof value === 'string' && value.length <= MAX_SIG_ALG_LENGTH,
	sanCount: count,
};
const DETAIL_FIELDS = Object.keys(DETAIL_CHECKS) as Array<keyof CertDetails>;

/** Queued certificate details, or undefined when absent or malformed: bad details never cost a row its names. */
function certDetails(value: unknown): CertDetails | undefined {
	if (!isFields(value) || !DETAIL_FIELDS.every((field) => DETAIL_CHECKS[field](value[field]))) return undefined;
	return Object.fromEntries(DETAIL_FIELDS.map((field) => [field, value[field]])) as unknown as CertDetails;
}

/** Queue issuer limit, the same cut the tailer applies (tailer/observations.ts MAX_ISSUER_LENGTH). */
export const MAX_QUEUED_ISSUER_LENGTH = 256;

/** The codec's folded form of `name`, or null when the codec refuses it. */
function folded(name: string): ReturnType<typeof nameKey> | null {
	try {
		return nameKey(name);
	} catch {
		return null;
	}
}

/** `value` if it is absent or a string, else false (a present non-string field fails the row). */
function optionalString(value: unknown): string | undefined | false {
	return value === undefined || typeof value === 'string' ? value : false;
}

/** A queued claim agrees when it was omitted (the compact wire shape) or equals what the indexer derived. */
function agrees(queued: string | undefined, derived: string): boolean {
	return queued === undefined || queued === derived;
}

type QueuedName = Fields & { name: string; issuer: string; wildcard: boolean };

function hasRequiredNameFields(o: Fields): o is QueuedName {
	return ['name', 'issuer'].every((field) => typeof o[field] === 'string') && typeof o.wildcard === 'boolean';
}

/** The queued `key` and `apex`: each may be omitted, but a present one must be a string. */
function queuedClaims(o: Fields): { key?: string; apex?: string } | null {
	const key = optionalString(o.key);
	const apex = optionalString(o.apex);
	return key === false || apex === false ? null : { key, apex };
}

/** nameKey(name).key when `name` is already folded and any queued key agrees, else null. */
function derivedKey(name: string, queued: string | undefined): string | null {
	const derived = folded(name);
	return derived && derived.name === name && agrees(queued, derived.key) ? derived.key : null;
}

/** apexOf(name) when `name` has a registrable apex and any queued apex agrees, else null. */
function derivedApex(name: string, queued: string | undefined): string | null {
	const apex = apexOf(name);
	return apex && agrees(queued, apex) ? apex : null;
}

/** The key and apex the indexer stores for a queued name row, or null when the row is refused. */
function derivedNameFields(o: QueuedName): { key: string; apex: string } | null {
	const claims = queuedClaims(o);
	if (!claims || o.issuer.length > MAX_QUEUED_ISSUER_LENGTH) return null;
	const key = derivedKey(o.name, claims.key);
	const apex = derivedApex(o.name, claims.apex);
	return key && apex ? { key, apex } : null;
}

function withDetails(row: NameObservation, value: unknown): NameObservation {
	const details = certDetails(value);
	return details ? { ...row, details } : row;
}

/**
 * A queued name row is stored only with fields the indexer derives itself (SQ-528, #1341):
 * - `key` is nameKey(name). A queued key may be omitted (the compact wire shape); when present it must equal the
 *   derived key, since a key that disagreed would sort into another domain's range or make the run undecodable.
 * - `apex` is apexOf(name), always. A queued apex may be omitted; when present it must equal the derived one. A
 *   name with no registrable apex is refused, exactly as the tailer refuses it, so a forged apex can never be
 *   persisted or win a merge tie-break.
 * - `name` must already be in its folded form, and `issuer` within the tailer's 256-character cut.
 */
function nameObservation(o: unknown): NameObservation | null {
	if (!isFields(o) || !epochs(o) || !hasRequiredNameFields(o)) return null;
	const derived = derivedNameFields(o);
	if (!derived) return null;
	const { name, issuer, wildcard } = o;
	return withDetails({ ...derived, name, firstSeen: o.firstSeen as number, notAfter: o.notAfter as number, issuer, wildcard }, o.details);
}

/** A queued host that is its own registrable apex, in the codec's folded form, or null. */
function foldedApex(value: unknown): string | null {
	if (typeof value !== 'string') return null;
	const host = folded(value);
	if (!host || host.wildcard) return null;
	return apexOf(host.name) === host.name ? host.name : null;
}

/** Both sides of a queued sibling row as distinct registrable apexes, as the tailer pairs them, or null. */
function distinctApexes(o: Fields): { apex: string; sibling: string } | null {
	const apex = foldedApex(o.apex);
	const sibling = foldedApex(o.sibling);
	return apex && sibling && apex !== sibling ? { apex, sibling } : null;
}

/** The stored key and apexes of a queued sibling row: key = siblingKey(apex, sibling); a queued key must agree. */
function siblingFields(o: Fields): { key: string; apex: string; sibling: string } | null {
	const key = optionalString(o.key);
	if (key === false) return null;
	const pair = distinctApexes(o);
	if (!pair) return null;
	const derived = siblingKey(pair.apex, pair.sibling);
	return agrees(key, derived) ? { key: derived, ...pair } : null;
}

/** A queued sibling row is stored with its key derived and both apexes folded (SQ-528); see siblingFields. */
function siblingObservation(o: unknown): SiblingObservation | null {
	if (!isFields(o) || !epochs(o)) return null;
	const fields = siblingFields(o);
	return fields ? { ...fields, firstSeen: o.firstSeen as number, notAfter: o.notAfter as number } : null;
}

async function putRun(
	env: Env,
	r2Key: string,
	rows: NameObservation[] | SiblingObservation[],
	createdAt: string,
): Promise<D1PreparedStatement | null> {
	if (rows.length === 0) return null;
	const run = await encodeRun(rows, { filterBitsPerEntry: T0_KEY_FILTER_BITS });
	await env.INDEX.put(r2Key, run.bytes);
	// The generation is resolved in the statement itself (see catalog.ts).
	return env.CURSORS.prepare(
		`INSERT INTO runs (id, generation, tier, key_lo, key_hi, r2_key, rows, bytes, block_index, created_at, key_filter, key_split)
		 SELECT g || ':' || ?1, g, 0, ?2, ?3, ?1, ?4, ?5, ?6, ?7, ?8, ?9 FROM (SELECT ${CURRENT_GENERATION_SQL} AS g)`,
	).bind(
		r2Key,
		run.keyLo,
		run.keyHi,
		run.rows,
		run.bytes.byteLength,
		serializeBlockIndex(run.blockIndex),
		createdAt,
		run.keyFilter,
		run.keySplit,
	);
}

export interface IndexOutcome {
	killed: boolean;
	names: number;
	siblings: number;
	/** Observations (or whole messages) refused by validation and dropped. */
	rejected: number;
}

/** Consumes one `bv-ct-index-entries` batch. `nowMs` is the clock (tests pin it). */
export async function indexEntries(batch: MessageBatch<unknown>, env: Env, nowMs = Date.now()): Promise<IndexOutcome> {
	const db = env.CURSORS;
	if (await isKilled(db)) {
		batch.retryAll({ delaySeconds: KILLED_RETRY_DELAY_SECONDS });
		return { killed: true, names: 0, siblings: 0, rejected: 0 };
	}

	const names: NameObservation[] = [];
	const siblings: SiblingObservation[] = [];
	let rejected = 0;
	for (const message of batch.messages) {
		const body = message.body;
		if (!isFields(body) || !Array.isArray(body.names) || !Array.isArray(body.siblings)) {
			// Never valid on a retry either: drop it now rather than hold the other 99 messages hostage.
			console.error(`bv-ct-index indexer: dropping malformed message ${message.id}`);
			message.ack();
			rejected++;
			continue;
		}
		for (const raw of body.names) {
			const row = nameObservation(raw);
			if (row) names.push(row);
			else rejected++;
		}
		for (const raw of body.siblings) {
			const row = siblingObservation(raw);
			if (row) siblings.push(row);
			else rejected++;
		}
	}
	if (rejected > 0) console.error(`bv-ct-index indexer: dropped ${rejected} invalid observation(s) or message(s)`);

	const createdAt = new Date(nowMs).toISOString();
	const stem = `${RUNS_PREFIX}t0/${nowMs}-${crypto.randomUUID()}`;
	const inserts = [
		await putRun(env, `${stem}.names.run`, names, createdAt),
		await putRun(env, `${stem}.siblings.run`, siblings, createdAt),
	].filter((statement): statement is D1PreparedStatement => statement !== null);

	await db.batch([
		...inserts,
		db.prepare("INSERT OR IGNORE INTO meta (k, v) VALUES ('index_started_at', ?1)").bind(createdAt),
		db.prepare("INSERT INTO meta (k, v) VALUES ('fresh_through', ?1) ON CONFLICT (k) DO UPDATE SET v = MAX(v, excluded.v)").bind(createdAt),
		ledgerStatement(db, nowMs, { r2ClassA: inserts.length, r2ClassB: 0, d1Rows: inserts.length + 3 }),
	]);
	batch.ackAll();
	return { killed: false, names: names.length, siblings: siblings.length, rejected };
}
