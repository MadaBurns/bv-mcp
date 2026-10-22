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

import { encodeRun, nameKey, serializeBlockIndex, siblingKey } from '../codec';
import type { Env } from '../index';
import type { CertDetails, NameObservation, SiblingObservation } from '../types';
import { CURRENT_GENERATION_SQL, RUNS_PREFIX, isKilled, ledgerStatement } from './catalog';

/** While the kill switch is on, batches are retried after this delay (the queue drops a message after 3 retries). */
export const KILLED_RETRY_DELAY_SECONDS = 3_600;

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

/** Whether `key` is exactly the key the codec derives from `name` (and `name` is already in its folded form). */
function codecAgrees(key: string, name: string): boolean {
	try {
		const derived = nameKey(name);
		return derived.key === key && derived.name === name;
	} catch {
		return false;
	}
}

type NameFields = Fields & { key: string; name: string; apex: string; issuer: string; wildcard: boolean };

function hasNameFields(o: Fields): o is NameFields {
	return ['key', 'name', 'apex', 'issuer'].every((field) => typeof o[field] === 'string') && typeof o.wildcard === 'boolean';
}

/**
 * A queued observation is stored only if its key is exactly the key the codec derives from its name. A key
 * that disagreed (e.g. a name row keyed into the sibling keyspace) would sort into another domain's range or
 * make the run undecodable, and every read of that range would fail.
 */
function nameObservation(o: unknown): NameObservation | null {
	if (!isFields(o) || !epochs(o) || !hasNameFields(o)) return null;
	const { key, name, apex, issuer, wildcard } = o;
	if (!codecAgrees(key, name)) return null;
	const row: NameObservation = { key, name, apex, firstSeen: o.firstSeen as number, notAfter: o.notAfter as number, issuer, wildcard };
	const details = certDetails(o.details);
	if (details) row.details = details;
	return row;
}

function siblingObservation(o: unknown): SiblingObservation | null {
	if (!isFields(o) || !epochs(o)) return null;
	const { key, apex, sibling } = o;
	if (typeof key !== 'string' || typeof apex !== 'string' || typeof sibling !== 'string') return null;
	try {
		if (siblingKey(apex, sibling) !== key) return null;
	} catch {
		return null;
	}
	return { key, apex, sibling, firstSeen: o.firstSeen as number, notAfter: o.notAfter as number };
}

async function putRun(
	env: Env,
	r2Key: string,
	rows: NameObservation[] | SiblingObservation[],
	createdAt: string,
): Promise<D1PreparedStatement | null> {
	if (rows.length === 0) return null;
	const run = await encodeRun(rows);
	await env.INDEX.put(r2Key, run.bytes);
	// The generation is resolved in the statement itself (see catalog.ts).
	return env.CURSORS.prepare(
		`INSERT INTO runs (id, generation, tier, key_lo, key_hi, r2_key, rows, bytes, block_index, created_at)
		 SELECT g || ':' || ?1, g, 0, ?2, ?3, ?1, ?4, ?5, ?6, ?7 FROM (SELECT ${CURRENT_GENERATION_SQL} AS g)`,
	).bind(r2Key, run.keyLo, run.keyHi, run.rows, run.bytes.byteLength, serializeBlockIndex(run.blockIndex), createdAt);
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
