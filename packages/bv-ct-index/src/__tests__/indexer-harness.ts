// SPDX-License-Identifier: BUSL-1.1
/**
 * Shared fixtures for the indexer tests: the real miniflare R2 and D1 bindings (storage is isolated per test),
 * a recording fake for the COMPACT queue, fake message batches, fault-injecting binding wrappers, and the
 * merge-rule oracle (codec mergeObservations folded per key).
 */

import { env } from 'cloudflare:workers';
import catalogSql from '../../migrations/0002_catalog.sql?raw';
import { apexOf, mergeObservations, nameKey, siblingKey } from '../codec';
import type { Env } from '../index';
import type { CompactionJob, CompactionLimits, JobOutcome } from '../indexer/compact';
import { runCompactionJob } from '../indexer/compact';
import { runCompactionCron } from '../indexer/plan';
import { indexEntries } from '../indexer/write';
import type { IndexReader, NameObservation, ObservationBatch, RunRow, SiblingObservation } from '../types';

export const DAY_S = 86_400;
export const HOUR_MS = 3_600_000;
export const DAY_MS = 24 * HOUR_MS;
/** 01:05 UTC today: the simulated clock every test starts from. */
export const T = Math.floor(Date.now() / DAY_MS) * DAY_MS + HOUR_MS + 5 * 60_000;
export const T_S = Math.floor(T / 1000);

const base = env as unknown as Env;

/**
 * Fresh catalog tables and an empty bucket. Each test file gets its own Miniflare storage, but the tests of a
 * file share it, so every test starts by resetting both.
 */
export async function applyCatalog(): Promise<void> {
	const db = base.CURSORS;
	const statements = catalogSql
		.split(';')
		.map((statement) => statement.trim())
		.filter((statement) => statement.replace(/^--.*$/gm, '').trim() !== '');
	const drops = ['runs', 'meta', 'ops_ledger'].map((table) => `DROP TABLE IF EXISTS ${table}`);
	await db.batch([...drops, ...statements].map((statement) => db.prepare(statement)));
	const keys = await objectKeys();
	if (keys.length > 0) await base.INDEX.delete(keys);
}

export class FakeQueue {
	readonly sent: CompactionJob[] = [];
	async send(body: CompactionJob): Promise<void> {
		this.sent.push(body);
	}
	async sendBatch(messages: Iterable<{ body: CompactionJob }>): Promise<void> {
		for (const message of messages) this.sent.push(message.body);
	}
}

export type TestEnv = Env & { queue: FakeQueue };

export function testEnv(overrides: Partial<Pick<Env, 'INDEX' | 'CURSORS'>> = {}): TestEnv {
	const queue = new FakeQueue();
	return {
		INDEX: overrides.INDEX ?? base.INDEX,
		CURSORS: overrides.CURSORS ?? base.CURSORS,
		ENTRIES: base.ENTRIES,
		COMPACT: queue as unknown as Queue<CompactionJob>,
		CT_INDEX_ADMIN_KEY: 'test-key',
		queue,
	};
}

export interface FakeBatch extends MessageBatch<unknown> {
	acked: string[];
	ackedAll: boolean;
	retriedAll: QueueRetryOptions | null;
}

export function fakeBatch(queue: string, bodies: unknown[]): FakeBatch {
	const batch = {
		queue,
		acked: [] as string[],
		ackedAll: false,
		retriedAll: null as QueueRetryOptions | null,
		messages: bodies.map((body, i) => ({
			id: `m${i}`,
			timestamp: new Date(),
			attempts: 1,
			body,
			ack: () => batch.acked.push(`m${i}`),
			retry: () => undefined,
		})),
		ackAll: () => {
			batch.ackedAll = true;
		},
		retryAll: (options?: QueueRetryOptions) => {
			batch.retriedAll = options ?? {};
		},
	};
	return batch as unknown as FakeBatch;
}

export function obs(name: string, overrides: Partial<NameObservation> = {}): NameObservation {
	const k = nameKey(name);
	return {
		key: k.key,
		name: k.name,
		apex: apexOf(k.name) ?? k.name,
		firstSeen: T_S - 10 * DAY_S,
		notAfter: T_S + 80 * DAY_S,
		issuer: 'R11',
		wildcard: k.wildcard,
		...overrides,
	};
}

export function sib(apex: string, sibling: string, overrides: Partial<SiblingObservation> = {}): SiblingObservation {
	return { key: siblingKey(apex, sibling), apex, sibling, firstSeen: T_S - DAY_S, notAfter: T_S + 60 * DAY_S, ...overrides };
}

export function batchBody(names: NameObservation[], siblings: SiblingObservation[] = []): ObservationBatch {
	return { logId: 'test-log', startIndex: 0, endIndex: names.length, names, siblings };
}

/** One T0 indexer invocation over one message. */
export async function ingest(
	testEnv: Env,
	nowMs: number,
	names: NameObservation[],
	siblings: SiblingObservation[] = [],
): Promise<FakeBatch> {
	const batch = fakeBatch('bv-ct-index-entries', [batchBody(names, siblings)]);
	await indexEntries(batch, testEnv, nowMs);
	return batch;
}

/** Runs the hourly cron at `nowMs`, then every job it enqueued, in order. */
export async function cronAndDrain(
	testEnv: TestEnv,
	nowMs: number,
	limits?: CompactionLimits,
): Promise<{ jobs: CompactionJob[]; outcomes: JobOutcome[]; snapshot: number | null }> {
	const before = testEnv.queue.sent.length;
	const cron = await runCompactionCron(testEnv, nowMs);
	const jobs = testEnv.queue.sent.slice(before);
	const outcomes: JobOutcome[] = [];
	for (const job of jobs) outcomes.push(await runCompactionJob(testEnv, job, limits, nowMs));
	return { jobs, outcomes, snapshot: cron.snapshot };
}

export interface CatalogRow {
	id: string;
	generation: number;
	tier: number;
	key_lo: string;
	key_hi: string;
	r2_key: string;
	rows: number;
}

export async function catalog(generation?: number): Promise<CatalogRow[]> {
	const { results } = await base.CURSORS.prepare(
		'SELECT id, generation, tier, key_lo, key_hi, r2_key, rows FROM runs WHERE ?1 IS NULL OR generation = ?1 ORDER BY generation, tier, key_lo, id',
	)
		.bind(generation ?? null)
		.all<CatalogRow>();
	return results.map((row) => ({ ...row, generation: Number(row.generation), tier: Number(row.tier), rows: Number(row.rows) }));
}

export async function objectKeys(): Promise<string[]> {
	const keys: string[] = [];
	let cursor: string | undefined;
	do {
		const page = await base.INDEX.list({ prefix: 'runs/', cursor });
		keys.push(...page.objects.map((object) => object.key));
		cursor = page.truncated ? page.cursor : undefined;
	} while (cursor !== undefined);
	return keys.sort();
}

/** Wraps a binding so that the named methods run `fault` instead (or before delegating, if it returns). */
export function withFault<T extends object>(target: T, method: string, fault: (...args: unknown[]) => unknown): T {
	return new Proxy(target, {
		get(object, property) {
			if (property === method) return fault;
			const value = Reflect.get(object, property);
			return typeof value === 'function' ? value.bind(object) : value;
		},
	});
}

const byKey = (a: RunRow, b: RunRow) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0);

/** The merge-rule oracle: fold every observation per key, drop rows expired at `now`, sort by key. */
export function expectedRows<T extends RunRow>(observations: T[], now: number): T[] {
	const merged = new Map<string, RunRow>();
	for (const row of observations) {
		const held = merged.get(row.key);
		merged.set(row.key, held ? mergeObservations(held, row) : { ...row });
	}
	return ([...merged.values()].filter((row) => row.notAfter >= now) as T[]).sort(byKey);
}

/** Every page of a scan, following cursors. */
export async function scanAll(reader: IndexReader, domain: string, limit = 1000): Promise<NameObservation[]> {
	const out: NameObservation[] = [];
	let cursor: string | null = null;
	do {
		const page = await reader.scan(domain, { limit, cursor });
		out.push(...page.names);
		cursor = page.cursor;
	} while (cursor !== null);
	return out;
}
