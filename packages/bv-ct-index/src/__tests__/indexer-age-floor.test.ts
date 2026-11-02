// SPDX-License-Identifier: BUSL-1.1
/** Calendar-window age, late publication recovery, and a synthetic compaction/read oracle over a UTC day boundary. */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { runCompactionJob } from '../indexer/compact';
import type { JobStats } from '../indexer/compact';
import { DEFAULT_PLAN_LIMITS, T0_MIN_AGE_MS, planCompactions, runCompactionCron } from '../indexer/plan';
import { createReader } from '../indexer/read';
import type { NameObservation, SiblingObservation } from '../types';
import {
	DAY_MS, DAY_S, HOUR_MS, T, applyCatalog, catalog, cronAndDrain, expectedRows, ingest, obs, scanAll, sib, testEnv, withFault,
} from './indexer-harness';

beforeEach(applyCatalog);
afterEach(() => vi.restoreAllMocks());
const MINUTE = 60_000;
const at = (day: number, hh: number, mm: number) => Math.floor(T / DAY_MS) * DAY_MS + day * DAY_MS + hh * HOUR_MS + mm * MINUTE;

describe('the two-minute T0 age floor', () => {
	it('selects a four-minute-old run without selecting a run at the next window boundary', async () => {
		const env = testEnv();
		await ingest(env, at(0, 1, 28), [obs('due.example.com')]);
		await ingest(env, at(0, 1, 30), [obs('boundary.example.com')]);
		const runs = await catalog();
		const due = runs.find((run) => run.r2_key.includes(`/${at(0, 1, 28)}-`))!;
		const planned = await cronAndDrain(env, at(0, 1, 32));
		expect(planned.jobs.map((job) => job.inputs)).toEqual([[due.id]]);
		expect(planned.outcomes).toEqual(['applied']);
		expect((await catalog()).filter((run) => run.tier === 0)).toHaveLength(1);
		expect((await scanAll(createReader(env, () => at(0, 1, 32)), 'example.com', 1)).map((row) => row.name)).toEqual([
			'boundary.example.com', 'due.example.com',
		]);
	});

	it('keeps exact half-open calendar windows through 96 UTC ticks and scheduler jitter', async () => {
		const env = testEnv();
		for (const jitter of [-1, 0, 1, 55_548]) {
			for (let tick = 0; tick < 96; tick++) {
				const nominal = at(0, 0, 2) + tick * 15 * MINUTE;
				const end = nominal - 2 * MINUTE - (jitter < 0 ? 15 * MINUTE : 0);
				const start = end - 15 * MINUTE;
				await env.CURSORS.prepare('DELETE FROM runs').run();
				const stamps = [start - 1, start, end - 1, end];
				await env.CURSORS.batch(stamps.map((stamp, i) => env.CURSORS.prepare(
					'INSERT INTO runs (id, generation, tier, key_lo, key_hi, rows, created_at) VALUES (?1, 1, 0, ?2, ?2, 1, ?3)',
				).bind(`edge-${i}`, 'com\x01example\x01host', new Date(stamp).toISOString())));
				const jobs = await planCompactions(env.CURSORS, nominal + jitter, DEFAULT_PLAN_LIMITS, false);
				expect(jobs.flatMap((job) => job.inputs).sort(), `${tick}/${jitter}`).toEqual(['edge-1', 'edge-2']);
				expect(nominal + jitter - end).toBeGreaterThanOrEqual(2 * MINUTE);
			}
		}
	});

	it('keeps a full old window readable through a forward handoff until full recovery', async () => {
		const env = testEnv();
		const rows = [obs('first.example.com'), obs('middle.example.com'), obs('last.example.com')];
		// A previous age-ten :17 full tick ended at 01:00. The new first :32 window begins at 01:15.
		for (const [i, stamp] of [at(0, 1, 0), at(0, 1, 7), at(0, 1, 15) - 1].entries()) await ingest(env, stamp, [rows[i]!]);
		const pending = (await catalog()).map((run) => run.id).sort();
		for (const tick of [at(0, 1, 32), at(0, 1, 47), at(0, 2, 2)]) expect((await cronAndDrain(env, tick)).jobs).toEqual([]);
		const reader = createReader(env, () => at(0, 2, 17));
		expect(await scanAll(reader, 'example.com', 1)).toEqual(expectedRows(rows, at(0, 2, 17) / 1000));
		const recovered = await cronAndDrain(env, at(0, 2, 17));
		expect(recovered.jobs.flatMap((job) => job.inputs).sort()).toEqual(pending);
		expect(recovered.outcomes.every((outcome) => outcome === 'applied')).toBe(true);
		expect((await catalog()).some((run) => run.tier === 0)).toBe(false);
		expect(await scanAll(reader, 'example.com', 1)).toEqual(expectedRows(rows, at(0, 2, 17) / 1000));
	});

	it('can replay the preceding calendar window after a full swap without losing a later publication', async () => {
		const env = testEnv();
		const old = obs('old.example.com');
		const later = obs('later.example.com');
		await ingest(env, at(0, 1, 5), [old]);
		expect((await cronAndDrain(env, at(0, 1, 17))).outcomes).toEqual(['applied']);
		await ingest(env, at(0, 1, 20), [later]);
		// Retreating one calendar window during rollback overlaps already-consumed inputs, not the later window.
		expect(await planCompactions(env.CURSORS, at(0, 1, 17), DEFAULT_PLAN_LIMITS, false)).toEqual([]);
		const next = await cronAndDrain(env, at(0, 1, 32));
		expect(next.jobs).toHaveLength(1);
		expect(next.outcomes).toEqual(['applied']);
		expect(await scanAll(createReader(env, () => at(0, 1, 32)), 'example.com', 1)).toEqual(expectedRows([old, later], at(0, 1, 32) / 1000));
	});

	it('recovers a catalog publication that arrives after its ordinary window, rather than promising earlier compaction', async () => {
		const env = testEnv();
		expect((await cronAndDrain(env, at(0, 1, 17))).jobs).toEqual([]);
		// Published after the :17 tick, while its stored statement timestamp precedes that tick's 01:15 cutoff.
		const row = obs('late.example.com');
		await ingest(env, at(0, 1, 14), [row]);
		for (const tick of [at(0, 1, 32), at(0, 1, 47), at(0, 2, 2)]) expect((await cronAndDrain(env, tick)).jobs).toEqual([]);
		expect(await scanAll(createReader(env, () => at(0, 2, 2)), 'example.com', 1)).toEqual([row]);
		const recovered = await cronAndDrain(env, at(0, 2, 17));
		expect(recovered.jobs).toHaveLength(1);
		expect(recovered.outcomes).toEqual(['applied']);
		expect(await scanAll(createReader(env, () => at(0, 2, 17)), 'example.com', 1)).toEqual([row]);
	});
});

describe('the full compaction horizon', () => {
	it('preserves rows, expiry, details, wildcards and cursors while metering T0/T1/roll-up/day work', async ({ task }) => {
		let attempt = 0;
		vi.spyOn(crypto, 'randomUUID').mockImplementation(() => `00000000-0000-4000-8000-${String(++attempt).padStart(12, '0')}`);
		const base = testEnv();
		const meter = { r2Puts: 0, d1RowsWritten: 0 };
		const env = testEnv({
			INDEX: withFault(base.INDEX, 'put', (...args: unknown[]) => {
				meter.r2Puts++;
				return base.INDEX.put(...(args as [string, Uint8Array]));
			}),
			CURSORS: withFault(base.CURSORS, 'batch', async (...args: unknown[]) => {
				const results = await base.CURSORS.batch(args[0] as D1PreparedStatement[]);
				for (const result of results) meter.d1RowsWritten += result.meta.rows_written;
				return results;
			}),
		});
		const names: NameObservation[] = [];
		const siblings: SiblingObservation[] = [];
		const events: Array<
			{ at: number; kind: 'publish'; startedAt: number; visibleAt: number; sequence: number; straddle?: boolean }
			| { at: number; kind: 'cron' }
		> = [];
		for (let i = 0; i < 31; i++) {
			const startedAt = at(0, 22, 40) + i * 5 * MINUTE;
			const visibleAt = startedAt + [0, 4 * MINUTE, 18 * MINUTE][i % 3]!;
			events.push({ at: visibleAt, kind: 'publish', startedAt, visibleAt, sequence: i });
		}
		events.push({ at: at(1, 0, 0) - 1, kind: 'publish', startedAt: at(0, 23, 55), visibleAt: at(1, 0, 0) - 1, sequence: 31, straddle: true });
		for (let tick = at(0, 22, 47); tick <= at(1, 3, 17); tick += 15 * MINUTE) events.push({ at: tick, kind: 'cron' });
		events.sort((a, b) => a.at - b.at || (a.kind === b.kind ? 0 : a.kind === 'publish' ? -1 : 1));
		const byTier: Record<string, { jobs: number; gets: number; outputs: number; outputRows: number }> = {};
		const limits = { ...DEFAULT_PLAN_LIMITS, maxInputs: 4, maxRows: 80, maxT3Rows: 120, maxT1Ranges: 8 };
		for (const event of events) {
			if (event.kind === 'publish') {
				const second = Math.floor(event.startedAt / 1000);
				const batch = [
					...Array.from({ length: 8 }, (_, i) => obs(`host-${event.sequence}-${i}.example.com`, {
						firstSeen: second - DAY_S, notAfter: second + DAY_S,
					})),
					obs('api.example.com', {
						firstSeen: second - DAY_S, notAfter: second + 2 * DAY_S, issuer: `issuer-${event.sequence}`,
						details: {
							notBefore: second - DAY_S, serial: event.sequence.toString(16), keyType: 'ec', keyBits: 256, sigAlg: 'ecdsa', sanCount: 1,
						},
					}),
					obs('*.example.com', { firstSeen: second - DAY_S, notAfter: second + DAY_S }),
					obs(`short-${event.sequence}.example.com`, { firstSeen: second - DAY_S, notAfter: second + 7 * 60 }),
				];
				const related = sib('example.com', event.sequence % 2 ? 'example.net' : 'example.org', {
					firstSeen: second - DAY_S, notAfter: second + DAY_S,
				});
				const before = new Set((await catalog()).map((run) => run.id));
				await ingest(env, event.startedAt, batch, [related]);
				const inserted = (await catalog()).filter((run) => !before.has(run.id));
				// Model the SQL execution timestamp independently from the invocation/key/ledger/freshness clock.
				// These fixture-only UPDATEs are outside the measured application D1 batches.
				await base.CURSORS.batch(inserted.map((run) => {
					const catalogAt = event.visibleAt + (event.straddle && run.r2_key.endsWith('.siblings.run') ? 1 : 0);
					return base.CURSORS.prepare('UPDATE runs SET created_at = ?1 WHERE id = ?2').bind(new Date(catalogAt).toISOString(), run.id);
				}));
				names.push(...batch);
				siblings.push(related);
			} else {
				const before = env.queue.sent.length;
				await runCompactionCron(env, event.at, limits);
				for (const job of env.queue.sent.slice(before)) {
					const stats: JobStats = { outputs: 0, gets: 0, putMs: 0, ms: 0 };
					expect(await runCompactionJob(env, job, { targetRawBytes: 2048 }, event.at, stats)).toBe('applied');
					const tier = byTier[job.tier] ??= { jobs: 0, gets: 0, outputs: 0, outputRows: 0 };
					tier.jobs++;
					tier.gets += stats.gets;
					tier.outputs += stats.outputs;
					tier.outputRows += (await catalog())
						.filter((run) => run.r2_key.startsWith(`runs/t${job.tier}/${job.id}/`))
						.reduce((sum, run) => sum + run.rows, 0);
				}
				if (new Date(event.at).getUTCMinutes() === 17) {
					const reader = createReader(env, () => event.at);
					expect((await reader.scan('com', { limit: 10_000 })).names).toEqual(expectedRows(names, Math.floor(event.at / 1000)));
					expect((await reader.siblings('example.com', { limit: 100 })).siblings).toEqual(expectedRows(siblings, Math.floor(event.at / 1000)));
				}
			}
		}
		const end = at(1, 3, 17);
		const reader = createReader(env, () => end);
		expect(await scanAll(reader, 'com', 7)).toEqual(expectedRows(names, end / 1000));
		expect((await catalog()).some((run) => run.tier === 0 || run.tier === 2)).toBe(false);
		expect(byTier['1']!.jobs).toBeGreaterThan(0);
		expect(byTier['2']!.jobs).toBeGreaterThan(0);
		expect(byTier['3']!.jobs).toBeGreaterThan(0);
		const result = {
			ageMinutes: T0_MIN_AGE_MS / MINUTE, catalogClock: 'statement-time model', fixtureIds: 'deterministic sequence', publications: 32,
			...meter, byTier,
			finalCatalogRows: (await catalog()).reduce((sum, run) => sum + run.rows, 0),
			finalLogicalNames: expectedRows(names, end / 1000).length,
			finalLogicalSiblings: expectedRows(siblings, end / 1000).length,
			finalObjects: (await catalog()).length,
		};
		Object.assign(task.meta, { fullHorizon: result });
		console.log('CT_AGE_FLOOR_HORIZON', JSON.stringify(result));
	});
});
