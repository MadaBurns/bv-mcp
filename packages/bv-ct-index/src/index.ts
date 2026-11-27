// SPDX-License-Identifier: BUSL-1.1
/**
 * bv-ct-index sidecar Worker entrypoint (US-12).
 *
 * `scheduled`: the tailer (src/tailer/) and the compaction planner. `queue`: the indexer, compaction jobs and tailer
 * shards and catch-up rows (one handler for all four queues, told apart by `batch.queue`). `fetch`: GET /health, open, and the
 * bearer-authenticated query API (src/api/).
 */

import { handleApiRequest } from './api/handler';
import type { CompactionJob } from './indexer/compact';
import { runCompactionBatch } from './indexer/compact';
import { COMPACTION_CRON, TRANSITIONAL_COMPACTION_CRON, runCompactionCron } from './indexer/plan';
import { createReader } from './indexer/read';
import { indexEntries } from './indexer/write';
import { runTailer } from './tailer';
import { CATCHUP_CRON, dispatchCatchup, isCatchupRequest, runCatchup, runCatchupMessage, type CatchupRequest } from './tailer/catchup';
import { runFanout, runShard, type ShardRequest } from './tailer/fanout';
import type { ObservationBatch } from './types';

export const ENTRIES_QUEUE = 'bv-ct-index-entries';
export const COMPACT_QUEUE = 'bv-ct-index-compact';
export const TAIL_QUEUE = 'bv-ct-index-tail';
export const CATCHUP_QUEUE = 'bv-ct-index-catchup';

export interface Env {
	/** R2 bucket `bv-ct-index`: the sorted runs (codec.ts). */
	INDEX: R2Bucket;
	/**
	 * D1 database `bv-ct-index-cursors`: one cursor per CT log (migrations/0001_log_cursors.sql), plus the run
	 * catalog, `meta` and `ops_ledger` (migrations/0002_catalog.sql).
	 */
	CURSORS: D1Database;
	/** Queue `bv-ct-index-entries`: produced by the tailer, consumed by the indexer. */
	ENTRIES: Queue<ObservationBatch>;
	/** Queue `bv-ct-index-compact`: compaction jobs (src/indexer/compact.ts), produced by the hourly planner. */
	COMPACT: Queue<CompactionJob>;
	/**
	 * Queue `bv-ct-index-tail`: one message per tailer shard (src/tailer/fanout.ts), produced by the minute cron.
	 * Unbound, the tailer runs over every log in the cron invocation alone.
	 */
	TAIL?: Queue<ShardRequest>;
	/**
	 * Queue `bv-ct-index-catchup`: one message per catch-up row (src/tailer/catchup.ts), produced by its 2-minute cron.
	 * Unbound, the cron reads the first claimable row itself.
	 */
	CATCHUP?: Queue<CatchupRequest>;
	/**
	 * Var: 'on' makes the tailer store each certificate's details (serial, key, signature, SAN count) on its name
	 * rows; anything else stores none. Older versions cannot read a row with details, and compaction carries the
	 * details forward, so once this has been on, never roll back to a version before it (runbook, "Certificate
	 * details"). Turning it off stops new details but does not remove stored ones.
	 */
	CERT_DETAILS?: string;
	/**
	 * Var: CT-log fetches per run of the bounded catch-up reader (src/tailer/catchup.ts); unset or invalid means its
	 * default. Not declared in the wrangler configs, so a deploy never resets a value the operator set.
	 */
	CATCHUP_MAX_FETCHES?: string;
	/** Var: entries per run of the bounded catch-up reader, shared across its rows; unset or invalid means its default. */
	CATCHUP_MAX_ENTRIES?: string;
	/** Var: get-entries requests in flight per catch-up row, 1 to 8; unset or invalid means its default (6). */
	CATCHUP_PAGES_IN_FLIGHT?: string;
	/** Secret: bearer key for the query API. */
	CT_INDEX_ADMIN_KEY: string;
	/**
	 * Optional secrets: one read key per calling Worker, accepted only with that Worker's X-BV-Caller
	 * (src/api/auth.ts READ_CALLERS). Unset means that caller is refused.
	 */
	CT_INDEX_KEY_BV_MCP?: string;
	CT_INDEX_KEY_BV_WEB_PROD?: string;
	CT_INDEX_KEY_BV2_OPS?: string;
	CT_INDEX_KEY_BV2_RECON?: string;
	CT_INDEX_KEY_BV2_CERTSTREAM?: string;
}

/** One shard per message; never retried (max_retries 0): the next tick re-plans the same logs from their cursors. */
async function tailShards(batch: MessageBatch<unknown>, env: Env): Promise<void> {
	for (const message of batch.messages) {
		const { shard, summary, skipped } = await runShard(env, message.body);
		console.log(
			JSON.stringify(summary ? { event: 'ct_tailer_tick', shard, ...summary } : { event: 'ct_tailer_shard_skipped', shard, skipped }),
		);
		message.ack();
	}
}

/**
 * One catch-up row per message (src/tailer/catchup.ts), on its own queue: a run holds its consumer invocation for about
 * two minutes, so it must not share one with the tailer's shards. max_retries 0, so a throw is logged here (bounded) and
 * not rethrown: the next dispatch re-reads the row from its cursor.
 */
async function catchupRows(batch: MessageBatch<unknown>, env: Env): Promise<void> {
	for (const message of batch.messages) {
		try {
			if (!isCatchupRequest(message.body)) {
				console.log(JSON.stringify({ event: 'ct_catchup_run', skipped: 'malformed' }));
			} else {
				const outcome = await runCatchupMessage(env, message.body);
				console.log(JSON.stringify({ event: 'ct_catchup_run', ...outcome }));
			}
		} catch (error) {
			const text = error instanceof Error ? `${error.name}: ${error.message}` : String(error);
			console.log(JSON.stringify({ event: 'ct_catchup_error', error: text.slice(0, 300) }));
		}
		message.ack();
	}
}

export default {
	async fetch(request, env) {
		const { pathname } = new URL(request.url);
		if (request.method === 'GET' && pathname === '/health') {
			return Response.json({ ok: true, worker: 'bv-ct-index' });
		}
		// /enumerate, /sans and /cert-meta (src/api/): bearer-authenticated, answered from the run index.
		return handleApiRequest(request, env, { reader: createReader(env) });
	},
	async scheduled(controller, env) {
		switch (controller.cron) {
			case '* * * * *': {
				// The tailer (src/tailer/): CT log entries -> ObservationBatch messages on ENTRIES.
				if (!env.TAIL) {
					const summary = await runTailer(env, { scheduledTime: controller.scheduledTime });
					console.log(JSON.stringify({ event: 'ct_tailer_tick', ...summary }));
					break;
				}
				const fanout = await runFanout(env, controller.scheduledTime, env.TAIL);
				console.log(JSON.stringify({ event: 'ct_tailer_fanout', ...fanout }));
				break;
			}
			case CATCHUP_CRON: {
				// The bounded catch-up reader: its own table and kill switch, apart from the forward tail. With its own queue
				// bound, each row is dispatched to its own consumer invocation (its own 6 connection slots); without it, this
				// invocation reads the first claimable row itself.
				if (env.CATCHUP) {
					const dispatch = await dispatchCatchup(env, env.CATCHUP, controller.scheduledTime);
					console.log(JSON.stringify({ event: 'ct_catchup_dispatch', ...dispatch }));
					break;
				}
				const summary = await runCatchup(env);
				console.log(JSON.stringify({ event: 'ct_catchup_run', ...summary }));
				break;
			}
			case COMPACTION_CRON:
			case TRANSITIONAL_COMPACTION_CRON: {
				const transitional = controller.cron === TRANSITIONAL_COMPACTION_CRON;
				if (transitional) console.log(JSON.stringify({ event: 'ct_compaction_transition', cron: controller.cron }));
				// Logged so a tail shows what was enqueued: an `ok` cron with no line says nothing about the plan.
				const { killed, snapshot, jobs } = await runCompactionCron(env, controller.scheduledTime, undefined, transitional);
				const tiers = [1, 2, 3].map((tier) => jobs.filter((job) => job.tier === tier).length);
				const inputs = jobs.reduce((sum, job) => sum + job.inputs.length, 0);
				console.log(JSON.stringify({ event: 'ct_compaction_plan', killed, snapshot, jobs: jobs.length, tiers, inputs }));
				break;
			}
			default:
				// A schedule no case matches (code rolled back while the triggers stayed) must be visible, not silent.
				console.log(JSON.stringify({ event: 'ct_cron_unmatched', cron: controller.cron }));
		}
	},
	async queue(batch, env) {
		if (batch.queue === ENTRIES_QUEUE) await indexEntries(batch, env);
		else if (batch.queue === COMPACT_QUEUE) await runCompactionBatch(batch, env);
		else if (batch.queue === TAIL_QUEUE) await tailShards(batch, env);
		else if (batch.queue === CATCHUP_QUEUE) await catchupRows(batch, env);
		else throw new Error(`bv-ct-index has no consumer for queue ${batch.queue}`);
	},
} satisfies ExportedHandler<Env, unknown>;
