// SPDX-License-Identifier: BUSL-1.1
/**
 * bv-ct-index sidecar Worker entrypoint (US-12).
 *
 * `scheduled`: the tailer (src/tailer/) and the compaction planner. `queue`: the indexer, compaction jobs and tailer
 * shards (one handler for all three queues, told apart by `batch.queue`). `fetch`: GET /health, open, and the
 * bearer-authenticated query API (src/api/).
 */

import { handleApiRequest } from './api/handler';
import type { CompactionJob } from './indexer/compact';
import { runCompactionBatch } from './indexer/compact';
import { COMPACTION_CRON, runCompactionCron } from './indexer/plan';
import { createReader } from './indexer/read';
import { indexEntries } from './indexer/write';
import { runTailer } from './tailer';
import { runFanout, runShard, type ShardRequest } from './tailer/fanout';
import type { ObservationBatch } from './types';

export const ENTRIES_QUEUE = 'bv-ct-index-entries';
export const COMPACT_QUEUE = 'bv-ct-index-compact';
export const TAIL_QUEUE = 'bv-ct-index-tail';

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
			case COMPACTION_CRON: {
				// Logged so a tail shows what was enqueued: an `ok` cron with no line says nothing about the plan.
				const { killed, snapshot, jobs } = await runCompactionCron(env, controller.scheduledTime);
				const tiers = [1, 2, 3].map((tier) => jobs.filter((job) => job.tier === tier).length);
				const inputs = jobs.reduce((sum, job) => sum + job.inputs.length, 0);
				console.log(JSON.stringify({ event: 'ct_compaction_plan', killed, snapshot, jobs: jobs.length, tiers, inputs }));
				break;
			}
		}
	},
	async queue(batch, env) {
		if (batch.queue === ENTRIES_QUEUE) await indexEntries(batch, env);
		else if (batch.queue === COMPACT_QUEUE) await runCompactionBatch(batch, env);
		else if (batch.queue === TAIL_QUEUE) await tailShards(batch, env);
		else throw new Error(`bv-ct-index has no consumer for queue ${batch.queue}`);
	},
} satisfies ExportedHandler<Env, unknown>;
