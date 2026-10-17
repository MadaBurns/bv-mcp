// SPDX-License-Identifier: BUSL-1.1
/**
 * bv-ct-index sidecar Worker entrypoint (US-12 wave 1 stub).
 *
 * Wave 2 fills disjoint modules: the tailer (src/tailer/) and compaction planner behind `scheduled`,
 * the indexer and compaction jobs behind `queue` (one handler for both queues, told apart by
 * `batch.queue`), and the query API (src/api/) behind `fetch`. Until then only GET /health answers.
 */

import { runTailer } from './tailer';
import type { ObservationBatch } from './types';

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
	/** Queue `bv-ct-index-compact`: compaction jobs, one key range each. The compaction ticket pins the message shape. */
	COMPACT: Queue<unknown>;
	/** Secret: bearer key for the query API. */
	CT_INDEX_ADMIN_KEY: string;
}

export default {
	async fetch(request) {
		const { pathname } = new URL(request.url);
		if (request.method === 'GET' && pathname === '/health') {
			return Response.json({ ok: true, worker: 'bv-ct-index' });
		}
		return Response.json({ error: 'not_implemented' }, { status: 501 });
	},
	async scheduled(controller, env) {
		switch (controller.cron) {
			case '* * * * *': {
				// The tailer (src/tailer/): CT log entries -> ObservationBatch messages on ENTRIES.
				const summary = await runTailer(env, { scheduledTime: controller.scheduledTime });
				console.log(JSON.stringify({ event: 'ct_tailer_tick', ...summary }));
				break;
			}
		}
	},
	async queue() {},
} satisfies ExportedHandler<Env, unknown>;
