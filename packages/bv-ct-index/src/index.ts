// SPDX-License-Identifier: BUSL-1.1
/**
 * bv-ct-index sidecar Worker entrypoint (US-12 wave 1 stub).
 *
 * Wave 2 fills disjoint modules: the tailer (src/tailer/) and compactor (src/indexer/) behind
 * `scheduled`, the indexer (src/indexer/) behind `queue`, and the query API (src/api/) behind
 * `fetch`. Until then only GET /health answers.
 */

import type { EntryBatch } from './types';

export interface Env {
	/** R2 bucket `bv-ct-index`: partition and suffix-rollup segments (key helpers in codec.ts). */
	INDEX: R2Bucket;
	/** D1 database `bv-ct-index-cursors`: one cursor per CT log (migrations/0001_log_cursors.sql). */
	CURSORS: D1Database;
	/** Queue `bv-ct-index-entries`: produced by the tailer, consumed by the indexer. */
	ENTRIES: Queue<EntryBatch>;
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
	async scheduled() {},
	async queue() {},
} satisfies ExportedHandler<Env, EntryBatch>;
