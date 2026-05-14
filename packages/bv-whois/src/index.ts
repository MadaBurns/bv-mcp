// SPDX-License-Identifier: BUSL-1.1
/**
 * bv-whois shim Worker entrypoint.
 *
 * Wires the production deps (KV namespace + real TCP/43 transport) into the
 * Hono app and exports the standard Worker `fetch` handler.
 */

import { buildApp } from './app';
import { whoisQuery } from './transport';
import type { KVLike } from './resolver';

interface Env {
	WHOIS_CACHE: KVLike;
}

export default {
	async fetch(request: Request, env: Env): Promise<Response> {
		const app = buildApp({
			kv: env.WHOIS_CACHE,
			whoisQuery: (server: string, query: string) => whoisQuery(server, query),
		});
		return app.fetch(request, env);
	},
};
