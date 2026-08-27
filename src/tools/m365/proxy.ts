// SPDX-License-Identifier: BUSL-1.1

/**
 * Shared proxy helper for M365 read tools.
 *
 * Behaviour:
 *   - No proxy binding → fail-soft: { ok: false, unprovisioned: true, tool: path }
 *   - HTTP non-2xx     → { ok: false, error: 'm365_proxy_<status>' }
 *   - fetch throws     → { ok: false, error: 'm365_proxy_unreachable' }
 *   - HTTP 2xx         → { ok: true, data: <parsed json> }
 *
 * Never throws.
 */
import type { M365ProxyResult } from './types';
import { disposeUnreadResponseBody, readJsonResponseCapped } from '../../lib/response-body';

// Target endpoint for the M365 read tools, reached via the `BV_WEB` service
// binding (repointed at `bv-web-prod` in #414). Over a service binding the host
// is irrelevant — only the PATH is matched downstream — so the `bv-web-internal`
// host is a stable placeholder.
//
// ISSUE #403 (repoint): this `/api/internal/mcp/m365/*` path is now served by
// `bv-web-prod` (`app/routes/api/internal/mcp/m365.ts`, registered as
// `api/internal/mcp/m365/:tool`), mirroring the validate-key internal-route
// pattern with a dedicated `BV_MCP_M365_KEY` bearer. The three active `<path>`
// segments map to `query-signins`, `get-ca-policies`, and `assess-coverage`.
// Deprecated `query_ual` is retained as a local compatibility tombstone and
// never calls this helper.
//
// HONESTY: the three active paths may return either live or representative
// fallback data depending on tenant provisioning. bv-mcp passes that producer
// envelope through opaquely as `{ ok: true, data }`. A non-2xx (e.g. 503 when
// the internal key is unset, 401 on a bad bearer) surfaces as
// `m365_proxy_<status>` and the tool stays fail-soft — this helper never throws.
const M365_BASE_URL = 'https://bv-web-internal/api/internal/mcp/m365';
const TIMEOUT_MS = 10_000;
const M365_PROXY_MAX_BODY_BYTES = 2 * 1024 * 1024;

export type M365PrincipalIdentity =
	| { kind: 'api_key'; credentialHash: string }
	| { kind: 'oauth_tenant'; tenantId: string; principalId: string };

export interface M365ProxyOptions {
	authToken?: string;
	identity?: M365PrincipalIdentity;
}

export async function callM365Proxy(
	proxy: { fetch: typeof fetch } | undefined,
	path: string,
	body: unknown,
	opts?: M365ProxyOptions,
): Promise<M365ProxyResult> {
	if (!proxy) {
		return { ok: false, unprovisioned: true, tool: path };
	}
	try {
		const headers: Record<string, string> = { 'Content-Type': 'application/json' };
		if (opts?.authToken) {
			headers['Authorization'] = `Bearer ${opts.authToken}`;
		}
		const response = await proxy.fetch(`${M365_BASE_URL}/${path}`, {
			method: 'POST',
			headers,
			body: JSON.stringify({ ...(body as object), identity: opts?.identity }),
			signal: AbortSignal.timeout(TIMEOUT_MS) as never,
		});
		if (!response.ok) {
			await disposeUnreadResponseBody(response);
			return { ok: false, error: `m365_proxy_${response.status}` };
		}
		const data = await readJsonResponseCapped<unknown>(response, M365_PROXY_MAX_BODY_BYTES);
		if (data === null) return { ok: false, error: 'm365_proxy_unreachable' };
		return { ok: true, data };
	} catch {
		return { ok: false, error: 'm365_proxy_unreachable' };
	}
}
