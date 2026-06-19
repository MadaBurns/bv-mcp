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

// Target endpoint for the M365 read tools, reached via the `BV_WEB` service
// binding (repointed at `bv-web-prod` in #414). Over a service binding the host
// is irrelevant — only the PATH is matched downstream — so the `bv-web-internal`
// host is a stable placeholder.
//
// ISSUE #403 (repoint): this `/api/internal/mcp/m365/*` path is now served by
// `bv-web-prod` (`app/routes/api/internal/mcp/m365.ts`, registered as
// `api/internal/mcp/m365/:tool`), mirroring the validate-key internal-route
// pattern + `BV_WEB_INTERNAL_KEY` bearer auth. The four `<path>` segments map to
// the four identity_secops tools: `query-signins`, `query-ual`,
// `get-ca-policies`, `assess-coverage`.
//
// HONESTY: bv-web-prod's live M365 posture (Graph fetch / compliance scan) is
// operator-gated behind its unbound `M365_DB` + Graph token, so today the route
// returns a clearly-labelled `representative: true` seam (NOT fabricated live
// data) until that downstream slice is provisioned. bv-mcp passes the response
// through opaquely as `{ ok: true, data }`. A non-2xx (e.g. 503 when the
// internal key is unset, 401 on a bad bearer) surfaces as `m365_proxy_<status>`
// and the tool stays fail-soft — the proxy never throws (see callM365Proxy).
const M365_BASE_URL = 'https://bv-web-internal/api/internal/mcp/m365';
const TIMEOUT_MS = 10_000;

export async function callM365Proxy(
	proxy: { fetch: typeof fetch } | undefined,
	path: string,
	body: unknown,
	opts?: { authToken?: string; keyHash?: string },
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
			body: JSON.stringify({ ...(body as object), keyHash: opts?.keyHash }),
			signal: AbortSignal.timeout(TIMEOUT_MS) as never,
		});
		if (!response.ok) {
			// Consume body to avoid leaking the connection.
			await response.text().catch(() => undefined);
			return { ok: false, error: `m365_proxy_${response.status}` };
		}
		const data: unknown = await response.json();
		return { ok: true, data };
	} catch {
		return { ok: false, error: 'm365_proxy_unreachable' };
	}
}
