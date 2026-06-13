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
// binding. NOTE (issue #403): this `/api/internal/m365/*` path was served by
// the now-retired `bv-web` SSR app. The active app, `bv-web-prod`, does NOT
// implement it — M365 there is session-authenticated dashboard reads from D1
// (`app/lib/dashboard/m365/*`), not an internal proxy. Until/unless that
// endpoint is built downstream, the four identity_secops tools fail-soft with
// `m365_proxy_404` in prod (the proxy never throws — see callM365Proxy). Kept
// in place intentionally as a deferred surface; do not treat as live.
const M365_BASE_URL = 'https://bv-web-internal/api/internal/m365';
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
