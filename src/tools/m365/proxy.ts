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

const M365_BASE_URL = 'https://bv-web-internal/m365';
const TIMEOUT_MS = 10_000;

export async function callM365Proxy(
	proxy: { fetch: typeof fetch } | undefined,
	path: string,
	body: unknown,
): Promise<M365ProxyResult> {
	if (!proxy) {
		return { ok: false, unprovisioned: true, tool: path };
	}
	try {
		const response = await proxy.fetch(`${M365_BASE_URL}/${path}`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify(body),
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
