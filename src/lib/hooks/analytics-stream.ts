// SPDX-License-Identifier: BUSL-1.1

/**
 * Analytics Stream Hook (Private Layer Interface)
 *
 * Streams a completed multi-tenant scan to bv-web-prod's internal ingest route
 * so the platform can roll up tenant scan telemetry. Called from the tenant
 * queue-consumer (src/tenants/queue-consumer.ts) inside `ctx.waitUntil(...)`.
 *
 * Target: `POST https://internal/api/internal/mcp/ingest-scan` on the `BV_WEB`
 * service binding (bv-web-prod `app/routes/api/internal/mcp/ingest-scan.ts`, added
 * for #418). The `https://internal` host + `/api/internal/...` path mirror the
 * proven entitlements/tier-auth binding calls — a bare path or a wrong path would
 * not resolve to a bv-web-prod route. The route is `BV_WEB_INTERNAL_KEY`-bearer
 * gated, so this hook forwards `Authorization: Bearer ${BV_WEB_INTERNAL_KEY}`
 * (mirroring every other internal cross-worker call).
 *
 * Fully FAIL-SOFT: this is best-effort telemetry. The binding is absent on OSS /
 * BSL self-hosts (noop), and any error — missing key, transient fetch failure,
 * non-2xx — is swallowed so a queue message is never redelivered over telemetry.
 */
interface AnalyticsHookEnv {
	BV_WEB?: { fetch: (input: RequestInfo, init?: RequestInit) => Promise<Response> };
	/** Shared bearer for bv-web-prod's internal routes. Absent on OSS/self-host. */
	BV_WEB_INTERNAL_KEY?: string;
	[key: string]: unknown;
}

export async function streamScanResult(env: AnalyticsHookEnv, payload: unknown): Promise<void> {
	// Noop when the private binding or its bearer is absent (OSS / BSL self-host):
	// posting unauthenticated would just earn a 401 from the gated route.
	if (!env.BV_WEB || typeof env.BV_WEB.fetch !== 'function' || !env.BV_WEB_INTERNAL_KEY) {
		return;
	}
	try {
		await env.BV_WEB.fetch(
			new Request('https://internal/api/internal/mcp/ingest-scan', {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					Authorization: `Bearer ${env.BV_WEB_INTERNAL_KEY}`,
				},
				body: JSON.stringify(payload),
				// Bound the best-effort telemetry POST so a stalled bv-web-prod ingest
				// route can't keep this waitUntil() promise alive to the wall-clock limit
				// (parity with lib/alerting.ts + lib/analytics-engine.ts).
				signal: AbortSignal.timeout(5_000),
			}),
		);
	} catch (e) {
		console.error('Analytics stream failed:', e);
	}
}
