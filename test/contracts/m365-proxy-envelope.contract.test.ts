// SPDX-License-Identifier: BUSL-1.1
/**
 * Contract: bv-web-prod → bv-mcp M365 proxy WIRE surface (consumer side).
 *
 * Endpoint: POST /api/internal/m365/<tool> over the `m365Proxy` (BV_WEB) service
 * binding, called by `callM365Proxy` in src/tools/m365/proxy.ts. The four
 * identity_secops tools (query_signins, query_ual, get_ca_policies,
 * assess_coverage) all funnel through this one helper.
 *
 * This is the CONSUMER-side complement to bv-web-prod's own
 * `m365.contract.test.ts` (the producer side, from #403). It pins how bv-mcp
 * CLASSIFIES the producer's response envelope into the `M365ProxyResult` union —
 * so a future bv-web-prod envelope change (or an accidental classification
 * regression here) is caught at this seam rather than only in prod.
 *
 * The producer answers map to four bv-mcp behaviors:
 *   - binding absent          → { ok: false, unprovisioned: true, tool }
 *   - HTTP 2xx + JSON body    → { ok: true, data: <parsed json> }  (passthrough)
 *   - HTTP non-2xx            → { ok: false, error: 'm365_proxy_<status>' }
 *   - fetch throws / timeout  → { ok: false, error: 'm365_proxy_unreachable' }
 *
 * The seam under test classifies on HTTP status + reachability ONLY — it does
 * NOT inspect the JSON body, so the `representative: true` (sample-vs-live)
 * marker rides through opaquely inside `data` on the 2xx path (issue #417 part
 * 2 labels it in the tool descriptions; the proxy stays body-agnostic).
 *
 * Never throws — every branch resolves to a value.
 */
import { describe, expect, it, vi } from 'vitest';
import { callM365Proxy } from '../../src/tools/m365/proxy';
import type { M365ProxyResult } from '../../src/tools/m365/types';

/** Build a minimal service-binding stub whose fetch returns `response`. */
function proxyReturning(response: Response): { fetch: typeof fetch } {
	return { fetch: vi.fn().mockResolvedValue(response) as unknown as typeof fetch };
}

/** Build a service-binding stub whose fetch rejects (network/binding failure). */
function proxyThrowing(err: unknown): { fetch: typeof fetch } {
	return { fetch: vi.fn().mockRejectedValue(err) as unknown as typeof fetch };
}

describe('M365 proxy envelope contract (consumer side)', () => {
	// ─── Branch 1: binding absent → fail-soft unprovisioned ────────────────────
	it('no binding → { ok: false, unprovisioned: true, tool } and never calls fetch', async () => {
		const result: M365ProxyResult = await callM365Proxy(undefined, 'query-signins', { ms_tenant_id: 't' });

		expect(result).toEqual({ ok: false, unprovisioned: true, tool: 'query-signins' });
		// `tool` echoes the path so the caller can attribute the unprovisioned answer.
		expect(result).not.toHaveProperty('error');
	});

	// ─── Branch 2: HTTP 2xx + JSON → opaque passthrough of the producer body ────
	it('200 + JSON body → { ok: true, data } passing the parsed body through verbatim', async () => {
		// A representative producer body: the seam-era sample payload carries the
		// `representative: true` marker the #417 labeling describes. The proxy must
		// pass it through UNINSPECTED — it classifies on status only.
		const producerBody = {
			representative: true,
			signins: [{ user: 'alice@example.com', status: 'success' }],
		};
		const proxy = proxyReturning(Response.json(producerBody));

		const result = await callM365Proxy(proxy, 'query-signins', { ms_tenant_id: 't' });

		expect(result.ok).toBe(true);
		if (!result.ok) throw new Error('expected ok result');
		// Body rides through opaquely — including the sample/non-live marker.
		expect(result.data).toEqual(producerBody);
		expect((result.data as { representative?: unknown }).representative).toBe(true);
		expect(proxy.fetch).toHaveBeenCalledOnce();
	});

	it('204-class 2xx → still ok:true (status drives classification, not body shape)', async () => {
		// Use 200 with an empty object to model a sparse live answer; the point is
		// that any 2xx is ok:true regardless of payload content.
		const proxy = proxyReturning(Response.json({}, { status: 200 }));

		const result = await callM365Proxy(proxy, 'assess-coverage', { ms_tenant_id: 't' });

		expect(result).toEqual({ ok: true, data: {} });
	});

	// ─── Branch 3: HTTP non-2xx → typed error string carrying the status ───────
	it('404 → { ok: false, error: "m365_proxy_404" } (the prod fail-soft, no live endpoint)', async () => {
		const proxy = proxyReturning(new Response('Not Found', { status: 404 }));

		const result = await callM365Proxy(proxy, 'get-ca-policies', { ms_tenant_id: 't' });

		expect(result).toEqual({ ok: false, error: 'm365_proxy_404' });
	});

	it('non-2xx error string interpolates the exact upstream status code', async () => {
		for (const status of [401, 403, 500, 503]) {
			const proxy = proxyReturning(new Response('err', { status }));
			const result = await callM365Proxy(proxy, 'query-ual', { ms_tenant_id: 't' });
			expect(result).toEqual({ ok: false, error: `m365_proxy_${status}` });
		}
	});

	// ─── Branch 4: fetch throws / aborts → single unreachable verdict ──────────
	it('fetch throws (network/binding failure) → { ok: false, error: "m365_proxy_unreachable" }', async () => {
		const proxy = proxyThrowing(new Error('network error'));

		const result = await callM365Proxy(proxy, 'query-signins', { ms_tenant_id: 't' });

		expect(result).toEqual({ ok: false, error: 'm365_proxy_unreachable' });
	});

	it('timeout/abort is classified as unreachable, NOT a status error (never throws)', async () => {
		const proxy = proxyThrowing(new DOMException('The operation was aborted', 'TimeoutError'));

		const result = await callM365Proxy(proxy, 'assess-coverage', { ms_tenant_id: 't' });

		expect(result).toEqual({ ok: false, error: 'm365_proxy_unreachable' });
	});

	// ─── Wire request shape: keyHash is folded into the POST body, bearer header ─
	it('threads keyHash into the request body and authToken into the Authorization header', async () => {
		const fetchMock = vi.fn().mockResolvedValue(Response.json({ representative: true }));
		const proxy = { fetch: fetchMock as unknown as typeof fetch };

		await callM365Proxy(proxy, 'query-signins', { ms_tenant_id: 'tenant-123' }, { authToken: 'tok', keyHash: 'abc123' });

		expect(fetchMock).toHaveBeenCalledOnce();
		const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
		expect(url).toBe('https://bv-web-internal/api/internal/m365/query-signins');
		expect(init.method).toBe('POST');
		expect((init.headers as Record<string, string>)['Authorization']).toBe('Bearer tok');
		expect((init.headers as Record<string, string>)['Content-Type']).toBe('application/json');
		// keyHash is merged into the body alongside the caller args.
		expect(JSON.parse(init.body as string)).toEqual({ ms_tenant_id: 'tenant-123', keyHash: 'abc123' });
	});

	it('omits the Authorization header when no authToken is supplied', async () => {
		const fetchMock = vi.fn().mockResolvedValue(Response.json({}));
		const proxy = { fetch: fetchMock as unknown as typeof fetch };

		await callM365Proxy(proxy, 'get-ca-policies', { ms_tenant_id: 't' });

		const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
		expect((init.headers as Record<string, string>)['Authorization']).toBeUndefined();
		// keyHash absent → body carries an explicit undefined (dropped by JSON.stringify).
		expect(JSON.parse(init.body as string)).toEqual({ ms_tenant_id: 't' });
	});
});
