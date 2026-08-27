// SPDX-License-Identifier: BUSL-1.1
/**
 * Contract: bv-mcp → bv-web-prod M365 seam, pinned at the REGISTRY boundary (#417 part 3).
 *
 * Companion to `m365-proxy-envelope.contract.test.ts`, which pins the seam at
 * `callM365Proxy` — the helper in isolation. That leaves both ENDS of the real
 * request path unpinned, and both are where a silent cross-repo break lands:
 *
 *   (a) the OUTBOUND end — `handleToolsCall`'s three active `identity_secops`
 *       dispatch arms (`src/handlers/tools.ts`) are what actually supply the proxy binding
 *       and the `m365ProxyAuthToken` bearer. Existing Authorization-header
 *       assertions call the three active tool functions DIRECTLY with an explicit
 *       `authToken`, so they cannot see the registry dropping that argument. Drop
 *       `authToken: runtimeOptions?.m365ProxyAuthToken` at any of those three call
 *       sites and every production call goes out UNAUTHENTICATED — bv-web-prod's
 *       bearer gate answers 401, bv-mcp classifies `m365_proxy_401`, and the whole
 *       existing suite stays green. Same for the URL: the path segments are what
 *       bv-web-prod's `api/internal/mcp/m365/:tool` route switches on, and a
 *       rename here 404s in prod (it already has once — `daaa741e`, "proxy URL
 *       path /api/internal/m365 (was /m365 → 405)").
 *
 *   (b) the INBOUND end — whether the producer's envelope survives `handleToolsCall`
 *       to the MCP caller. `callM365Proxy` returning `{ ok: true, data }` proves
 *       nothing about what the tool response carries; the `representative`
 *       sample-vs-live marker that #417 part 2 labels in the tool descriptions is
 *       only honest if it actually reaches the client, in BOTH channels (the text
 *       `content` an LLM reads and the MCP-standard `structuredContent` a program
 *       reads). All four registered tools are in `NON_CHECK_RESULT_TOOLS`, so they publish
 *       no `outputSchema` — nothing else constrains their response shape at all.
 *
 * Everything below drives the REAL registry (`handleToolsCall`) against a mocked
 * binding. No live network, no live Graph, no bv-web-prod call.
 *
 * ⚠️ Cross-repo caveat: the request URL/method/auth pinned here is what bv-mcp
 * PROMISES TO SEND, and the classification is what bv-mcp REQUIRES TO RECEIVE.
 * bv-web-prod's own producer-side contract test is the other half; neither repo
 * can prove the pair alone.
 */
import { describe, expect, it } from 'vitest';
import { NON_CHECK_RESULT_TOOLS, TOOLS } from '../../src/schemas/tool-definitions';

/** Active MCP tool name → the bv-web-prod `:tool` path segment bv-mcp must request. */
const ACTIVE_TOOL_PATH_SEGMENTS: Record<string, string> = {
	query_signins: 'query-signins',
	get_ca_policies: 'get-ca-policies',
	assess_coverage: 'assess-coverage',
};
const IDENTITY_SECOPS_TOOLS = [...Object.keys(ACTIVE_TOOL_PATH_SEGMENTS), 'query_ual'];

/**
 * The base path bv-web-prod registers the route under. Over a service binding the
 * HOST is irrelevant (only the path is matched downstream), so the placeholder
 * host is not part of the cross-repo contract — the PATH is.
 */
const M365_BASE_PATH = '/api/internal/mcp/m365';

/** A real principal — the Layer-2 registry guard hard-rejects without one. */
const KEY_HASH = 'a'.repeat(64);
const M365_IDENTITY = { kind: 'api_key' as const, credentialHash: KEY_HASH };
const INTERNAL_BEARER = 'bv-web-internal-key-value';

interface CapturedRequest {
	url: string;
	method: string | undefined;
	headers: Record<string, string>;
	body: Record<string, unknown>;
}

/** Binding stub that records the outbound request and answers with `respond()`. */
function capturingProxy(respond: () => Response): {
	proxy: { fetch: typeof fetch };
	calls: CapturedRequest[];
} {
	const calls: CapturedRequest[] = [];
	const proxy = {
		fetch: (async (input: RequestInfo | URL, init?: RequestInit) => {
			const raw = init?.headers;
			const headers: Record<string, string> = {};
			if (raw instanceof Headers) {
				raw.forEach((v, k) => {
					headers[k] = v;
				});
			} else if (raw) {
				Object.assign(headers, raw as Record<string, string>);
			}
			calls.push({
				url: String(input),
				method: init?.method,
				headers,
				body: JSON.parse((init?.body as string) ?? '{}') as Record<string, unknown>,
			});
			return respond();
		}) as unknown as typeof fetch,
	};
	return { proxy, calls };
}

/** Extract the parsed `M365ProxyResult` a caller sees in the text channel. */
function parseTextChannel(result: { content?: { type: string; text?: string }[] }): Record<string, unknown> {
	const first = result.content?.[0];
	if (first?.type !== 'text' || typeof first.text !== 'string') throw new Error('expected a text content block');
	return JSON.parse(first.text) as Record<string, unknown>;
}

// ───────────────────────────────────────────────────────────────────────────────
// SSOT: the set under contract is DERIVED, so a fifth identity_secops tool added
// to TOOL_DEFS without a seam contract fails here instead of shipping unpinned.
// ───────────────────────────────────────────────────────────────────────────────

describe('M365 seam — the contracted tool set is derived from the registry', () => {
	it('every identity_secops tool has a pinned bv-web-prod path segment', () => {
		const registryTools = TOOLS.filter((t) => t.group === 'identity_secops')
			.map((t) => t.name)
			.sort();

		expect(registryTools).toEqual([...IDENTITY_SECOPS_TOOLS].sort());
	});

	it('every identity_secops tool is a NON_CHECK_RESULT_TOOL (custom envelope, no outputSchema)', () => {
		// Load-bearing for the inbound assertions below: because these tools publish
		// no `outputSchema`, the response shape is constrained by NOTHING except
		// these tests. Were one to be moved out of the set, its envelope would be
		// re-shaped to CheckResult and the `representative` marker would vanish.
		for (const name of IDENTITY_SECOPS_TOOLS) {
			expect(NON_CHECK_RESULT_TOOLS.has(name)).toBe(true);
			const def = TOOLS.find((t) => t.name === name);
			expect(def?.outputSchema).toBeUndefined();
		}
	});
});

const LIVE_CAPABLE_UNVERIFIED_TOOLS = ['query_signins', 'get_ca_policies', 'assess_coverage'] as const;

describe('M365 seam — tool descriptions disclose lifecycle and sample/live provenance before use', () => {
	for (const name of LIVE_CAPABLE_UNVERIFIED_TOOLS) {
		it(`${name} discloses the unverified live path and preserves per-response sample/live semantics`, () => {
			const def = TOOLS.find((t) => t.name === name);
			expect(def).toBeDefined();
			expect(def!.description.startsWith('LIVE PATH NOT YET PRODUCTION-VERIFIED')).toBe(true);
			expect(def!.description).toContain('`true` is sample/fallback data');
			expect(def!.description).toContain('`false` means the upstream Microsoft Graph read succeeded');
		});
	}

	it('query_ual is an explicit compatibility tombstone, not an advertised future integration', () => {
		const def = TOOLS.find((t) => t.name === 'query_ual');
		expect(def).toBeDefined();
		expect(def!.description.startsWith('DEPRECATED')).toBe(true);
		expect(def!.description).toContain('query_ual_deprecated');
		expect(def!.description).toContain('never calls the M365 proxy');
		expect(def!.description).not.toContain('integration is not yet implemented');
		expect(def!.annotations?.title).toContain('Deprecated');
		expect(def!.lifecycle).toEqual({
			status: 'deprecated',
			reason: 'sample_only_no_live_path',
			replacement: null,
		});
	});
});

// ───────────────────────────────────────────────────────────────────────────────
// OUTBOUND: what bv-mcp promises to send bv-web-prod, driven through the registry.
// ───────────────────────────────────────────────────────────────────────────────

describe('M365 seam — outbound request contract (through handleToolsCall)', () => {
	for (const [toolName, segment] of Object.entries(ACTIVE_TOOL_PATH_SEGMENTS)) {
		it(`${toolName} → POST ${M365_BASE_PATH}/${segment} with the internal bearer`, async () => {
			const { handleToolsCall } = await import('../../src/handlers/tools');
			const { proxy, calls } = capturingProxy(() => Response.json({ representative: true }));

			await handleToolsCall({ name: toolName, arguments: { ms_tenant_id: 'tenant-abc' } }, undefined, {
				m365Proxy: proxy,
				m365ProxyAuthToken: INTERNAL_BEARER,
				keyHash: KEY_HASH,
				m365Identity: M365_IDENTITY,
			});

			expect(calls).toHaveLength(1);
			const call = calls[0]!;

			// PATH is the cross-repo contract — bv-web-prod routes on `:tool`.
			expect(new URL(call.url).pathname).toBe(`${M365_BASE_PATH}/${segment}`);
			expect(call.method).toBe('POST');
			expect(call.headers['Content-Type']).toBe('application/json');

			// THE UNCOVERED WIRE: the registry must thread `m365ProxyAuthToken`
			// (= BV_MCP_M365_KEY) into the bearer. Dropping it at the dispatch
			// arm is invisible to every other test in the repo and 401s in prod.
			expect(call.headers['Authorization']).toBe(`Bearer ${INTERNAL_BEARER}`);

			// The discriminated identity rides in the body; security ownership and
			// downstream credential lookup are not overloaded onto one hash field.
			expect(call.body.identity).toEqual(M365_IDENTITY);
			expect(call.body.ms_tenant_id).toBe('tenant-abc');
		});
	}

	it('query_ual is a deprecated tombstone that never calls the M365 proxy', async () => {
		const { handleToolsCall } = await import('../../src/handlers/tools');
		const { proxy, calls } = capturingProxy(() => Response.json({ representative: true }));

		const result = await handleToolsCall({ name: 'query_ual', arguments: { ms_tenant_id: 'tenant-abc' } }, undefined, {
			m365Proxy: proxy,
			m365ProxyAuthToken: INTERNAL_BEARER,
			keyHash: KEY_HASH,
			m365Identity: M365_IDENTITY,
		});

		expect(calls).toHaveLength(0);
		expect(result.isError).toBe(true);
		expect(result.structuredContent).toEqual({ ok: false, error: 'query_ual_deprecated' });
		expect(parseTextChannel(result)).toEqual({ ok: false, error: 'query_ual_deprecated' });
		expect(result._meta).toEqual({
			'com.blackveilsecurity/tool-status': {
				status: 'deprecated',
				reason: 'sample_only_no_live_path',
				replacement: null,
			},
		});
	});

	it('query_ual retains legacy argument validation before the tombstone', async () => {
		const { handleToolsCall } = await import('../../src/handlers/tools');
		const { proxy, calls } = capturingProxy(() => Response.json({ representative: true }));

		const result = await handleToolsCall({ name: 'query_ual', arguments: {} }, undefined, {
			m365Proxy: proxy,
			m365ProxyAuthToken: INTERNAL_BEARER,
			keyHash: KEY_HASH,
		});

		expect(calls).toHaveLength(0);
		expect(result).toEqual({
			content: [{ type: 'text', text: 'Error: Missing required parameter: ms_tenant_id' }],
			isError: true,
		});
	});

	it('query_ual retains the identity auth backstop before the tombstone', async () => {
		const { handleToolsCall } = await import('../../src/handlers/tools');
		const { proxy, calls } = capturingProxy(() => Response.json({ representative: true }));

		const result = await handleToolsCall({ name: 'query_ual', arguments: { ms_tenant_id: 'tenant-abc' } }, undefined, {
			m365Proxy: proxy,
			m365ProxyAuthToken: INTERNAL_BEARER,
		});

		expect(calls).toHaveLength(0);
		expect(result).toEqual({
			content: [{ type: 'text', text: 'Error: Invalid request: m365_proxy_unauthenticated (authentication required).' }],
			isError: true,
		});
	});

	it('forwards the optional query_signins filters bv-web-prod reads off the body', async () => {
		const { handleToolsCall } = await import('../../src/handlers/tools');
		const { proxy, calls } = capturingProxy(() => Response.json({ representative: true }));

		await handleToolsCall(
			{
				name: 'query_signins',
				arguments: { ms_tenant_id: 'tenant-abc', user_principal_name: 'alice@example.com', failures_only: true, since_hours: 6 },
			},
			undefined,
			{ m365Proxy: proxy, m365ProxyAuthToken: INTERNAL_BEARER, keyHash: KEY_HASH, m365Identity: M365_IDENTITY },
		);

		expect(calls[0]!.body).toMatchObject({
			ms_tenant_id: 'tenant-abc',
			user_principal_name: 'alice@example.com',
			failures_only: true,
			since_hours: 6,
			identity: M365_IDENTITY,
		});
	});
});

// ───────────────────────────────────────────────────────────────────────────────
// INBOUND: what bv-mcp requires to receive, and what survives to the caller.
// ───────────────────────────────────────────────────────────────────────────────

describe('M365 seam — the representative sample/live marker reaches the caller', () => {
	it('representative: true survives to BOTH the text channel and structuredContent', async () => {
		const { handleToolsCall } = await import('../../src/handlers/tools');
		const producerBody = { representative: true, signIns: [{ userPrincipalName: 'alice@example.com', status: 'failure' }] };
		const { proxy } = capturingProxy(() => Response.json(producerBody));

		const result = await handleToolsCall({ name: 'query_signins', arguments: { ms_tenant_id: 'tenant-abc' } }, undefined, {
			m365Proxy: proxy,
			m365ProxyAuthToken: INTERNAL_BEARER,
			keyHash: KEY_HASH,
			m365Identity: M365_IDENTITY,
		});

		expect(result.isError).toBeFalsy();

		// Text channel — what an LLM client reads and repeats to a human. The
		// #417-part-2 tool descriptions promise this marker is checkable per
		// response; a caller can only honour that if it is actually here.
		const text = parseTextChannel(result);
		expect(text.ok).toBe(true);
		expect((text.data as Record<string, unknown>).representative).toBe(true);

		// structuredContent — the MCP-standard machine channel. Same marker.
		expect(result.structuredContent?.ok).toBe(true);
		expect((result.structuredContent?.data as Record<string, unknown>).representative).toBe(true);
	});

	it('representative: false (live Graph read) survives verbatim — never coerced or dropped', async () => {
		// bv-web-prod's `liveGetCaPolicies()` stamps `false` once a tenant is
		// connected and keyed. Presenting live Entra data as a sample is as wrong as
		// the reverse, so `false` must arrive as `false` — not absent, not falsy-by-omission.
		const { handleToolsCall } = await import('../../src/handlers/tools');
		const liveBody = { representative: false, policies: [{ displayName: 'Require MFA for admins', state: 'enabled' }] };
		const { proxy } = capturingProxy(() => Response.json(liveBody));

		const result = await handleToolsCall({ name: 'get_ca_policies', arguments: { ms_tenant_id: 'tenant-abc' } }, undefined, {
			m365Proxy: proxy,
			m365ProxyAuthToken: INTERNAL_BEARER,
			keyHash: KEY_HASH,
			m365Identity: M365_IDENTITY,
		});

		const data = result.structuredContent?.data as Record<string, unknown>;
		expect(Object.hasOwn(data, 'representative')).toBe(true);
		expect(data.representative).toBe(false);
		expect(parseTextChannel(result).data).toEqual(liveBody);
	});

	it('does NOT synthesize a marker the producer omitted', async () => {
		// Absence must stay absence at the registry too: a default of either value
		// would silently mislabel one of the two envelopes above.
		const { handleToolsCall } = await import('../../src/handlers/tools');
		const { proxy } = capturingProxy(() => Response.json({ policies: [] }));

		const result = await handleToolsCall({ name: 'get_ca_policies', arguments: { ms_tenant_id: 'tenant-abc' } }, undefined, {
			m365Proxy: proxy,
			m365ProxyAuthToken: INTERNAL_BEARER,
			keyHash: KEY_HASH,
			m365Identity: M365_IDENTITY,
		});

		expect(Object.hasOwn(result.structuredContent?.data as object, 'representative')).toBe(false);
	});
});

describe('M365 seam — producer failure classification reaches the caller', () => {
	// bv-web-prod's documented internal-gate answers: 503 when BV_MCP_M365_KEY
	// is unset upstream, 401 on a missing/wrong bearer, 404 if the route moves.
	for (const status of [401, 403, 404, 500, 503]) {
		it(`HTTP ${status} → the caller sees ok:false + m365_proxy_${status} (never a fabricated success)`, async () => {
			const { handleToolsCall } = await import('../../src/handlers/tools');
			const { proxy } = capturingProxy(() => new Response('upstream error', { status }));

			const result = await handleToolsCall({ name: 'query_signins', arguments: { ms_tenant_id: 'tenant-abc' } }, undefined, {
				m365Proxy: proxy,
				m365ProxyAuthToken: INTERNAL_BEARER,
				keyHash: KEY_HASH,
				m365Identity: M365_IDENTITY,
			});

			expect(result.structuredContent).toMatchObject({ ok: false, error: `m365_proxy_${status}` });
			expect(parseTextChannel(result)).toEqual({ ok: false, error: `m365_proxy_${status}` });
		});
	}

	it('a thrown/aborted binding call → m365_proxy_unreachable, and the tool still resolves', async () => {
		const { handleToolsCall } = await import('../../src/handlers/tools');
		const proxy = {
			fetch: (async () => {
				throw new DOMException('The operation was aborted', 'TimeoutError');
			}) as unknown as typeof fetch,
		};

		const result = await handleToolsCall({ name: 'assess_coverage', arguments: { ms_tenant_id: 'tenant-abc' } }, undefined, {
			m365Proxy: proxy,
			m365ProxyAuthToken: INTERNAL_BEARER,
			keyHash: KEY_HASH,
			m365Identity: M365_IDENTITY,
		});

		expect(result.structuredContent).toMatchObject({ ok: false, error: 'm365_proxy_unreachable' });
	});
});

describe('M365 seam — BSL self-host degradation (no BV_WEB binding)', () => {
	for (const [toolName, segment] of Object.entries(ACTIVE_TOOL_PATH_SEGMENTS)) {
		it(`${toolName}: no binding → ok:false + unprovisioned:true + tool:"${segment}", and never throws`, async () => {
			// A BSL self-host has no `BV_WEB`, so `m365Proxy` is undefined at all three
			// index.ts construction sites. The fail-soft wrapper must produce a plain
			// value the caller can read — not an exception, and NOT an `m365_proxy_*`
			// error, which would misreport a never-provisioned deployment as an
			// upstream outage.
			const { handleToolsCall } = await import('../../src/handlers/tools');

			const result = await handleToolsCall({ name: toolName, arguments: { ms_tenant_id: 'tenant-abc' } }, undefined, {
				m365ProxyAuthToken: INTERNAL_BEARER,
				keyHash: KEY_HASH,
				// m365Proxy intentionally absent.
			});

			expect(result.structuredContent).toEqual({ ok: false, unprovisioned: true, tool: segment });
			expect(result.structuredContent).not.toHaveProperty('error');
			expect(parseTextChannel(result)).toEqual({ ok: false, unprovisioned: true, tool: segment });
		});
	}
});
