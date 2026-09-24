// SPDX-License-Identifier: BUSL-1.1
//
// Chaos E: KV bindings that THROW (not return null/miss) on the /mcp request
// path — rate limiter, session store, scan cache, OAuth token storage.
//
// test/chaos/invariants.spec.ts P4/P5 already cover a KV that returns null/
// misses (rate-limiter advisory lock) and a session-KV PUT failure at the
// `createSession()` unit level. fuzzing-degradation.chaos.test.ts covers a
// fuzz-counter KV miss. None of those inject a KV binding whose get/put/delete
// REJECT — this file is scoped to exactly that failure mode, on every KV
// binding reachable from the /mcp request path (grep confirmed no existing
// chaos/invariant test constructs a rejecting KVNamespace mock for
// RATE_LIMIT, SESSION_STORE, SCAN_CACHE, or the OAuth token endpoint).
//
// Hypotheses (SQ-192), each with its negative control recorded as a ticket
// comment per testing-methodology principle 8:
//
//  H1 — RATE_LIMIT KV throws on every get/put during an authenticated
//       tools/call's per-tier daily-quota check. `checkToolDailyRateLimit` —
//       the exact function execute.ts calls for that check — is proven
//       fail-open at the unit level (falls back to the in-memory limiter,
//       logs exactly once), and a full /mcp request with RATE_LIMIT globally
//       broken is proven to still complete (200) end-to-end.
//  H2 — SESSION_STORE KV throws on every get/put/delete during `initialize`.
//       A session id/serverInfo must still come back, and a subsequent
//       tools/list with that session id must not 500.
//  H3 — SCAN_CACHE KV throws on every get/put around scan_domain.
//       MEASURED: FALSIFIED as literally stated — see the H3 describe block.
//  H4 — SESSION_STORE (the KV `handleToken` uses for OAuth code/token state)
//       throws during POST /oauth/token. Returns a 503 `temporarily_unavailable`
//       OAuth error body, never a 500 or a leaked internal message (SQ-199
//       wrapped consumeCode()'s unwrapped kv.get() as StrongStateUnavailableError
//       — see the H4 describe block).

import { env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import worker from '../../src/index';
import { setupFetchMock, createDohResponse, txtResponse, nsResponse, caaResponse, dnssecResponse, httpResponse } from '../helpers/dns-mock';

const TEST_API_KEY = 'test-api-key-sq192';
const TEST_SIGNING_SECRET = 'a'.repeat(32);

/** A KVNamespace whose get/put/delete/list all REJECT — the failure mode under test. */
function rejectingKv(message = 'KV unavailable (chaos SQ-192)'): KVNamespace {
	const fail = () => Promise.reject(new Error(message));
	return {
		get: fail,
		put: fail,
		delete: fail,
		list: fail,
		getWithMetadata: fail,
	} as unknown as KVNamespace;
}

/** A healthy in-memory-backed KVNamespace — used as the negative-control fixture. */
function healthyKv(): KVNamespace {
	const store = new Map<string, string>();
	return {
		get: async (key: string) => store.get(key) ?? null,
		put: async (key: string, value: string) => {
			store.set(key, value);
		},
		delete: async (key: string) => {
			store.delete(key);
		},
		list: async () => ({ keys: [], list_complete: true, cursor: undefined }),
	} as unknown as KVNamespace;
}

// ---------------------------------------------------------------------------
// H1 — RATE_LIMIT KV throws during an authenticated tools/call daily quota
// check.
//
// Hypothesis: given RATE_LIMIT rejects on every get/put, an authenticated
// tools/call is still served, and the KV outage is logged exactly once (not
// once per internal retry), never silently swallowed with no trace.
//
// Negative control: the same call against a HEALTHY KV must NOT emit the
// rate-limiter fallback log line — proves the log assertion actually
// discriminates a real outage from ordinary traffic.
// ---------------------------------------------------------------------------

describe('H1: RATE_LIMIT KV throws — authenticated tools/call daily-quota check', () => {
	afterEach(() => {
		vi.restoreAllMocks();
	});

	it('checkToolDailyRateLimit (the function execute.ts calls) fails OPEN and logs the outage exactly once', async () => {
		const { checkToolDailyRateLimit, resetAllRateLimits } = await import('../../src/lib/rate-limiter');
		resetAllRateLimits();
		const logSpy = vi.spyOn(console, 'log').mockImplementation(() => undefined);

		const result = await checkToolDailyRateLimit('principal-h1-chaos', 'check_spf', 500, rejectingKv(), undefined);

		// Fail-OPEN posture: a KV outage on this binding does not deny the call —
		// checkToolDailyRateLimitKV's own try/catch falls back to the (fresh,
		// empty) in-memory counter, which allows a first call for this principal.
		expect(result.allowed).toBe(true);
		expect(result.remaining).toBe(499);

		const fallbackLogs = logSpy.mock.calls.filter(
			([line]) => typeof line === 'string' && line.includes('[rate-limiter] KV tool quota error'),
		);
		expect(fallbackLogs).toHaveLength(1);
	});

	it('negative control: the same call against a healthy KV allows the request WITHOUT the fallback log', async () => {
		const { checkToolDailyRateLimit, resetAllRateLimits } = await import('../../src/lib/rate-limiter');
		resetAllRateLimits();
		const logSpy = vi.spyOn(console, 'log').mockImplementation(() => undefined);

		const result = await checkToolDailyRateLimit('principal-h1-control', 'check_spf', 500, healthyKv(), undefined);

		expect(result.allowed).toBe(true);
		const fallbackLogs = logSpy.mock.calls.filter(
			([line]) => typeof line === 'string' && line.includes('[rate-limiter] KV tool quota error'),
		);
		expect(fallbackLogs).toHaveLength(0);
	});

	it('end-to-end: an authenticated tools/call over /mcp still completes (200) with RATE_LIMIT globally broken', async () => {
		const { resetAllRateLimits } = await import('../../src/lib/rate-limiter');
		const { resetSessions } = await import('../../src/lib/session');
		resetAllRateLimits();
		resetSessions();

		const { restore } = setupFetchMock();
		globalThis.fetch = vi.fn().mockImplementation(async () => createDohResponse([{ name: 'example.com', type: 16 }], []));

		// Owner tier (BV_API_KEY) has an Infinity daily limit and so never reaches
		// checkToolDailyRateLimit's KV branch at all (see the unit test above for
		// that exact branch) — this end-to-end call instead proves the weaker but
		// still real claim: nothing else on the authenticated /mcp request path
		// (session-create control-plane limiter, tier resolution, etc.) crashes
		// when RATE_LIMIT is globally unavailable.
		const authEnv = { ...env, BV_API_KEY: TEST_API_KEY, RATE_LIMIT: rejectingKv() } as unknown as Parameters<typeof worker.fetch>[1];

		const ctx1 = createExecutionContext();
		const initRes = await worker.fetch(
			new Request('http://example.com/mcp', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${TEST_API_KEY}` },
				body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }),
			}),
			authEnv,
			ctx1,
		);
		await waitOnExecutionContext(ctx1);
		expect(initRes.status).toBe(200);
		const sessionId = initRes.headers.get('mcp-session-id');
		expect(sessionId).toBeTruthy();

		const ctx2 = createExecutionContext();
		const callRes = await worker.fetch(
			new Request('http://example.com/mcp', {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					Authorization: `Bearer ${TEST_API_KEY}`,
					'Mcp-Session-Id': sessionId ?? '',
				},
				body: JSON.stringify({
					jsonrpc: '2.0',
					id: 2,
					method: 'tools/call',
					params: { name: 'check_spf', arguments: { domain: 'example.com' } },
				}),
			}),
			authEnv,
			ctx2,
		);
		await waitOnExecutionContext(ctx2);
		restore();

		expect(callRes.status).toBe(200);
		const body = (await callRes.json()) as { result?: unknown; error?: unknown };
		expect(body.error).toBeUndefined();
		expect(body.result).toBeDefined();
	});
});

// ---------------------------------------------------------------------------
// H2 — SESSION_STORE KV throws during initialize / session validation.
//
// Hypothesis: session creation is in-memory-first (dual-write), so a session
// id and serverInfo still come back from `initialize` even when SESSION_STORE
// rejects on every op, and a subsequent same-isolate call with that session
// id is served (not 500) from the in-memory store.
//
// Negative control: the identical two-request sequence against a healthy
// SESSION_STORE must NOT emit a `kv_fallback`/`session` degradation event —
// proves the degradation-event assertion actually discriminates the outage.
// ---------------------------------------------------------------------------

describe('H2: SESSION_STORE KV throws — initialize and session validation', () => {
	beforeEach(async () => {
		const { resetSessions } = await import('../../src/lib/session');
		resetSessions();
	});

	function initializeRequest(): Request {
		return new Request('http://example.com/mcp', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
			body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }),
		});
	}

	function toolsListRequest(sessionId: string): Request {
		return new Request('http://example.com/mcp', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json', Accept: 'application/json', 'Mcp-Session-Id': sessionId },
			body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} }),
		});
	}

	it('initialize returns a session id/serverInfo, and a subsequent tools/list with that session does not 500', async () => {
		type TestEnv = typeof env & { MCP_ANALYTICS?: unknown };
		const writeAttempts: unknown[][] = [];
		const sessionEnv = {
			...env,
			SESSION_STORE: rejectingKv(),
			MCP_ANALYTICS: {
				writeDataPoint(point: unknown) {
					writeAttempts.push([point]);
				},
			},
		} as unknown as TestEnv;

		const ctx1 = createExecutionContext();
		const initRes = await worker.fetch(initializeRequest(), sessionEnv as unknown as Parameters<typeof worker.fetch>[1], ctx1);
		await waitOnExecutionContext(ctx1);

		expect(initRes.status).toBe(200);
		const sessionId = initRes.headers.get('mcp-session-id');
		expect(sessionId).toMatch(/^[a-f0-9]{64}$/);
		const initBody = (await initRes.json()) as { result?: { serverInfo?: unknown } };
		expect(initBody.result?.serverInfo).toBeDefined();

		const ctx2 = createExecutionContext();
		const listRes = await worker.fetch(
			toolsListRequest(sessionId as string),
			sessionEnv as unknown as Parameters<typeof worker.fetch>[1],
			ctx2,
		);
		await waitOnExecutionContext(ctx2);

		expect(listRes.status).toBe(200);
		const listBody = (await listRes.json()) as { result?: unknown; error?: unknown };
		expect(listBody.error).toBeUndefined();
		expect(listBody.result).toBeDefined();

		// The KV outage is surfaced, not silently swallowed: session.ts's
		// createSession() emits a `kv_fallback`/`session` degradation event when
		// its KV put rejects (src/lib/session.ts createSession()).
		const degradationCalls = writeAttempts.filter(([point]) => {
			const p = point as { indexes?: string[]; blobs?: string[] };
			return p.indexes?.[0] === 'degradation' && p.blobs?.[0] === 'kv_fallback' && p.blobs?.[1] === 'session';
		});
		expect(degradationCalls.length).toBeGreaterThanOrEqual(1);
	});

	it('negative control: the same two-request sequence against a healthy SESSION_STORE emits no kv_fallback/session event', async () => {
		type TestEnv = typeof env & { MCP_ANALYTICS?: unknown };
		const writeAttempts: unknown[][] = [];
		const controlEnv = {
			...env,
			SESSION_STORE: healthyKv(),
			MCP_ANALYTICS: {
				writeDataPoint(point: unknown) {
					writeAttempts.push([point]);
				},
			},
		} as unknown as TestEnv;

		const ctx1 = createExecutionContext();
		const initRes = await worker.fetch(initializeRequest(), controlEnv as unknown as Parameters<typeof worker.fetch>[1], ctx1);
		await waitOnExecutionContext(ctx1);
		expect(initRes.status).toBe(200);
		const sessionId = initRes.headers.get('mcp-session-id') as string;

		const ctx2 = createExecutionContext();
		const listRes = await worker.fetch(
			toolsListRequest(sessionId),
			controlEnv as unknown as Parameters<typeof worker.fetch>[1],
			ctx2,
		);
		await waitOnExecutionContext(ctx2);
		expect(listRes.status).toBe(200);

		const degradationCalls = writeAttempts.filter(([point]) => {
			const p = point as { indexes?: string[]; blobs?: string[] };
			return p.indexes?.[0] === 'degradation' && p.blobs?.[0] === 'kv_fallback' && p.blobs?.[1] === 'session';
		});
		expect(degradationCalls).toHaveLength(0);
	});
});

// ---------------------------------------------------------------------------
// H3 — SCAN_CACHE KV throws on both get and put around scan_domain.
//
// Ticket hypothesis: a second identical call re-runs the checks (the DNS
// mock is hit again) rather than throwing.
//
// MEASURED — FALSIFIED as literally stated. Read src/lib/cache.ts: cacheSet's
// catch block on a KV put failure falls through UNCONDITIONALLY to
// `IN_MEMORY_CACHE.set(...)` — the SAME per-isolate cache used when no KV
// binding is configured at all. cacheGet's catch does the mirror read. So a
// persistent SCAN_CACHE outage on get+put does not disable caching; it
// silently degrades scan_domain's cache to the in-process TTLCache. A second
// identical call within the same isolate is served from THAT cache
// (`cached: true`) without re-running any check — not re-executed, and not a
// throw either. Negative control below shows the discriminating signal
// (`cached` flip + DoH call count) tracks a REAL cache write, not a test
// artifact: with `force_refresh: true` on the second call, the DNS mock IS
// hit again even with SCAN_CACHE throwing, proving the fallback truly is a
// cache (bypassable), not a stuck/duplicated result.
// ---------------------------------------------------------------------------

function resolveDoh(url: string): Response {
	if (url.includes('type=TXT') || url.includes('type=16')) {
		if (url.includes('_dmarc.')) return txtResponse('_dmarc.example.com', ['v=DMARC1; p=reject']);
		if (url.includes('_domainkey.')) return txtResponse('default._domainkey.example.com', ['v=DKIM1; k=rsa; p=MIGf']);
		if (url.includes('_mta-sts.')) return txtResponse('_mta-sts.example.com', ['v=STSv1; id=20240101']);
		if (url.includes('_smtp._tls.')) return txtResponse('_smtp._tls.example.com', ['v=TLSRPTv1; rua=mailto:tls@example.com']);
		if (url.includes('default._bimi.')) return txtResponse('default._bimi.example.com', ['v=BIMI1; l=https://example.com/logo.svg']);
		return txtResponse('example.com', ['v=spf1 include:_spf.google.com -all']);
	}
	if (url.includes('type=NS') || url.includes('type=2')) return nsResponse('example.com', ['ns1.example.com.', 'ns2.example.com.']);
	if (url.includes('type=CAA') || url.includes('type=257')) return caaResponse('example.com', ['0 issue "letsencrypt.org"']);
	if (url.includes('type=A') || url.includes('type=1')) return dnssecResponse('example.com', true);
	return createDohResponse([], []);
}

function installScanDnsMock(): { restore: () => void; dohCalls: () => number } {
	const { restore } = setupFetchMock();
	let count = 0;
	globalThis.fetch = vi.fn().mockImplementation(async (input: string | URL | Request) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.href : (input as Request).url;
		const isDoh = url.includes('cloudflare-dns.com') || url.includes('dns.google');
		if (isDoh) {
			count += 1;
			return resolveDoh(url);
		}
		return httpResponse('OK');
	}) as unknown as typeof fetch;
	return { restore, dohCalls: () => count };
}

describe('H3: SCAN_CACHE KV throws — scan_domain', () => {
	it('FALSIFIED vs ticket H3: first call completes a full scored result; a second identical call is served from the in-memory cache fallback, NOT re-executed', async () => {
		const { scanDomain } = await import('../../src/tools/scan-domain');
		const { IN_MEMORY_CACHE } = await import('../../src/lib/cache');
		IN_MEMORY_CACHE.clear();

		const { restore, dohCalls } = installScanDnsMock();
		const kv = rejectingKv();

		const first = await scanDomain('example.com', kv, {});
		expect(first.domain).toBe('example.com');
		expect(Array.isArray(first.checks)).toBe(true);
		expect(first.checks.length).toBeGreaterThan(0);
		expect(first.cached).toBe(false);
		const callsAfterFirst = dohCalls();
		expect(callsAfterFirst).toBeGreaterThan(0);

		const second = await scanDomain('example.com', kv, {});
		// MEASURED: no re-execution — cacheGet's fallback read hits the same
		// IN_MEMORY_CACHE entry cacheSet's fallback write populated after call 1.
		expect(dohCalls()).toBe(callsAfterFirst);
		expect(second.cached).toBe(true);
		expect(second.domain).toBe(first.domain);
		expect(second.score).toEqual(first.score);

		restore();
		IN_MEMORY_CACHE.clear();
	});

	it('negative control: force_refresh bypasses the cache fallback and the DNS mock IS hit again despite SCAN_CACHE throwing', async () => {
		const { scanDomain } = await import('../../src/tools/scan-domain');
		const { IN_MEMORY_CACHE } = await import('../../src/lib/cache');
		IN_MEMORY_CACHE.clear();

		const { restore, dohCalls } = installScanDnsMock();
		const kv = rejectingKv();

		const first = await scanDomain('example.com', kv, {});
		const callsAfterFirst = dohCalls();
		expect(callsAfterFirst).toBeGreaterThan(0);

		const second = await scanDomain('example.com', kv, { forceRefresh: true });
		expect(dohCalls()).toBeGreaterThan(callsAfterFirst);
		expect(second.cached).toBe(false);
		expect(second.domain).toBe(first.domain);

		restore();
		IN_MEMORY_CACHE.clear();
	});
});

// ---------------------------------------------------------------------------
// H4 — SESSION_STORE (the KV handleToken() uses for OAuth code/token state)
// throws during POST /oauth/token.
//
// Ticket hypothesis: the route returns a 503 OAuth error body with an
// allowlisted message, never a stack trace or a 500 with internals.
//
// SQ-199 fix: src/oauth/storage.ts `consumeCode()` previously called
// `await kv.get(codeKey(code))` UNWRAPPED (no try/catch) before it ever
// reached the `StrongStateUnavailableError` path, so `handleToken()`'s catch
// (`error instanceof StrongStateUnavailableError`) never matched and the
// request path ended in an UNHANDLED rejection reaching Hono's own default
// handler (500, no app.onError registered). `consumeCode()`'s initial read
// now goes through a `safeKvGet` wrapper that maps a rejecting binding to
// `StrongStateUnavailableError`, so `handleToken`'s existing catch now
// converts it to the 503 `temporarily_unavailable` OAuth error body.
//
// Negative control: the identical request against a healthy SESSION_STORE
// completes as an ordinary `invalid_grant` 400 (unknown code) — proves the
// KV-throw path is what changes the outcome, not the request shape.
// ---------------------------------------------------------------------------

describe('H4: SESSION_STORE (OAuth storage) KV throws — POST /oauth/token', () => {
	function tokenRequestBody(): URLSearchParams {
		return new URLSearchParams({
			grant_type: 'authorization_code',
			code: 'sq192-chaos-test-code',
			redirect_uri: 'https://claude.ai/cb',
			client_id: 'sq192-chaos-test-client',
			code_verifier: 'x'.repeat(43),
		});
	}

	it('returns 503 temporarily_unavailable and never leaks the raw KV error message or a stack trace', async () => {
		type TestEnv = typeof env & { OAUTH_SIGNING_SECRET?: string };
		const tokenEnv = {
			...env,
			OAUTH_SIGNING_SECRET: TEST_SIGNING_SECRET,
			SESSION_STORE: rejectingKv('KV unavailable (chaos SQ-192 — must never reach the client)'),
		} as unknown as TestEnv;

		const ctx = createExecutionContext();
		const res = await worker.fetch(
			new Request('http://example.com/oauth/token', {
				method: 'POST',
				headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
				body: tokenRequestBody().toString(),
			}),
			tokenEnv as unknown as Parameters<typeof worker.fetch>[1],
			ctx,
		);
		await waitOnExecutionContext(ctx);

		const text = await res.text();

		// Load-bearing safety assertion regardless of which status the KV throw
		// ultimately produces: no raw error text, no stack frame, ever reaches
		// the client body.
		expect(text).not.toContain('chaos SQ-192');
		expect(text).not.toContain('KV unavailable');
		expect(text.toLowerCase()).not.toContain('.ts:');
		expect(text.toLowerCase()).not.toContain('at consumecode');

		// The ticket contract: consumeCode()'s kv.get() rejection is now wrapped
		// as StrongStateUnavailableError, so handleToken()'s existing catch
		// converts it to the OAuth 503 temporarily_unavailable shape — never the
		// unwrapped 500 this test used to measure.
		expect(res.status).toBe(503);
		const body = JSON.parse(text) as { error?: string; error_description?: string };
		expect(body.error).toBe('temporarily_unavailable');
		expect(typeof body.error_description).toBe('string');
	});

	it('negative control: the identical request against a healthy SESSION_STORE resolves as an ordinary invalid_grant 400', async () => {
		type TestEnv = typeof env & { OAUTH_SIGNING_SECRET?: string };
		const controlEnv = {
			...env,
			OAUTH_SIGNING_SECRET: TEST_SIGNING_SECRET,
			SESSION_STORE: healthyKv(),
		} as unknown as TestEnv;

		const ctx = createExecutionContext();
		const res = await worker.fetch(
			new Request('http://example.com/oauth/token', {
				method: 'POST',
				headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
				body: tokenRequestBody().toString(),
			}),
			controlEnv as unknown as Parameters<typeof worker.fetch>[1],
			ctx,
		);
		await waitOnExecutionContext(ctx);

		expect(res.status).toBe(400);
		const body = (await res.json()) as { error?: string };
		expect(body.error).toBe('invalid_grant');
	});
});
