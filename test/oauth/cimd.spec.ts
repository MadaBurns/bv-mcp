import { env } from 'cloudflare:test';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { clearKvPrefix } from '../helpers/kv';

// Shapes copied from the live documents served at these URLs (fetched 2026-10-29).
const WEB_ID = 'https://claude.ai/oauth/mcp-oauth-client-metadata';
const CODE_ID = 'https://claude.ai/oauth/claude-code-client-metadata';
const CACHE_PREFIX = 'oauth:client:cimd:';

function webDoc(overrides: Record<string, unknown> = {}): Record<string, unknown> {
	return {
		client_id: WEB_ID,
		client_name: 'Claude',
		client_uri: 'https://claude.ai',
		redirect_uris: ['https://claude.ai/api/mcp/auth_callback'],
		grant_types: ['authorization_code', 'refresh_token', 'urn:ietf:params:oauth:grant-type:jwt-bearer'],
		response_types: ['code'],
		token_endpoint_auth_method: 'none',
		...overrides,
	};
}

function jsonResponse(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
}

function urlOf(input: RequestInfo | URL): string {
	if (typeof input === 'string') return input;
	return input instanceof URL ? input.href : input.url;
}

function stubFetch(handler: (url: string, init?: RequestInit) => Response | Promise<Response>) {
	const mock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => handler(urlOf(input), init));
	vi.stubGlobal('fetch', mock);
	return mock;
}

function kv(): KVNamespace {
	return env.SESSION_STORE as unknown as KVNamespace;
}

async function cachedKeys() {
	return (await env.SESSION_STORE.list({ prefix: CACHE_PREFIX })).keys;
}

beforeEach(async () => {
	await clearKvPrefix(env.SESSION_STORE, 'oauth:');
});
afterEach(async () => {
	vi.unstubAllGlobals();
	await clearKvPrefix(env.SESSION_STORE, 'oauth:');
});

describe('isCimdClientId', () => {
	it.each([WEB_ID, CODE_ID, 'https://app.vendor.example.org/oauth/client.json', 'https://app.vendor.example.org:8443/meta'])(
		'accepts %s',
		async (id) => {
			const { isCimdClientId } = await import('../../src/oauth/cimd');
			expect(isCimdClientId(id)).toBe(true);
		},
	);

	it.each([
		['plain http', 'http://claude.ai/oauth/mcp-oauth-client-metadata'],
		['non-https scheme', 'ftp://claude.ai/oauth/client'],
		['bare origin', 'https://claude.ai'],
		['root path', 'https://claude.ai/'],
		['username', 'https://user@claude.ai/oauth/client'],
		['username + password', 'https://user:pass@claude.ai/oauth/client'],
		['query string', 'https://claude.ai/oauth/client?x=1'],
		['fragment', 'https://claude.ai/oauth/client#frag'],
		['over 512 chars', `https://claude.ai/${'a'.repeat(600)}`],
		['not a URL', 'not a url'],
		['empty', ''],
		['DCR-style opaque id', '3f2a9c1e-5d7b-4e8a-9b1c-0d2e4f6a8b0c'],
	])('rejects %s', async (_label, id) => {
		const { isCimdClientId } = await import('../../src/oauth/cimd');
		expect(isCimdClientId(id)).toBe(false);
	});

	it('exports the two Claude client ids', async () => {
		const { CLAUDE_WEB_CIMD_CLIENT_ID, CLAUDE_CODE_CIMD_CLIENT_ID } = await import('../../src/oauth/cimd');
		expect(CLAUDE_WEB_CIMD_CLIENT_ID).toBe(WEB_ID);
		expect(CLAUDE_CODE_CIMD_CLIENT_ID).toBe(CODE_ID);
	});
});

describe('resolveClient', () => {
	it('fetches, validates and caches a valid metadata document; the second call makes no fetch', async () => {
		const { resolveClient } = await import('../../src/oauth/cimd');
		const fetchMock = stubFetch(() => jsonResponse(webDoc()));
		const before = Math.floor(Date.now() / 1000);

		const first = await resolveClient(kv(), WEB_ID);
		expect(first).toMatchObject({
			client_id: WEB_ID,
			client_name: 'Claude',
			redirect_uris: ['https://claude.ai/api/mcp/auth_callback'],
		});
		expect(first?.client_id_issued_at).toBeGreaterThanOrEqual(before);
		expect(fetchMock).toHaveBeenCalledTimes(1);
		const [calledUrl, init] = fetchMock.mock.calls[0];
		expect(urlOf(calledUrl)).toBe(WEB_ID);
		expect(init?.method).toBe('GET');
		expect(init?.redirect).toBe('manual');
		expect(new Headers(init?.headers).get('accept')).toBe('application/json');
		expect(init?.signal).toBeInstanceOf(AbortSignal);

		const keys = await cachedKeys();
		expect(keys).toHaveLength(1);
		expect(keys[0].name).toMatch(/^oauth:client:cimd:[0-9a-f]{64}$/);
		expect(keys[0].expiration).toBeGreaterThanOrEqual(before + 3600 - 5);
		expect(keys[0].expiration).toBeLessThanOrEqual(before + 3600 + 5);

		const second = await resolveClient(kv(), WEB_ID);
		expect(second).toEqual(first);
		expect(fetchMock).toHaveBeenCalledTimes(1);
	});

	it('resolves the Claude Code document with its port-less loopback redirects', async () => {
		const { resolveClient } = await import('../../src/oauth/cimd');
		stubFetch(() =>
			jsonResponse(
				webDoc({
					client_id: CODE_ID,
					client_name: 'Claude Code',
					redirect_uris: ['http://localhost/callback', 'http://127.0.0.1/callback'],
				}),
			),
		);
		const rec = await resolveClient(kv(), CODE_ID);
		expect(rec?.redirect_uris).toEqual(['http://localhost/callback', 'http://127.0.0.1/callback']);
	});

	it('seals the cached record when an envelope key is supplied', async () => {
		const { resolveClient } = await import('../../src/oauth/cimd');
		const { isSealed } = await import('../../src/lib/kv-envelope');
		const key = new Uint8Array(32).fill(7);
		const fetchMock = stubFetch(() => jsonResponse(webDoc()));

		const first = await resolveClient(kv(), WEB_ID, key);
		expect(first?.client_id).toBe(WEB_ID);
		const keys = await cachedKeys();
		expect(keys).toHaveLength(1);
		const raw = await env.SESSION_STORE.get(keys[0].name);
		expect(raw && isSealed(raw)).toBe(true);
		expect(raw).not.toContain('auth_callback');

		const second = await resolveClient(kv(), WEB_ID, key);
		expect(second).toEqual(first);
		expect(fetchMock).toHaveBeenCalledTimes(1);
	});

	it('prefers a dynamically registered client and never fetches for it', async () => {
		const { resolveClient } = await import('../../src/oauth/cimd');
		const { putClient } = await import('../../src/oauth/storage');
		const fetchMock = stubFetch(() => jsonResponse(webDoc()));
		await putClient(kv(), { client_id: 'dcr-client-1', client_id_issued_at: 1, redirect_uris: ['https://claude.ai/cb'] });

		const rec = await resolveClient(kv(), 'dcr-client-1');
		expect(rec?.client_id).toBe('dcr-client-1');
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it('returns null without fetching for an unknown non-CIMD client id', async () => {
		const { resolveClient } = await import('../../src/oauth/cimd');
		const fetchMock = stubFetch(() => jsonResponse(webDoc()));
		expect(await resolveClient(kv(), 'missing')).toBeNull();
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it.each([
		['client_id mismatch', () => jsonResponse(webDoc({ client_id: 'https://claude.ai/oauth/other-client' }))],
		['client_id differing only by a trailing slash', () => jsonResponse(webDoc({ client_id: `${WEB_ID}/` }))],
		['a 302 redirect', () => new Response(null, { status: 302, headers: { location: 'https://claude.ai/elsewhere' } })],
		['a 404', () => jsonResponse({ error: 'not_found' }, 404)],
		['a 500', () => new Response('boom', { status: 500 })],
		['a body over 5KB', () => jsonResponse(webDoc({ padding: 'x'.repeat(6000) }))],
		['malformed JSON', () => new Response('{"client_id":', { status: 200 })],
		['a JSON array', () => jsonResponse([webDoc()])],
		['a non-Anthropic redirect_uri', () => jsonResponse(webDoc({ redirect_uris: ['https://attacker.example.net/cb'] }))],
		[
			'one bad redirect_uri among good ones',
			() => jsonResponse(webDoc({ redirect_uris: ['https://claude.ai/api/mcp/auth_callback', 'https://attacker.example.net/cb'] })),
		],
		['empty redirect_uris', () => jsonResponse(webDoc({ redirect_uris: [] }))],
		['missing redirect_uris', () => jsonResponse(webDoc({ redirect_uris: undefined }))],
		['missing client_name', () => jsonResponse(webDoc({ client_name: undefined }))],
		['empty client_name', () => jsonResponse(webDoc({ client_name: '' }))],
		['client_name over 200 chars', () => jsonResponse(webDoc({ client_name: 'C'.repeat(201) }))],
		['a client_secret', () => jsonResponse(webDoc({ client_secret: 'shh' }))],
		['a client_secret_expires_at', () => jsonResponse(webDoc({ client_secret_expires_at: 0 }))],
		['a jwks', () => jsonResponse(webDoc({ jwks: { keys: [] } }))],
		['token_endpoint_auth_method client_secret_basic', () => jsonResponse(webDoc({ token_endpoint_auth_method: 'client_secret_basic' }))],
		['token_endpoint_auth_method private_key_jwt', () => jsonResponse(webDoc({ token_endpoint_auth_method: 'private_key_jwt' }))],
	])('returns null and caches nothing for %s', async (_label, respond) => {
		const { resolveClient } = await import('../../src/oauth/cimd');
		const fetchMock = stubFetch(respond);
		expect(await resolveClient(kv(), WEB_ID)).toBeNull();
		expect(fetchMock).toHaveBeenCalledTimes(1);
		expect(await cachedKeys()).toHaveLength(0);
	});

	it('accepts a document that omits token_endpoint_auth_method', async () => {
		const { resolveClient } = await import('../../src/oauth/cimd');
		stubFetch(() => jsonResponse(webDoc({ token_endpoint_auth_method: undefined })));
		expect((await resolveClient(kv(), WEB_ID))?.client_id).toBe(WEB_ID);
	});

	it('returns null when the fetch rejects (network error or timeout)', async () => {
		const { resolveClient } = await import('../../src/oauth/cimd');
		stubFetch(() => Promise.reject(new DOMException('The operation was aborted due to timeout', 'TimeoutError')));
		expect(await resolveClient(kv(), WEB_ID)).toBeNull();
		expect(await cachedKeys()).toHaveLength(0);
	});

	it('returns null without fetching when safeFetch blocks the host', async () => {
		const { resolveClient } = await import('../../src/oauth/cimd');
		const fetchMock = stubFetch(() => jsonResponse(webDoc({ client_id: 'https://metadata.internal/client' })));
		expect(await resolveClient(kv(), 'https://metadata.internal/client')).toBeNull();
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it('ignores a cache entry whose client_id does not match the requested URL and refetches', async () => {
		const { resolveClient } = await import('../../src/oauth/cimd');
		const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(WEB_ID)));
		const hex = Array.from(digest, (b) => b.toString(16).padStart(2, '0')).join('');
		await env.SESSION_STORE.put(
			`${CACHE_PREFIX}${hex}`,
			JSON.stringify({ client_id: 'https://attacker.example.net/meta', client_id_issued_at: 1, redirect_uris: ['https://claude.ai/evil'] }),
		);
		const fetchMock = stubFetch(() => jsonResponse(webDoc()));

		const rec = await resolveClient(kv(), WEB_ID);
		expect(rec?.client_id).toBe(WEB_ID);
		expect(rec?.redirect_uris).toEqual(['https://claude.ai/api/mcp/auth_callback']);
		expect(fetchMock).toHaveBeenCalledTimes(1);
	});

	it('still resolves the client when the cache write fails', async () => {
		const { resolveClient } = await import('../../src/oauth/cimd');
		stubFetch(() => jsonResponse(webDoc()));
		const failingPut = {
			get: async () => null,
			put: async () => {
				throw new Error('KV write unavailable');
			},
		} as unknown as KVNamespace;
		expect((await resolveClient(failingPut, WEB_ID))?.client_id).toBe(WEB_ID);
	});

	it('does not cache failures: a failed fetch is retried on the next call', async () => {
		const { resolveClient } = await import('../../src/oauth/cimd');
		let calls = 0;
		const fetchMock = stubFetch(() => {
			calls += 1;
			return calls === 1 ? new Response('unavailable', { status: 503 }) : jsonResponse(webDoc());
		});
		expect(await resolveClient(kv(), WEB_ID)).toBeNull();
		expect(await cachedKeys()).toHaveLength(0);
		expect((await resolveClient(kv(), WEB_ID))?.client_id).toBe(WEB_ID);
		expect(fetchMock).toHaveBeenCalledTimes(2);
	});
});

describe('redirectUriMatches', () => {
	const claudeCode = ['http://localhost/callback', 'http://127.0.0.1/callback'] as const;

	it('matches an exact registered URI', async () => {
		const { redirectUriMatches } = await import('../../src/oauth/cimd');
		expect(redirectUriMatches('https://claude.ai/api/mcp/auth_callback', ['https://claude.ai/api/mcp/auth_callback'])).toBe(true);
	});

	it('ignores the port for a localhost loopback redirect (RFC 8252 subsection 7.3)', async () => {
		const { redirectUriMatches } = await import('../../src/oauth/cimd');
		expect(redirectUriMatches('http://localhost:53682/callback', claudeCode)).toBe(true);
	});

	it('ignores the port for a 127.0.0.1 loopback redirect', async () => {
		const { redirectUriMatches } = await import('../../src/oauth/cimd');
		expect(redirectUriMatches('http://127.0.0.1:41234/callback', claudeCode)).toBe(true);
	});

	it('ignores the port in either direction for loopback hosts', async () => {
		const { redirectUriMatches } = await import('../../src/oauth/cimd');
		expect(redirectUriMatches('http://localhost/callback', ['http://localhost:8080/callback'])).toBe(true);
	});

	it('does NOT ignore the port for a non-loopback host', async () => {
		const { redirectUriMatches } = await import('../../src/oauth/cimd');
		expect(redirectUriMatches('https://claude.ai:8443/api/mcp/auth_callback', ['https://claude.ai/api/mcp/auth_callback'])).toBe(false);
		expect(redirectUriMatches('http://app.example.org:8080/callback', ['http://app.example.org/callback'])).toBe(false);
	});

	it.each([
		['path mismatch on loopback', 'http://localhost:53682/other'],
		['path mismatch on 127.0.0.1', 'http://127.0.0.1:53682/callback/extra'],
		['query mismatch on loopback', 'http://localhost:53682/callback?x=1'],
		['scheme mismatch on loopback', 'https://localhost:53682/callback'],
		['userinfo on loopback', 'http://user@localhost:53682/callback'],
		['fragment on loopback', 'http://localhost:53682/callback#frag'],
		['loopback lookalike host', 'http://localhost.attacker.example.net:53682/callback'],
		['unparseable', 'not a url'],
	])('rejects %s', async (_label, requested) => {
		const { redirectUriMatches } = await import('../../src/oauth/cimd');
		expect(redirectUriMatches(requested, claudeCode)).toBe(false);
	});

	it('does not cross-match localhost and 127.0.0.1', async () => {
		const { redirectUriMatches } = await import('../../src/oauth/cimd');
		expect(redirectUriMatches('http://localhost:5555/callback', ['http://127.0.0.1/callback'])).toBe(false);
		expect(redirectUriMatches('http://127.0.0.1:5555/callback', ['http://localhost/callback'])).toBe(false);
	});

	it('rejects a non-loopback path mismatch and an empty registration list', async () => {
		const { redirectUriMatches } = await import('../../src/oauth/cimd');
		expect(redirectUriMatches('https://claude.ai/api/mcp/other', ['https://claude.ai/api/mcp/auth_callback'])).toBe(false);
		expect(redirectUriMatches('http://localhost:5555/callback', [])).toBe(false);
		expect(redirectUriMatches('http://localhost:5555/callback', ['not a url'])).toBe(false);
	});
});
