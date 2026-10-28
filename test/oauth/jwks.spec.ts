import { env } from 'cloudflare:test';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { clearKvPrefix } from '../helpers/kv';

const TYP = 'oauth-id-jag+jwt';
const NOW = 1_700_000_000;
const JWKS_URI = 'https://acme.okta.com/oauth2/v1/keys';
// An already-expired, wrong-audience claim set: verifyJwsWithJwks must return it untouched.
const CLAIMS = { iss: 'https://acme.okta.com', sub: 'user-1', aud: 'https://elsewhere', exp: 1, iat: 0, jti: 'j1' };

type Alg = 'RS256' | 'ES256';
interface Signer {
	alg: Alg;
	kid: string;
	privateKey: CryptoKey;
	publicJwk: JsonWebKey & { kid: string };
	privateJwk: JsonWebKey & { kid: string };
}

const kv = () => env.SESSION_STORE as unknown as KVNamespace;
const encoder = new TextEncoder();

function b64url(bytes: ArrayBuffer | Uint8Array): string {
	let binary = '';
	for (const byte of new Uint8Array(bytes)) binary += String.fromCharCode(byte);
	return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

const b64urlJson = (value: unknown) => b64url(encoder.encode(JSON.stringify(value)));

async function makeSigner(alg: Alg, kid: string, modulusLength = 2048): Promise<Signer> {
	const params =
		alg === 'RS256'
			? { name: 'RSASSA-PKCS1-v1_5', modulusLength, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }
			: { name: 'ECDSA', namedCurve: 'P-256' };
	const pair = (await crypto.subtle.generateKey(params, true, ['sign', 'verify'])) as CryptoKeyPair;
	const pub = (await crypto.subtle.exportKey('jwk', pair.publicKey)) as JsonWebKey;
	const priv = (await crypto.subtle.exportKey('jwk', pair.privateKey)) as JsonWebKey;
	const material = alg === 'RS256' ? { kty: 'RSA', n: pub.n, e: pub.e } : { kty: 'EC', crv: 'P-256', x: pub.x, y: pub.y };
	return {
		alg,
		kid,
		privateKey: pair.privateKey,
		publicJwk: { ...material, kid, use: 'sig', alg },
		privateJwk: { ...priv, kid, use: 'sig', alg },
	};
}

async function signJws(signer: Signer, claims: Record<string, unknown> = CLAIMS, header: Record<string, unknown> = {}): Promise<string> {
	const signingInput = `${b64urlJson({ alg: signer.alg, typ: TYP, kid: signer.kid, ...header })}.${b64urlJson(claims)}`;
	const params = signer.alg === 'RS256' ? { name: 'RSASSA-PKCS1-v1_5' } : { name: 'ECDSA', hash: 'SHA-256' };
	const signature = await crypto.subtle.sign(params, signer.privateKey, encoder.encode(signingInput));
	return `${signingInput}.${b64url(signature)}`;
}

function jsonResponse(body: unknown, init: ResponseInit = {}): Response {
	return new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' }, ...init });
}

let rsa: Signer;
let rsaRotated: Signer;
let ec: Signer;
let rsaWeak: Signer;

beforeAll(async () => {
	[rsa, rsaRotated, ec, rsaWeak] = await Promise.all([
		makeSigner('RS256', 'rsa-1'),
		makeSigner('RS256', 'rsa-2'),
		makeSigner('ES256', 'ec-1'),
		makeSigner('RS256', 'rsa-weak', 1024),
	]);
});

afterEach(async () => {
	vi.unstubAllGlobals();
	await clearKvPrefix(env.SESSION_STORE, 'oauth:');
});

async function verify(token: string, keys: unknown[], allowedAlgs: readonly Alg[] = ['RS256', 'ES256']) {
	const { verifyJwsWithJwks } = await import('../../src/oauth/jwks');
	return verifyJwsWithJwks(token, { jwks: { keys: keys as JsonWebKey[] }, allowedAlgs, expectedTyp: TYP });
}

async function expectCode(promise: Promise<unknown>, code: string): Promise<void> {
	// Settle first: attaching the handler after an await would leave an early rejection unhandled.
	const settled = promise.then(
		() => null,
		(caught: unknown) => caught,
	);
	const { AssertionVerifyError } = await import('../../src/oauth/jwks');
	const error = await settled;
	expect(error).toBeInstanceOf(AssertionVerifyError);
	expect((error as { code: string }).code).toBe(code);
}

describe('oauth/jwks — verifyJwsWithJwks', () => {
	it('RS256: returns the header and the claims unvalidated', async () => {
		const result = await verify(await signJws(rsa), [rsaRotated.publicJwk, rsa.publicJwk, ec.publicJwk]);
		expect(result.header).toEqual({ alg: 'RS256', typ: TYP, kid: 'rsa-1' });
		expect(result.claims).toEqual(CLAIMS);
	});

	it('ES256: verifies a raw r||s signature', async () => {
		const result = await verify(await signJws(ec), [rsa.publicJwk, ec.publicJwk]);
		expect(result.header.alg).toBe('ES256');
		expect(result.claims.sub).toBe('user-1');
	});

	it('kid-less header: uses the single compatible key', async () => {
		const result = await verify(await signJws(rsa, CLAIMS, { kid: undefined }), [rsa.publicJwk, ec.publicJwk]);
		expect(result.claims.jti).toBe('j1');
	});

	it('wrong or missing typ → bad_typ', async () => {
		await expectCode(verify(await signJws(rsa, CLAIMS, { typ: 'JWT' }), [rsa.publicJwk]), 'bad_typ');
		await expectCode(verify(await signJws(rsa, CLAIMS, { typ: undefined }), [rsa.publicJwk]), 'bad_typ');
	});

	it('alg none → bad_alg', async () => {
		const token = `${b64urlJson({ alg: 'none', typ: TYP, kid: 'rsa-1' })}.${b64urlJson(CLAIMS)}.`;
		await expectCode(verify(token, [rsa.publicJwk]), 'bad_alg');
	});

	it('HS256 header signed with the public key as an HMAC secret → bad_alg', async () => {
		const signingInput = `${b64urlJson({ alg: 'HS256', typ: TYP, kid: 'rsa-1' })}.${b64urlJson(CLAIMS)}`;
		const secret = encoder.encode(JSON.stringify(rsa.publicJwk));
		const hmac = await crypto.subtle.importKey('raw', secret, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
		const signature = await crypto.subtle.sign('HMAC', hmac, encoder.encode(signingInput));
		await expectCode(verify(`${signingInput}.${b64url(signature)}`, [rsa.publicJwk]), 'bad_alg');
	});

	it('a supported alg outside allowedAlgs → bad_alg', async () => {
		await expectCode(verify(await signJws(ec), [ec.publicJwk], ['RS256']), 'bad_alg');
	});

	it('unknown kid → no_key', async () => {
		await expectCode(verify(await signJws(rsa, CLAIMS, { kid: 'rotated-away' }), [rsa.publicJwk, rsaRotated.publicJwk]), 'no_key');
	});

	it('kid-less header with two compatible keys → no_key', async () => {
		await expectCode(verify(await signJws(rsa, CLAIMS, { kid: undefined }), [rsa.publicJwk, rsaRotated.publicJwk]), 'no_key');
	});

	it('key with use=enc, a mismatched alg, or the wrong curve → no_key', async () => {
		const token = await signJws(rsa);
		await expectCode(verify(token, [{ ...rsa.publicJwk, use: 'enc' }]), 'no_key');
		await expectCode(verify(token, [{ ...rsa.publicJwk, alg: 'RS512' }]), 'no_key');
		await expectCode(verify(await signJws(ec), [{ ...ec.publicJwk, crv: 'P-384' }]), 'no_key');
	});

	it('private key material in the JWKS → no_key', async () => {
		expect(rsa.privateJwk.d).toEqual(expect.any(String));
		await expectCode(verify(await signJws(rsa), [rsa.privateJwk]), 'no_key');
	});

	it('RSA-1024 key → no_key', async () => {
		await expectCode(verify(await signJws(rsaWeak), [rsaWeak.publicJwk]), 'no_key');
	});

	it('key members that WebCrypto cannot import → no_key', async () => {
		await expectCode(verify(await signJws(ec), [{ ...ec.publicJwk, x: 'AAAA' }]), 'no_key');
		await expectCode(verify(await signJws(rsa), [{ ...rsa.publicJwk, n: '' }]), 'no_key');
	});

	it('tampered payload → bad_signature', async () => {
		const [h, , s] = (await signJws(rsa)).split('.');
		await expectCode(verify(`${h}.${b64urlJson({ ...CLAIMS, sub: 'admin' })}.${s}`, [rsa.publicJwk]), 'bad_signature');
		const [eh, , es] = (await signJws(ec)).split('.');
		await expectCode(verify(`${eh}.${b64urlJson({ ...CLAIMS, sub: 'admin' })}.${es}`, [ec.publicJwk]), 'bad_signature');
	});

	it('signature by a different key under the same kid → bad_signature', async () => {
		await expectCode(verify(await signJws(rsaRotated, CLAIMS, { kid: 'rsa-1' }), [rsa.publicJwk]), 'bad_signature');
	});

	it('a WebCrypto verify that rejects → bad_signature, not a raw error', async () => {
		const token = await signJws(rsa);
		const spy = vi.spyOn(crypto.subtle, 'verify').mockRejectedValueOnce(new DOMException('boom', 'OperationError'));
		try {
			await expectCode(verify(token, [rsa.publicJwk]), 'bad_signature');
			expect(spy).toHaveBeenCalledTimes(1);
		} finally {
			spy.mockRestore();
		}
	});

	it('ES256 signature that is not 64 raw bytes → bad_signature', async () => {
		const [h, p, s] = (await signJws(ec)).split('.');
		await expectCode(verify(`${h}.${p}.${s}AAAA`, [ec.publicJwk]), 'bad_signature');
		await expectCode(verify(`${h}.${p}.`, [ec.publicJwk]), 'bad_signature');
	});

	it('malformed compact serialization → malformed', async () => {
		const good = await signJws(rsa);
		const [h, p, s] = good.split('.');
		const cases = [
			`${h}.${p}`,
			`${good}.extra`,
			`${h}+.${p}.${s}`,
			`${'A'.repeat(8193)}.${p}.${s}`,
			`${b64urlJson(['not', 'an', 'object'])}.${p}.${s}`,
			`${b64url(encoder.encode('{not json'))}.${p}.${s}`,
			`${h}.${p}.A`,
		];
		for (const token of cases) await expectCode(verify(token, [rsa.publicJwk]), 'malformed');
	});

	it('validly signed payload that is not a JSON object → malformed', async () => {
		await expectCode(verify(await signJws(rsa, ['array'] as unknown as Record<string, unknown>), [rsa.publicJwk]), 'malformed');
	});

	it('non-string input → malformed; a set without a keys array → no_key', async () => {
		const { verifyJwsWithJwks } = await import('../../src/oauth/jwks');
		await expectCode(verify(undefined as unknown as string, [rsa.publicJwk]), 'malformed');
		const noKeys = verifyJwsWithJwks(await signJws(rsa), { jwks: {} as never, allowedAlgs: ['RS256'], expectedTyp: TYP });
		await expectCode(noKeys, 'no_key');
	});

	it('non-string kid or any crit header → malformed', async () => {
		await expectCode(verify(await signJws(rsa, CLAIMS, { kid: 7 }), [rsa.publicJwk]), 'malformed');
		await expectCode(verify(await signJws(rsa, CLAIMS, { crit: ['exp'], exp: 1 }), [rsa.publicJwk]), 'malformed');
	});

	it('ignores a key embedded in the header (jwk) and verifies only against the set', async () => {
		const token = await signJws(rsaRotated, CLAIMS, { kid: 'rsa-1', jwk: rsaRotated.publicJwk });
		await expectCode(verify(token, [rsa.publicJwk]), 'bad_signature');
	});
});

describe('oauth/jwks — getJwksCached', () => {
	let served: () => Response;
	let fetchMock: ReturnType<typeof vi.fn>;

	function stubFetch(response: () => Response) {
		served = response;
		fetchMock = vi.fn(async () => served());
		vi.stubGlobal('fetch', fetchMock);
	}

	async function cacheKeyFor(uri: string): Promise<string> {
		const { sha256Hex } = await import('../../src/oauth/jwks');
		return `oauth:ema-jwks:${await sha256Hex(uri)}`;
	}

	async function expectFetchFailureNotCached(response: () => Response, uri = JWKS_URI): Promise<void> {
		const { getJwksCached, JwksFetchError } = await import('../../src/oauth/jwks');
		stubFetch(response);
		const error = await getJwksCached(kv(), uri, { now: NOW }).then(
			() => null,
			(caught: unknown) => caught,
		);
		expect(error).toBeInstanceOf(JwksFetchError);
		expect((error as { code: string }).code).toBe('no_key');
		expect(await env.SESSION_STORE.get(await cacheKeyFor(uri))).toBeNull();
	}

	it('sha256Hex is lowercase hex SHA-256', async () => {
		const { sha256Hex } = await import('../../src/oauth/jwks');
		expect(await sha256Hex('abc')).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
	});

	it('fetches GET with manual redirects, a JSON accept header and a timeout signal, then caches for 600s', async () => {
		const { getJwksCached } = await import('../../src/oauth/jwks');
		stubFetch(() => jsonResponse({ keys: [rsa.publicJwk] }));
		const first = await getJwksCached(kv(), JWKS_URI, { now: NOW });
		expect(first).toEqual({ keys: [rsa.publicJwk] });

		const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
		expect(url).toBe(JWKS_URI);
		expect(init.method).toBe('GET');
		expect(init.redirect).toBe('manual');
		expect(new Headers(init.headers).get('accept')).toBe('application/json');
		expect(init.signal).toBeInstanceOf(AbortSignal);

		const key = await cacheKeyFor(JWKS_URI);
		expect(await env.SESSION_STORE.get(key, 'json')).toEqual({ fetchedAt: NOW, keys: [rsa.publicJwk] });
		const listed = await env.SESSION_STORE.list({ prefix: key });
		const nowSeconds = Date.now() / 1000;
		expect(listed.keys[0].expiration).toBeGreaterThan(nowSeconds + 590);
		expect(listed.keys[0].expiration).toBeLessThan(nowSeconds + 610);

		expect(await getJwksCached(kv(), JWKS_URI, { now: NOW + 599 })).toEqual(first);
		expect(fetchMock).toHaveBeenCalledTimes(1);
	});

	it('refetches once the cached set is 600s old', async () => {
		const { getJwksCached } = await import('../../src/oauth/jwks');
		stubFetch(() => jsonResponse({ keys: [rsa.publicJwk] }));
		await getJwksCached(kv(), JWKS_URI, { now: NOW });
		served = () => jsonResponse({ keys: [rsaRotated.publicJwk] });
		expect(await getJwksCached(kv(), JWKS_URI, { now: NOW + 600 })).toEqual({ keys: [rsaRotated.publicJwk] });
		expect(fetchMock).toHaveBeenCalledTimes(2);
	});

	it('forceRefresh refetches once, then serves the cache for 60s, then may refetch again', async () => {
		const { getJwksCached } = await import('../../src/oauth/jwks');
		stubFetch(() => jsonResponse({ keys: [rsa.publicJwk] }));
		await getJwksCached(kv(), JWKS_URI, { now: NOW });

		served = () => jsonResponse({ keys: [rsa.publicJwk, rsaRotated.publicJwk] });
		const refreshed = await getJwksCached(kv(), JWKS_URI, { now: NOW + 1, forceRefresh: true });
		expect(refreshed.keys).toHaveLength(2);
		expect(fetchMock).toHaveBeenCalledTimes(2);

		served = () => jsonResponse({ keys: [ec.publicJwk] });
		expect(await getJwksCached(kv(), JWKS_URI, { now: NOW + 30, forceRefresh: true })).toEqual(refreshed);
		expect(await getJwksCached(kv(), JWKS_URI, { now: NOW + 60, forceRefresh: true })).toEqual(refreshed);
		expect(fetchMock).toHaveBeenCalledTimes(2);

		expect(await getJwksCached(kv(), JWKS_URI, { now: NOW + 61, forceRefresh: true })).toEqual({ keys: [ec.publicJwk] });
		expect(fetchMock).toHaveBeenCalledTimes(3);
	});

	it('drops non-object entries from keys', async () => {
		const { getJwksCached } = await import('../../src/oauth/jwks');
		stubFetch(() => jsonResponse({ keys: [1, null, 'x', [], rsa.publicJwk] }));
		expect(await getJwksCached(kv(), JWKS_URI, { now: NOW })).toEqual({ keys: [rsa.publicJwk] });
	});

	it('non-200 is rejected and never cached; the next call fetches again', async () => {
		await expectFetchFailureNotCached(() => jsonResponse({ keys: [rsa.publicJwk] }, { status: 500 }));
		const { getJwksCached } = await import('../../src/oauth/jwks');
		served = () => jsonResponse({ keys: [rsa.publicJwk] });
		expect(await getJwksCached(kv(), JWKS_URI, { now: NOW })).toEqual({ keys: [rsa.publicJwk] });
		expect(fetchMock).toHaveBeenCalledTimes(2);
	});

	it('a 3xx redirect is rejected, not followed, and never cached', async () => {
		await expectFetchFailureNotCached(
			() => new Response(null, { status: 302, headers: { location: 'https://attacker.example.net/keys' } }),
		);
		expect(fetchMock).toHaveBeenCalledTimes(1);
	});

	it('a body over 64KB is rejected and never cached', async () => {
		await expectFetchFailureNotCached(() => jsonResponse({ keys: [rsa.publicJwk], pad: 'x'.repeat(70_000) }));
	});

	it('a non-JSON body is rejected and never cached', async () => {
		await expectFetchFailureNotCached(() => new Response('<html>login</html>', { status: 200 }));
	});

	it('a JSON body without a usable keys array is rejected and never cached', async () => {
		await expectFetchFailureNotCached(() => jsonResponse({ keys: 'nope' }));
		await expectFetchFailureNotCached(() => jsonResponse({ keys: [1, 'x'] }));
		await expectFetchFailureNotCached(() => jsonResponse([rsa.publicJwk]));
	});

	it('a network error is a JwksFetchError and never cached', async () => {
		await expectFetchFailureNotCached(() => {
			throw new TypeError('network down');
		});
	});

	it('a URL safeFetch blocks never reaches fetch', async () => {
		await expectFetchFailureNotCached(() => jsonResponse({ keys: [rsa.publicJwk] }), 'http://acme.okta.com/oauth2/v1/keys');
		expect(fetchMock).not.toHaveBeenCalled();
		await expectFetchFailureNotCached(() => jsonResponse({ keys: [rsa.publicJwk] }), 'https://localhost/keys');
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it('a corrupt cache entry is treated as a miss', async () => {
		const { getJwksCached } = await import('../../src/oauth/jwks');
		const key = await cacheKeyFor(JWKS_URI);
		stubFetch(() => jsonResponse({ keys: [rsa.publicJwk] }));
		const corrupt = [
			'not-json',
			JSON.stringify({ fetchedAt: 'yesterday', keys: [rsa.publicJwk] }),
			JSON.stringify({ fetchedAt: NOW, keys: [] }),
		];
		for (const [index, raw] of corrupt.entries()) {
			await env.SESSION_STORE.put(key, raw);
			expect(await getJwksCached(kv(), JWKS_URI, { now: NOW })).toEqual({ keys: [rsa.publicJwk] });
			expect(fetchMock).toHaveBeenCalledTimes(index + 1);
		}
	});

	it('without opts.now, caches against the wall clock', async () => {
		const { getJwksCached } = await import('../../src/oauth/jwks');
		stubFetch(() => jsonResponse({ keys: [rsa.publicJwk] }));
		await getJwksCached(kv(), JWKS_URI);
		const stored = (await env.SESSION_STORE.get(await cacheKeyFor(JWKS_URI), 'json')) as { fetchedAt: number } | null;
		expect(stored).toEqual({ fetchedAt: expect.any(Number), keys: [rsa.publicJwk] });
		expect(Math.abs((stored?.fetchedAt ?? 0) - Date.now() / 1000)).toBeLessThan(5);
		await getJwksCached(kv(), JWKS_URI);
		expect(fetchMock).toHaveBeenCalledTimes(1);
	});

	it('a KV binding that rejects degrades to an uncached fetch', async () => {
		const { getJwksCached } = await import('../../src/oauth/jwks');
		const failingKv = {
			get: async () => {
				throw new Error('kv unavailable');
			},
			put: async () => {
				throw new Error('kv unavailable');
			},
		} as unknown as KVNamespace;
		stubFetch(() => jsonResponse({ keys: [rsa.publicJwk] }));
		expect(await getJwksCached(failingKv, JWKS_URI, { now: NOW })).toEqual({ keys: [rsa.publicJwk] });
		expect(await getJwksCached(failingKv, JWKS_URI, { now: NOW, forceRefresh: true })).toEqual({ keys: [rsa.publicJwk] });
		expect(fetchMock).toHaveBeenCalledTimes(2);
	});

	it('a fetched set verifies a token end to end', async () => {
		const { getJwksCached, verifyJwsWithJwks } = await import('../../src/oauth/jwks');
		stubFetch(() => jsonResponse({ keys: [rsa.publicJwk, ec.publicJwk] }));
		const jwks = await getJwksCached(kv(), JWKS_URI, { now: NOW });
		const result = await verifyJwsWithJwks(await signJws(ec), { jwks, allowedAlgs: ['RS256', 'ES256'], expectedTyp: TYP });
		expect(result.claims).toEqual(CLAIMS);
	});
});
