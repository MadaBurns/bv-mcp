// SPDX-License-Identifier: BUSL-1.1

/**
 * Asymmetric JWS verification (RS256 / ES256) against a JSON Web Key Set, and
 * a bounded, KV-cached JWKS fetch.
 *
 * Built for the Enterprise Managed Auth jwt-bearer grant (US-14): a customer
 * IdP signs an ID-JAG assertion with its own key and the token endpoint checks
 * it against that tenant's registered `jwks_uri`. This module only proves
 * "this JWS was signed by exactly one key in this set". It never validates
 * claims: iss / aud / exp / client_id belong to the grant handler.
 *
 * Deliberately separate from `./jwt.ts`, which pins HS256 for our own
 * self-issued access tokens. Keys come ONLY from the caller-supplied set: the
 * `jku`, `jwk`, `x5u` and `x5c` header parameters are never consulted, so a
 * token cannot nominate its own verification key.
 */

import { OAUTH_KV_PREFIX } from '../lib/config';
import { logEvent } from '../lib/log';
import { disposeUnreadResponseBody, readJsonResponseCapped } from '../lib/response-body';
import { safeFetch } from '../lib/safe-fetch';

/** A JWK as published in a JWKS: the WebCrypto shape plus the `kid` member (RFC 7517 §4.5). */
export type JsonWebKeyWithId = JsonWebKey & { kid?: string };

export interface JsonWebKeySet {
	keys: JsonWebKeyWithId[];
}

export type AssertionVerifyErrorCode = 'malformed' | 'bad_typ' | 'bad_alg' | 'no_key' | 'bad_signature';

export class AssertionVerifyError extends Error {
	readonly code: AssertionVerifyErrorCode;

	constructor(code: AssertionVerifyErrorCode, message = `JWS verification failed: ${code}`) {
		super(message);
		this.name = 'AssertionVerifyError';
		this.code = code;
	}
}

/**
 * The JWKS could not be fetched, or the response was not a usable key set.
 * Carries code `no_key` (with no key set there is no key to verify against),
 * so a caller mapping every AssertionVerifyError to one OAuth error needs no
 * second branch. A failed fetch is never cached.
 */
export class JwksFetchError extends AssertionVerifyError {
	constructor(reason: string) {
		super('no_key', `JWKS fetch failed: ${reason}`);
		this.name = 'JwksFetchError';
	}
}

export type SupportedAlg = 'RS256' | 'ES256';

interface AlgProfile {
	readonly kty: 'RSA' | 'EC';
	readonly crv: 'P-256' | undefined;
	/** Public members that must be strings; the only members handed to importKey besides `kty`. */
	readonly members: readonly string[];
	readonly importParams: { name: string; hash?: string; namedCurve?: string };
	readonly verifyParams: { name: string; hash?: string };
	readonly minModulusBits: number;
	/** Exact signature length when the algorithm fixes one (ES256 is raw r||s, RFC 7518 §3.4). */
	readonly signatureBytes: number | null;
}

const ALG_PROFILES: Readonly<Record<SupportedAlg, AlgProfile>> = {
	RS256: {
		kty: 'RSA',
		crv: undefined,
		members: ['n', 'e'],
		importParams: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
		verifyParams: { name: 'RSASSA-PKCS1-v1_5' },
		minModulusBits: 2048,
		signatureBytes: null,
	},
	ES256: {
		kty: 'EC',
		crv: 'P-256',
		members: ['crv', 'x', 'y'],
		importParams: { name: 'ECDSA', namedCurve: 'P-256' },
		verifyParams: { name: 'ECDSA', hash: 'SHA-256' },
		minModulusBits: 0,
		signatureBytes: 64,
	},
};

const MAX_JWS_PART_LENGTH = 8192;
const BASE64URL_PART = /^[A-Za-z0-9_-]*$/;

const JWKS_CACHE_TTL_SECONDS = 600;
const JWKS_REFRESH_THROTTLE_SECONDS = 60;
const JWKS_FETCH_TIMEOUT_MS = 5000;
const JWKS_MAX_BYTES = 64 * 1024;

const jwksCacheKey = (uriHash: string) => `${OAUTH_KV_PREFIX}ema-jwks:${uriHash}`;
const jwksRefreshKey = (uriHash: string) => `${OAUTH_KV_PREFIX}ema-jwks-refresh:${uriHash}`;

const textEncoder = new TextEncoder();

function isPlainObject(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Shape only: selectKey re-checks every member before a key is used. */
function isJwkObject(value: unknown): value is JsonWebKeyWithId {
	return isPlainObject(value);
}

function base64UrlDecode(part: string): Uint8Array<ArrayBuffer> {
	const pad = part.length % 4 === 0 ? '' : '='.repeat(4 - (part.length % 4));
	const binary = atob(part.replace(/-/g, '+').replace(/_/g, '/') + pad);
	return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

function isCompactPart(part: string): boolean {
	return part.length <= MAX_JWS_PART_LENGTH && BASE64URL_PART.test(part);
}

function splitCompact(compact: string): [string, string, string] {
	const parts = typeof compact === 'string' ? compact.split('.') : [];
	if (parts.length !== 3 || !parts.every(isCompactPart)) throw new AssertionVerifyError('malformed');
	return [parts[0], parts[1], parts[2]];
}

function decodePart(part: string): Uint8Array<ArrayBuffer> {
	try {
		return base64UrlDecode(part);
	} catch {
		throw new AssertionVerifyError('malformed');
	}
}

function decodeJsonObject(part: string): Record<string, unknown> {
	let value: unknown;
	try {
		value = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(decodePart(part)));
	} catch {
		throw new AssertionVerifyError('malformed');
	}
	if (!isPlainObject(value)) throw new AssertionVerifyError('malformed');
	return value;
}

/** RFC 7515 §4.1.11: this verifier understands no extensions, so any `crit` makes the JWS invalid. */
function decodeHeader(part: string): Record<string, unknown> {
	const header = decodeJsonObject(part);
	if (header.crit !== undefined) throw new AssertionVerifyError('malformed');
	return header;
}

function isSupportedAlg(alg: unknown): alg is SupportedAlg {
	return alg === 'RS256' || alg === 'ES256';
}

function headerAlg(header: Record<string, unknown>, allowedAlgs: readonly SupportedAlg[]): SupportedAlg {
	const alg = header.alg;
	if (!isSupportedAlg(alg) || !allowedAlgs.includes(alg)) throw new AssertionVerifyError('bad_alg');
	return alg;
}

function headerKid(header: Record<string, unknown>): string | undefined {
	const kid = header.kid;
	if (kid === undefined || typeof kid === 'string') return kid;
	throw new AssertionVerifyError('malformed');
}

function hasKeyMaterial(key: Record<string, unknown>, profile: AlgProfile): boolean {
	return key.kty === profile.kty && key.crv === profile.crv && profile.members.every((member) => typeof key[member] === 'string');
}

/** RFC 7517 §4.3: when `key_ops` is present it must permit `verify`. */
function allowsVerify(key: Record<string, unknown>): boolean {
	return key.key_ops === undefined || (Array.isArray(key.key_ops) && key.key_ops.includes('verify'));
}

/** `use` (if any) is `sig` and `key_ops` (if any) includes `verify`. */
function intendedForVerification(key: Record<string, unknown>): boolean {
	return (key.use === undefined || key.use === 'sig') && allowsVerify(key);
}

function isSigningKeyFor(key: Record<string, unknown>, alg: SupportedAlg): boolean {
	const algOk = key.alg === undefined || key.alg === alg;
	return algOk && intendedForVerification(key) && hasKeyMaterial(key, ALG_PROFILES[alg]);
}

function matchesKid(key: Record<string, unknown>, kid: string | undefined): boolean {
	return kid === undefined || key.kid === kid;
}

/**
 * Collapses entries that are the same key listed twice (same kid, kty, public
 * members and private-material presence). Entries that merely share a `kid`
 * but differ in material stay separate, so they are still ambiguous.
 */
function dedupeIdenticalKeys(keys: Record<string, unknown>[], profile: AlgProfile): Record<string, unknown>[] {
	const unique = new Map<string, Record<string, unknown>>();
	for (const key of keys) {
		const privatePart = key.d === undefined ? undefined : ['d', key.d];
		const fingerprint = JSON.stringify([key.kid, key.kty, ...profile.members.map((member) => key[member]), privatePart]);
		if (!unique.has(fingerprint)) unique.set(fingerprint, key);
	}
	return [...unique.values()];
}

/**
 * Exactly one compatible key: matched by `kid` when the header names one,
 * otherwise the only key whose kty/crv/use/key_ops/alg fit (identical
 * duplicates count once). A JWK carrying private material (`d`) is refused
 * rather than used — a published private key means anyone can sign, so its
 * signatures prove nothing.
 */
function selectKey(jwks: JsonWebKeySet, alg: SupportedAlg, kid: string | undefined): Record<string, unknown> {
	const keys: unknown[] = Array.isArray(jwks?.keys) ? jwks.keys : [];
	const matching = keys.filter(isPlainObject).filter((key) => matchesKid(key, kid) && isSigningKeyFor(key, alg));
	const candidates = dedupeIdenticalKeys(matching, ALG_PROFILES[alg]);
	if (candidates.length !== 1 || candidates[0].d !== undefined) throw new AssertionVerifyError('no_key');
	return candidates[0];
}

/** Public members only, so private material, `key_ops`, `ext` and `alg` never reach importKey. */
function publicJwk(key: Record<string, unknown>, profile: AlgProfile): JsonWebKey {
	const entries = profile.members.map((member) => [member, key[member]]);
	return Object.fromEntries([['kty', profile.kty], ...entries]) as unknown as JsonWebKey;
}

function modulusBits(key: CryptoKey): number {
	const { modulusLength } = key.algorithm as { modulusLength?: unknown };
	return typeof modulusLength === 'number' ? modulusLength : 0;
}

async function importVerifyKey(key: Record<string, unknown>, profile: AlgProfile): Promise<CryptoKey> {
	let cryptoKey: CryptoKey;
	try {
		cryptoKey = await crypto.subtle.importKey('jwk', publicJwk(key, profile), profile.importParams, false, ['verify']);
	} catch {
		throw new AssertionVerifyError('no_key');
	}
	if (modulusBits(cryptoKey) < profile.minModulusBits) throw new AssertionVerifyError('no_key');
	return cryptoKey;
}

async function verifySignature(
	key: CryptoKey,
	profile: AlgProfile,
	signature: Uint8Array<ArrayBuffer>,
	signingInput: string,
): Promise<void> {
	const lengthOk = profile.signatureBytes === null || signature.byteLength === profile.signatureBytes;
	const valid =
		lengthOk && (await crypto.subtle.verify(profile.verifyParams, key, signature, textEncoder.encode(signingInput)).catch(() => false));
	if (!valid) throw new AssertionVerifyError('bad_signature');
}

/**
 * Verify a compact JWS against `opts.jwks` and return its decoded header and
 * claims. Throws AssertionVerifyError: `malformed` (shape, encoding, JSON,
 * `crit`), `bad_typ` (`typ` !== expectedTyp), `bad_alg` (anything outside
 * allowedAlgs, so `none` and HS* always), `no_key` (zero or several matching
 * keys, private or weak key) or `bad_signature`. Claims are NOT validated.
 */
export async function verifyJwsWithJwks(
	compact: string,
	opts: { jwks: JsonWebKeySet; allowedAlgs: readonly SupportedAlg[]; expectedTyp: string },
): Promise<{ header: Record<string, unknown>; claims: Record<string, unknown> }> {
	const [h, p, s] = splitCompact(compact);
	const header = decodeHeader(h);
	if (header.typ !== opts.expectedTyp) throw new AssertionVerifyError('bad_typ');
	const alg = headerAlg(header, opts.allowedAlgs);
	const profile = ALG_PROFILES[alg];
	const key = await importVerifyKey(selectKey(opts.jwks, alg, headerKid(header)), profile);
	await verifySignature(key, profile, decodePart(s), `${h}.${p}`);
	return { header, claims: decodeJsonObject(p) };
}

/** Lowercase hex SHA-256 of the UTF-8 input. */
export async function sha256Hex(input: string): Promise<string> {
	const digest = await crypto.subtle.digest('SHA-256', textEncoder.encode(input));
	return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

// The JWKS cache holds public keys only and is an optimisation: a KV fault on
// read is a miss (we fetch) and a KV fault on write just leaves the set
// uncached. Neither may fail a grant that the IdP itself can still serve.
async function kvGetQuietly(kv: KVNamespace, key: string): Promise<string | null> {
	try {
		return await kv.get(key);
	} catch {
		return null;
	}
}

async function kvPutQuietly(kv: KVNamespace, key: string, value: string, expirationTtl: number): Promise<void> {
	try {
		await kv.put(key, value, { expirationTtl });
	} catch {
		// Best-effort cache write; see above.
	}
}

function parseJsonQuietly(raw: string): unknown {
	try {
		return JSON.parse(raw);
	} catch {
		return undefined;
	}
}

/** A public RS256 or ES256 key: the least a set must hold to be worth caching. */
function isPlausibleSigningKey(key: Record<string, unknown>): boolean {
	return key.d === undefined && (hasKeyMaterial(key, ALG_PROFILES.RS256) || hasKeyMaterial(key, ALG_PROFILES.ES256));
}

/**
 * The `keys` array with non-object entries dropped; null unless at least one
 * remaining entry is a plausible signing key. An empty or error-shaped 200
 * body (`{"keys":[{}]}`) is therefore a failed fetch, never a cached set.
 */
function extractKeys(document: unknown): JsonWebKeyWithId[] | null {
	if (!isPlainObject(document) || !Array.isArray(document.keys)) return null;
	const keys = document.keys.filter(isJwkObject);
	return keys.some((key) => isPlausibleSigningKey(key as Record<string, unknown>)) ? keys : null;
}

function isFresh(fetchedAt: unknown, now: number): boolean {
	const age = now - (Number.isSafeInteger(fetchedAt) ? (fetchedAt as number) : Number.NaN);
	return age >= 0 && age < JWKS_CACHE_TTL_SECONDS;
}

async function readCachedJwks(kv: KVNamespace, uriHash: string, now: number): Promise<JsonWebKeySet | null> {
	const raw = await kvGetQuietly(kv, jwksCacheKey(uriHash));
	const entry = raw === null ? undefined : parseJsonQuietly(raw);
	if (!isPlainObject(entry) || !isFresh(entry.fetchedAt, now)) return null;
	const keys = extractKeys(entry);
	return keys ? { keys } : null;
}

async function requestJwks(jwksUri: string): Promise<Response> {
	try {
		return await safeFetch(jwksUri, {
			method: 'GET',
			redirect: 'manual',
			headers: { accept: 'application/json' },
			signal: AbortSignal.timeout(JWKS_FETCH_TIMEOUT_MS),
		});
	} catch {
		throw new JwksFetchError('request failed, timed out or was blocked by policy');
	}
}

async function fetchJwksKeys(jwksUri: string): Promise<JsonWebKeyWithId[]> {
	const response = await requestJwks(jwksUri);
	if (response.status !== 200) {
		await disposeUnreadResponseBody(response);
		throw new JwksFetchError(`HTTP ${response.status}`);
	}
	const keys = extractKeys(await readJsonResponseCapped<unknown>(response, JWKS_MAX_BYTES));
	if (!keys) throw new JwksFetchError('response is not a JSON key set within the size cap');
	return keys;
}

async function fetchAndCache(kv: KVNamespace, uriHash: string, jwksUri: string, now: number): Promise<JsonWebKeySet> {
	const keys = await fetchJwksKeys(jwksUri);
	await kvPutQuietly(kv, jwksCacheKey(uriHash), JSON.stringify({ fetchedAt: now, keys }), JWKS_CACHE_TTL_SECONDS);
	return { keys };
}

/**
 * True when this caller may bypass the cache. Records the attempt first, so
 * every other forced refresh of the same URI in the next 60s falls back to the
 * cached set: an attacker cycling unknown `kid`s cannot make us hammer the IdP.
 *
 * This KV marker is only the cross-isolate, best-effort layer: the read and the
 * write are not atomic and KV is eventually consistent across colos, so
 * simultaneous callers can all pass it. Concurrency inside one isolate is
 * bounded by `singleFlight` below.
 */
async function claimForcedRefresh(kv: KVNamespace, uriHash: string, now: number): Promise<boolean> {
	const last = await kvGetQuietly(kv, jwksRefreshKey(uriHash));
	if (last !== null && now - Number(last) < JWKS_REFRESH_THROTTLE_SECONDS) return false;
	await kvPutQuietly(kv, jwksRefreshKey(uriHash), String(now), JWKS_REFRESH_THROTTLE_SECONDS);
	return true;
}

/**
 * In-isolate single flight: callers that arrive while an identical operation is
 * running share its promise (and so its one outbound fetch). The entry is
 * removed on settle, success or failure, so a failure is never replayed.
 */
const inflight = new Map<string, Promise<JsonWebKeySet>>();

function singleFlight(key: string, run: () => Promise<JsonWebKeySet>): Promise<JsonWebKeySet> {
	const existing = inflight.get(key);
	if (existing) return existing;
	const flight: Promise<JsonWebKeySet> = run().finally(() => {
		if (inflight.get(key) === flight) inflight.delete(key);
	});
	inflight.set(key, flight);
	return flight;
}

/**
 * A failed forced refresh must not lock out tokens the cached set can still
 * verify: serve the cache, or rethrow when there is none.
 */
async function refreshOrServeCache(kv: KVNamespace, uriHash: string, jwksUri: string, now: number): Promise<JsonWebKeySet> {
	try {
		return await fetchAndCache(kv, uriHash, jwksUri, now);
	} catch (error) {
		const cached = await readCachedJwks(kv, uriHash, now);
		if (!cached) throw error;
		logEvent({
			timestamp: new Date().toISOString(),
			severity: 'info',
			category: 'oauth',
			result: 'ema_jwks_refresh_failed_serving_cache',
			error: error instanceof Error ? error.message : 'unknown',
		});
		return cached;
	}
}

async function resolveJwks(kv: KVNamespace, jwksUri: string, forceRefresh: boolean, now: number): Promise<JsonWebKeySet> {
	const uriHash = await sha256Hex(jwksUri);
	if (forceRefresh && (await claimForcedRefresh(kv, uriHash, now))) return refreshOrServeCache(kv, uriHash, jwksUri, now);
	return (await readCachedJwks(kv, uriHash, now)) ?? fetchAndCache(kv, uriHash, jwksUri, now);
}

/**
 * The JWKS at `jwksUri`, served from SESSION_STORE for 600s after a good
 * fetch. Fetches over safeFetch (https, SSRF-validated) with no redirects, a
 * 5s timeout and a 64KB body cap; only an HTTP 200 JSON body whose `keys`
 * holds at least one plausible public RS256/ES256 key is accepted and cached.
 * Anything else throws JwksFetchError and caches nothing. `forceRefresh` (for
 * an unknown `kid` after key rotation) refetches at most once per 60s per URI,
 * and a forced refresh that fails serves the still-valid cached set instead.
 * Concurrent calls in one isolate share a single fetch. `now` is epoch seconds.
 */
export function getJwksCached(
	kv: KVNamespace,
	jwksUri: string,
	opts: { forceRefresh?: boolean; now?: number } = {},
): Promise<JsonWebKeySet> {
	const now = opts.now ?? Math.floor(Date.now() / 1000);
	const forceRefresh = opts.forceRefresh === true;
	return singleFlight(`${forceRefresh ? 'refresh' : 'read'}:${jwksUri}`, () => resolveJwks(kv, jwksUri, forceRefresh, now));
}
