// SPDX-License-Identifier: BUSL-1.1
import type { ClientRecord, CodeRecord } from '../schemas/oauth';
import { ClientRecordSchema, CodeRecordSchema } from '../schemas/oauth';
import { OAUTH_CLIENT_TTL_SECONDS, OAUTH_CODE_TTL_SECONDS, OAUTH_JWT_TTL_SECONDS, OAUTH_KV_PREFIX } from '../lib/config';

const clientKey = (id: string) => `${OAUTH_KV_PREFIX}client:${id}`;
const codeKey = (code: string) => `${OAUTH_KV_PREFIX}code:${code}`;
const revokedKey = (jti: string) => `${OAUTH_KV_PREFIX}revoked:${jti}`;

/** Generate a URL-safe opaque authorization code (~32 bytes of entropy, base64url). */
export function createAuthorizationCode(): string {
	const bytes = new Uint8Array(32);
	crypto.getRandomValues(bytes);
	let s = '';
	for (const b of bytes) s += String.fromCharCode(b);
	return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Persist a registered OAuth client record. Refreshes the 1-year TTL on every write. */
export async function putClient(kv: KVNamespace, rec: ClientRecord): Promise<void> {
	await kv.put(clientKey(rec.client_id), JSON.stringify(rec), { expirationTtl: OAUTH_CLIENT_TTL_SECONDS });
}

/** Look up a client by id. Returns null if not found or if stored record fails schema validation. */
export async function getClient(kv: KVNamespace, id: string): Promise<ClientRecord | null> {
	const raw = await kv.get(clientKey(id));
	if (!raw) return null;
	try {
		return ClientRecordSchema.parse(JSON.parse(raw));
	} catch {
		return null;
	}
}

/** Store a one-time authorization code with a 60s TTL (KV minimum). */
export async function putCode(kv: KVNamespace, code: string, rec: CodeRecord): Promise<void> {
	await kv.put(codeKey(code), JSON.stringify(rec), { expirationTtl: OAUTH_CODE_TTL_SECONDS });
}

/**
 * Single-use authorization code retrieval. Reads, deletes, then parses — a
 * parse failure still invalidates the code since delete already ran. KV is
 * eventually consistent, so two concurrent requests with the same code could
 * both read before either delete propagates; v1 accepts this because PKCE
 * verification (Phase 7) provides a second binding factor.
 */
export async function consumeCode(kv: KVNamespace, code: string): Promise<CodeRecord | null> {
	const raw = await kv.get(codeKey(code));
	if (!raw) return null;
	await kv.delete(codeKey(code));
	try {
		return CodeRecordSchema.parse(JSON.parse(raw));
	} catch {
		return null;
	}
}

/** Add a JWT id to the revocation denylist. TTL is clamped to >= 60s (KV minimum). */
export async function revokeJti(kv: KVNamespace, jti: string, ttlSeconds: number): Promise<void> {
	await kv.put(revokedKey(jti), '1', { expirationTtl: Math.max(60, ttlSeconds) });
}

/** Return true if the given JWT id is on the revocation denylist. */
export async function isRevoked(kv: KVNamespace, jti: string): Promise<boolean> {
	return (await kv.get(revokedKey(jti))) !== null;
}

// ---------------------------------------------------------------------------
// Token-version helpers (FIND-13)
//
// A per-subject counter stored in KV at `oauth:tokenver:{sub}`. Minted JWTs
// carry a `ver` claim equal to the current counter. On verification, a token
// whose `ver` is less than the current stored version is rejected — this lets
// bv-web invalidate all in-flight JWTs for a subject (e.g. on plan downgrade)
// by bumping the counter, without waiting 90 days for JWTs to expire.
//
// Default-1 semantics: when the key is absent the version is treated as 1.
// Existing tokens (no `ver` claim) also default to 1. A first revoke writes 2,
// which rejects all ver=1 (and no-ver) tokens while new mints get ver=2.
//
// TTL: OAUTH_JWT_TTL_SECONDS + 1 day buffer. If the KV key were ever evicted
// while live JWTs still exist, the check would default back to 1 and silently
// re-accept revoked tokens. The TTL is refreshed on every bump.
// ---------------------------------------------------------------------------

/** KV key for the token-version counter for a subject. */
const tokenVersionKey = (sub: string) => `${OAUTH_KV_PREFIX}tokenver:${sub}`;

/** Minimum TTL we keep the counter alive for. 90-day JWT lifetime + 1 day buffer. */
const TOKEN_VERSION_TTL_SECONDS = OAUTH_JWT_TTL_SECONDS + 86_400;

/**
 * Read the current token-version for a subject. Returns 1 when the key is
 * absent or unparseable (matches the default `ver` value for old tokens).
 */
export async function getTokenVersion(kv: KVNamespace, sub: string): Promise<number> {
	const raw = await kv.get(tokenVersionKey(sub));
	if (!raw) return 1;
	const n = Number(raw);
	return Number.isFinite(n) && n >= 1 ? n : 1;
}

/**
 * Increment the token-version for a subject and return the new value.
 * After this call, all JWTs carrying the previous version (or no `ver` claim
 * at all, which defaults to 1) will be rejected by `resolveTier`.
 */
export async function bumpTokenVersion(kv: KVNamespace, sub: string): Promise<number> {
	const current = await getTokenVersion(kv, sub);
	const next = current + 1;
	await kv.put(tokenVersionKey(sub), String(next), { expirationTtl: TOKEN_VERSION_TTL_SECONDS });
	return next;
}
