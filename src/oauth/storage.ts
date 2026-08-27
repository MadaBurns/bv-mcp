// SPDX-License-Identifier: BUSL-1.1
import type { ClientRecord, CodeRecord, CodeRecordInput } from '../schemas/oauth';
import { ClientRecordSchema, CodeRecordSchema } from '../schemas/oauth';
import { OAUTH_CLIENT_TTL_SECONDS, OAUTH_CODE_TTL_SECONDS, OAUTH_JWT_TTL_SECONDS, OAUTH_KV_PREFIX } from '../lib/config';
import { sealKv, openKv, isSealed } from '../lib/kv-envelope';
import {
	bumpVersionIdempotentlyWithCoordinator,
	bumpVersionWithCoordinator,
	claimOnceWithCoordinator,
	getVersionWithCoordinator,
	hasMarkerWithCoordinator,
	setMarkerWithCoordinator,
	setMaxVersionWithCoordinator,
	type QuotaCoordinator,
} from '../lib/quota-coordinator';

const clientKey = (id: string) => `${OAUTH_KV_PREFIX}client:${id}`;
const codeKey = (code: string) => `${OAUTH_KV_PREFIX}code:${code}`;
const revokedKey = (jti: string) => `${OAUTH_KV_PREFIX}revoked:${jti}`;

function isExactRecord(value: unknown, keys: readonly string[]): value is Record<string, unknown> {
	if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
	const actualKeys = Object.keys(value);
	return actualKeys.length === keys.length && keys.every((key) => actualKeys.includes(key));
}

function isClaimOnceResult(value: unknown): value is { claimed: boolean } {
	return isExactRecord(value, ['claimed']) && typeof value.claimed === 'boolean';
}

function isMarkerResult(value: unknown): value is { present: boolean } {
	return isExactRecord(value, ['present']) && typeof value.present === 'boolean';
}

function isVersionResult(value: unknown): value is { value: number } {
	if (!isExactRecord(value, ['value'])) return false;
	const candidate = value.value;
	return typeof candidate === 'number' && Number.isSafeInteger(candidate) && candidate >= 1;
}

function isIdempotentVersionBumpResult(
	value: unknown,
): value is { state: 'complete'; value: number } | { state: 'conflict' } {
	if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
	const record = value as Record<string, unknown>;
	const state = record.state;
	if (state === 'conflict') return isExactRecord(value, ['state']);
	return state === 'complete' && isExactRecord(value, ['state', 'value']) && isVersionResult({ value: record.value });
}

export class StrongStateUnavailableError extends Error {
	constructor(operation: string) {
		super(`Strong authorization state unavailable during ${operation}`);
		this.name = 'StrongStateUnavailableError';
	}
}

async function coordinationKey(
	kind: 'code' | 'jti' | 'subject' | 'subject-entitlement-generation',
	value: string,
): Promise<string> {
	const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)));
	const hex = Array.from(digest)
		.map((byte) => byte.toString(16).padStart(2, '0'))
		.join('');
	return `oauth:${kind}:${hex}`;
}

/** Generate a URL-safe opaque authorization code (~32 bytes of entropy, base64url). */
export function createAuthorizationCode(): string {
	const bytes = new Uint8Array(32);
	crypto.getRandomValues(bytes);
	let s = '';
	for (const b of bytes) s += String.fromCharCode(b);
	return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Persist a registered OAuth client record. Refreshes the 1-year TTL on every write. */
export async function putClient(kv: KVNamespace, rec: ClientRecord, kvEnvelopeKey?: Uint8Array): Promise<void> {
	const plaintext = JSON.stringify(rec);
	const value = kvEnvelopeKey ? await sealKv(plaintext, kvEnvelopeKey) : plaintext;
	await kv.put(clientKey(rec.client_id), value, { expirationTtl: OAUTH_CLIENT_TTL_SECONDS });
}

/** Look up a client by id. Returns null if not found or if stored record fails schema validation. */
export async function getClient(kv: KVNamespace, id: string, kvEnvelopeKey?: Uint8Array): Promise<ClientRecord | null> {
	const raw = await kv.get(clientKey(id));
	if (!raw) return null;
	try {
		// Migration read-fallback: try decrypt if key present and value looks sealed;
		// fall back to plaintext parse for legacy records.
		let jsonStr: string;
		if (kvEnvelopeKey && isSealed(raw)) {
			try {
				jsonStr = await openKv(raw, kvEnvelopeKey);
			} catch {
				// Decryption failed — treat as unrecoverable (corrupted or wrong key)
				return null;
			}
		} else {
			jsonStr = raw;
		}
		return ClientRecordSchema.parse(JSON.parse(jsonStr));
	} catch {
		return null;
	}
}

/** Store a one-time authorization code with a 60s TTL (KV minimum). */
export async function putCode(kv: KVNamespace, code: string, rec: CodeRecordInput, kvEnvelopeKey?: Uint8Array): Promise<void> {
	const plaintext = JSON.stringify(rec);
	const value = kvEnvelopeKey ? await sealKv(plaintext, kvEnvelopeKey) : plaintext;
	await kv.put(codeKey(code), value, { expirationTtl: OAUTH_CODE_TTL_SECONDS });
}

/**
 * Single-use authorization code retrieval. The KV payload is validated first,
 * then a strongly consistent Durable Object claim is acquired before the code
 * is returned. A malformed payload is deleted, and concurrent exchanges can
 * never both claim the same code even though the KV mirror is eventually
 * consistent.
 */
export async function consumeCode(
	kv: KVNamespace,
	code: string,
	kvEnvelopeKey?: Uint8Array,
	quotaCoordinator?: DurableObjectNamespace<QuotaCoordinator>,
): Promise<CodeRecord | null> {
	const raw = await kv.get(codeKey(code));
	if (!raw) return null;
	let record: CodeRecord;
	try {
		// Migration read-fallback: try decrypt first if key present and value looks sealed;
		// fall back to legacy plaintext parse. A malformed record is invalidated below.
		let jsonStr: string;
		if (kvEnvelopeKey && isSealed(raw)) {
			try {
				jsonStr = await openKv(raw, kvEnvelopeKey);
			} catch {
				// Decryption failed — code is unrecoverable (corrupted or wrong key)
				return null;
			}
		} else {
			jsonStr = raw;
		}
		record = CodeRecordSchema.parse(JSON.parse(jsonStr));
	} catch {
		await kv.delete(codeKey(code));
		return null;
	}

	let claim;
	try {
		const expiresAt = record.issued_at * 1000 + OAUTH_CODE_TTL_SECONDS * 1000;
		claim = await claimOnceWithCoordinator(await coordinationKey('code', code), expiresAt, quotaCoordinator);
	} catch {
		throw new StrongStateUnavailableError('authorization-code consumption');
	}
	if (!isClaimOnceResult(claim)) throw new StrongStateUnavailableError('authorization-code consumption');
	if (!claim.claimed) return null;
	await kv.delete(codeKey(code));
	return record;
}

/** Add a JWT id to the revocation denylist. TTL is clamped to >= 60s (KV minimum). */
export async function revokeJti(
	kv: KVNamespace,
	jti: string,
	ttlSeconds: number,
	quotaCoordinator?: DurableObjectNamespace<QuotaCoordinator>,
): Promise<void> {
	const ttl = Math.max(60, ttlSeconds);
	let marker;
	try {
		marker = await setMarkerWithCoordinator(await coordinationKey('jti', jti), Date.now() + ttl * 1000, quotaCoordinator);
	} catch {
		throw new StrongStateUnavailableError('token revocation');
	}
	if (!isMarkerResult(marker) || !marker.present) throw new StrongStateUnavailableError('token revocation');
	try {
		await kv.put(revokedKey(jti), '1', { expirationTtl: ttl });
	} catch {
		// Strong marker is authoritative; KV is a migration/visibility mirror.
	}
}

/** Return true if the given JWT id is on the revocation denylist. */
export async function isRevoked(
	kv: KVNamespace,
	jti: string,
	quotaCoordinator?: DurableObjectNamespace<QuotaCoordinator>,
): Promise<boolean> {
	let marker;
	const key = await coordinationKey('jti', jti);
	try {
		marker = await hasMarkerWithCoordinator(key, quotaCoordinator);
	} catch {
		throw new StrongStateUnavailableError('token revocation check');
	}
	if (!isMarkerResult(marker)) throw new StrongStateUnavailableError('token revocation check');
	if (marker.present) return true;

	// Migration fallback for deny entries created before strong state shipped.
	let legacyRevoked: boolean;
	try {
		legacyRevoked = (await kv.get(revokedKey(jti))) !== null;
	} catch {
		throw new StrongStateUnavailableError('token revocation check');
	}
	if (!legacyRevoked) return false;
	const migrated = await setMarkerWithCoordinator(key, Date.now() + OAUTH_JWT_TTL_SECONDS * 1000, quotaCoordinator);
	if (!isMarkerResult(migrated) || !migrated.present) throw new StrongStateUnavailableError('token revocation migration');
	return true;
}

// ---------------------------------------------------------------------------
// Token-version helpers (FIND-13)
//
// A per-subject counter stored authoritatively in a strongly consistent
// Durable Object, with `oauth:tokenver:{sub}` retained as a migration seed and
// observability mirror. Minted JWTs carry a `ver` claim equal to the current
// counter. On verification, a token whose `ver` is less than the current
// stored version is rejected — this lets
// bv-web invalidate all in-flight JWTs for a subject (e.g. on plan downgrade)
// by bumping the counter, without waiting for JWTs to expire.
//
// Default-1 semantics: when the key is absent the version is treated as 1.
// Existing tokens (no `ver` claim) also default to 1. A first revoke writes 2,
// which rejects all ver=1 (and no-ver) tokens while new mints get ver=2.
//
// The strong version record is persistent. Its KV migration/visibility mirror
// uses OAUTH_JWT_TTL_SECONDS + a 1 day buffer; expiry or eventual consistency in
// that mirror cannot roll the authoritative version backwards.
// ---------------------------------------------------------------------------

/** KV migration/mirror key for the token-version counter for a subject. */
const tokenVersionKey = (sub: string) => `${OAUTH_KV_PREFIX}tokenver:${sub}`;

/** Minimum TTL we keep the counter alive for. Access-token lifetime + 1 day buffer. */
const TOKEN_VERSION_TTL_SECONDS = OAUTH_JWT_TTL_SECONDS + 86_400;

/** KV migration/visibility mirror for the minimum valid entitlement generation. */
const entitlementGenerationKey = (sub: string) => `${OAUTH_KV_PREFIX}entitlement-generation:${sub}`;

/**
 * Read the minimum entitlement generation accepted for a subject. Generation 1
 * is the compatibility floor for credentials minted before generation claims
 * shipped; the strongly consistent coordinator is authoritative.
 */
export async function getMinimumEntitlementGeneration(
	kv: KVNamespace,
	sub: string,
	quotaCoordinator?: DurableObjectNamespace<QuotaCoordinator>,
): Promise<number> {
	const raw = await kv.get(entitlementGenerationKey(sub));
	const parsed = Number(raw);
	const legacyValue = Number.isSafeInteger(parsed) && parsed >= 1 ? parsed : 1;
	let result;
	try {
		result = await getVersionWithCoordinator(
			await coordinationKey('subject-entitlement-generation', sub),
			legacyValue,
			quotaCoordinator,
		);
	} catch {
		throw new StrongStateUnavailableError('entitlement-generation read');
	}
	if (!isVersionResult(result)) throw new StrongStateUnavailableError('entitlement-generation read');
	return result.value;
}

/**
 * Monotonically raise a subject's minimum valid entitlement generation. This is
 * naturally idempotent: delayed and repeated outbox deliveries of generation N
 * can never revoke a credential authorized later under generation N or greater.
 */
export async function raiseMinimumEntitlementGeneration(
	kv: KVNamespace,
	sub: string,
	minGeneration: number,
	quotaCoordinator?: DurableObjectNamespace<QuotaCoordinator>,
): Promise<number> {
	if (!Number.isSafeInteger(minGeneration) || minGeneration < 1) {
		throw new StrongStateUnavailableError('entitlement-generation update');
	}
	const raw = await kv.get(entitlementGenerationKey(sub));
	const parsed = Number(raw);
	const legacyValue = Number.isSafeInteger(parsed) && parsed >= 1 ? parsed : 1;
	let result;
	try {
		result = await setMaxVersionWithCoordinator(
			await coordinationKey('subject-entitlement-generation', sub),
			legacyValue,
			minGeneration,
			quotaCoordinator,
		);
	} catch {
		throw new StrongStateUnavailableError('entitlement-generation update');
	}
	if (!isVersionResult(result)) throw new StrongStateUnavailableError('entitlement-generation update');
	try {
		await kv.put(entitlementGenerationKey(sub), String(result.value), {
			expirationTtl: TOKEN_VERSION_TTL_SECONDS,
		});
	} catch {
		// Strong state is authoritative; KV is only a migration/visibility mirror.
	}
	return result.value;
}

/**
 * Read the current strongly consistent token-version for a subject. A valid
 * legacy KV value seeds the record on first access; otherwise it starts at 1,
 * matching the default `ver` value for old tokens.
 */
export async function getTokenVersion(
	kv: KVNamespace,
	sub: string,
	quotaCoordinator?: DurableObjectNamespace<QuotaCoordinator>,
): Promise<number> {
	const raw = await kv.get(tokenVersionKey(sub));
	const n = Number(raw);
	const legacyValue = Number.isSafeInteger(n) && n >= 1 ? n : 1;
	let result;
	try {
		result = await getVersionWithCoordinator(await coordinationKey('subject', sub), legacyValue, quotaCoordinator);
	} catch {
		throw new StrongStateUnavailableError('token-version read');
	}
	if (!isVersionResult(result)) throw new StrongStateUnavailableError('token-version read');
	return result.value;
}

/**
 * Increment the token-version for a subject and return the new value.
 * After this call, all JWTs carrying the previous version (or no `ver` claim
 * at all, which defaults to 1) will be rejected by `resolveTier`.
 */
export async function bumpTokenVersion(
	kv: KVNamespace,
	sub: string,
	quotaCoordinator?: DurableObjectNamespace<QuotaCoordinator>,
): Promise<number> {
	const raw = await kv.get(tokenVersionKey(sub));
	const parsed = Number(raw);
	const legacyValue = Number.isSafeInteger(parsed) && parsed >= 1 ? parsed : 1;
	let result;
	try {
		result = await bumpVersionWithCoordinator(await coordinationKey('subject', sub), legacyValue, quotaCoordinator);
	} catch {
		throw new StrongStateUnavailableError('token-version bump');
	}
	if (!isVersionResult(result)) throw new StrongStateUnavailableError('token-version bump');
	try {
		await kv.put(tokenVersionKey(sub), String(result.value), { expirationTtl: TOKEN_VERSION_TTL_SECONDS });
	} catch {
		// Strong version is authoritative; KV is a migration/visibility mirror.
	}
	return result.value;
}

/**
 * Atomically bump a subject version and persist the response associated with a
 * caller idempotency key in the same subject-shard transaction. A transport
 * failure can therefore be retried without either double-bumping or stranding a
 * pre-mutation claim.
 */
export async function bumpTokenVersionIdempotently(
	kv: KVNamespace,
	sub: string,
	idempotencyCoordinationKey: string,
	requestHash: string,
	expiresAt: number,
	quotaCoordinator?: DurableObjectNamespace<QuotaCoordinator>,
): Promise<{ state: 'complete'; value: number } | { state: 'conflict' }> {
	const raw = await kv.get(tokenVersionKey(sub));
	const parsed = Number(raw);
	const legacyValue = Number.isSafeInteger(parsed) && parsed >= 1 ? parsed : 1;
	let result;
	try {
		result = await bumpVersionIdempotentlyWithCoordinator(
			await coordinationKey('subject', sub),
			idempotencyCoordinationKey,
			requestHash,
			legacyValue,
			expiresAt,
			quotaCoordinator,
		);
	} catch {
		throw new StrongStateUnavailableError('idempotent token-version bump');
	}
	if (!isIdempotentVersionBumpResult(result)) throw new StrongStateUnavailableError('idempotent token-version bump');
	if (result.state === 'conflict') return result;
	try {
		await kv.put(tokenVersionKey(sub), String(result.value), { expirationTtl: TOKEN_VERSION_TTL_SECONDS });
	} catch {
		// Strong version + replay record committed atomically; KV is only a mirror.
	}
	return result;
}
