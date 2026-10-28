// SPDX-License-Identifier: BUSL-1.1

/**
 * Enterprise Managed Auth (EMA) per-tenant trusted-issuer store.
 *
 * Layout in SESSION_STORE (no TTL — tenants live until an operator deletes them):
 *   oauth:ema-tenant:<tenant_id>              → EmaTenantRecord JSON (sealed when KV_ENVELOPE_KEY is set)
 *   oauth:ema-issuer:<sha256hex(issuer)>      → tenant_id (plain; the key is a hash and the value is not sensitive)
 *
 * The issuer index is how the token grant answers "is this `iss` allowlisted?".
 * One issuer maps to exactly one tenant.
 */

import { EMA_TENANT_ID_PATTERN, EmaTenantRecordSchema, type EmaTenantRecord } from '../schemas/ema';
import { OAUTH_KV_PREFIX } from '../lib/config';
import { sealKv, openKv, isSealed } from '../lib/kv-envelope';
import { StrongStateUnavailableError } from './storage';

const tenantKey = (tenantId: string) => `${OAUTH_KV_PREFIX}ema-tenant:${tenantId}`;
const TENANT_PREFIX = `${OAUTH_KV_PREFIX}ema-tenant:`;
const ISSUER_PREFIX = `${OAUTH_KV_PREFIX}ema-issuer:`;
const issuerKey = async (normalizedIssuer: string) => `${ISSUER_PREFIX}${await sha256Hex(normalizedIssuer)}`;

/** Hard cap on list size — the operator surface, not a pagination API. */
const EMA_TENANT_LIST_LIMIT = 100;

export class EmaTenantConflictError extends Error {
	constructor() {
		super('Issuer is already registered to a different tenant');
		this.name = 'EmaTenantConflictError';
	}
}

async function sha256Hex(value: string): Promise<string> {
	const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)));
	return Array.from(digest, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function isPlainHttpsUrl(url: URL): boolean {
	return url.protocol === 'https:' && !url.username && !url.password && !url.search && !url.hash;
}

/**
 * Canonical form of an issuer identifier: https only, no userinfo/query/fragment,
 * lowercase host, and every trailing slash stripped, so the result is a fixed point
 * (normalizing it again changes nothing). Throws on anything else.
 */
export function normalizeIssuer(iss: string): string {
	const url = new URL(iss);
	if (!isPlainHttpsUrl(url)) throw new Error('Issuer must be an https URL without userinfo, query or fragment');
	return url.origin + url.pathname.replace(/\/+$/, '');
}

/**
 * Read one tenant record, fail-closed. With an envelope key configured an unsealed
 * (plaintext) record is treated as absent: the keyspace is sealed from birth, so a
 * plaintext value can only have been planted. The decoded `tenant_id` must equal the
 * key it was read from, so a valid blob copied under another key is not honoured.
 */
async function readRecord(kv: KVNamespace, tenantId: string, kvEnvelopeKey?: Uint8Array): Promise<EmaTenantRecord | null> {
	const raw = await kv.get(tenantKey(tenantId));
	if (!raw) return null;
	try {
		let json = raw;
		if (kvEnvelopeKey) {
			if (!isSealed(raw)) return null;
			json = await openKv(raw, kvEnvelopeKey);
		}
		const record = EmaTenantRecordSchema.parse(JSON.parse(json));
		return record.tenant_id === tenantId ? record : null;
	} catch {
		// Corrupted, wrong-key or schema-invalid: an unreadable tenant is not a trusted tenant.
		return null;
	}
}

/**
 * Upsert a tenant. The stored issuer is the normalized form. Throws
 * EmaTenantConflictError when another tenant already owns the issuer; moving a
 * tenant to a new issuer releases its old index entry.
 */
export async function putEmaTenant(kv: KVNamespace, rec: EmaTenantRecord, kvEnvelopeKey?: Uint8Array): Promise<EmaTenantRecord> {
	const stored: EmaTenantRecord = { ...rec, issuer: normalizeIssuer(rec.issuer) };
	const newIndexKey = await issuerKey(stored.issuer);
	const owner = await kv.get(newIndexKey);
	if (owner && owner !== stored.tenant_id) {
		if (await ownsIssuer(kv, owner, stored.issuer, kvEnvelopeKey)) throw new EmaTenantConflictError();
	}

	const previous = await readRecord(kv, stored.tenant_id, kvEnvelopeKey);
	const plaintext = JSON.stringify(stored);
	await kv.put(tenantKey(stored.tenant_id), kvEnvelopeKey ? await sealKv(plaintext, kvEnvelopeKey) : plaintext);
	await kv.put(newIndexKey, stored.tenant_id);

	if (previous && previous.issuer !== stored.issuer) await releaseIssuerIndex(kv, previous.issuer, stored.tenant_id);
	return stored;
}

/**
 * Does `tenantId` really hold `issuer`? An index entry whose owner record is missing,
 * unreadable (key rotation, corruption) or lists a different issuer is an orphan: it
 * cannot vouch for the issuer (getEmaTenantByIssuer re-checks the record) and must not
 * block another tenant from claiming it either.
 */
async function ownsIssuer(kv: KVNamespace, tenantId: string, issuer: string, kvEnvelopeKey?: Uint8Array): Promise<boolean> {
	const record = await readRecord(kv, tenantId, kvEnvelopeKey);
	return record !== null && record.issuer === issuer;
}

/** Delete an issuer's index entry, but only while it still points at `tenantId`. */
async function releaseIssuerIndex(kv: KVNamespace, issuer: string, tenantId: string): Promise<void> {
	const indexKey = await issuerKey(issuer);
	if ((await kv.get(indexKey)) === tenantId) await kv.delete(indexKey);
}

export async function getEmaTenant(kv: KVNamespace, tenantId: string, kvEnvelopeKey?: Uint8Array): Promise<EmaTenantRecord | null> {
	return readRecord(kv, tenantId, kvEnvelopeKey);
}

/** Resolve an `iss` claim to its tenant. Null when the issuer is malformed, unregistered, or its record is unreadable. */
export async function getEmaTenantByIssuer(kv: KVNamespace, issuer: string, kvEnvelopeKey?: Uint8Array): Promise<EmaTenantRecord | null> {
	let normalized: string;
	try {
		normalized = normalizeIssuer(issuer);
	} catch {
		return null;
	}
	const tenantId = await kv.get(await issuerKey(normalized));
	if (!tenantId) return null;
	const record = await readRecord(kv, tenantId, kvEnvelopeKey);
	// A stale index entry must never vouch for an issuer the record no longer lists.
	return record && record.issuer === normalized ? record : null;
}

/**
 * Delete every issuer index entry that points at `tenantId`. Used when the record is
 * missing or unreadable, so its issuer (and therefore the index key) cannot be derived.
 */
async function releaseIssuerIndexesOwnedBy(kv: KVNamespace, tenantId: string): Promise<void> {
	let cursor: string | undefined;
	do {
		const page = await kv.list({ prefix: ISSUER_PREFIX, cursor });
		const owners = await Promise.all(page.keys.map(async (key) => [key.name, await kv.get(key.name)] as const));
		await Promise.all(owners.filter(([, owner]) => owner === tenantId).map(([name]) => kv.delete(name)));
		cursor = page.list_complete ? undefined : page.cursor;
	} while (cursor);
}

/** Idempotent. Releases the issuer index even when the record is missing or cannot be read. */
export async function deleteEmaTenant(kv: KVNamespace, tenantId: string, kvEnvelopeKey?: Uint8Array): Promise<void> {
	const record = await readRecord(kv, tenantId, kvEnvelopeKey);
	if (record) await releaseIssuerIndex(kv, record.issuer, tenantId);
	else await releaseIssuerIndexesOwnedBy(kv, tenantId);
	await kv.delete(tenantKey(tenantId));
}

/** Every EMA access token's subject is `ema:<tenant_id>:<32 hex of sha256(IdP sub)>`. */
export const EMA_SUBJECT_PREFIX = 'ema:';

/**
 * The epoch an EMA access token must carry as `tep`. A record written before `token_epoch`
 * existed falls back to `created_at`; the two never collide (ms vs s) and only equality matters.
 */
export function tenantEpoch(rec: EmaTenantRecord): number {
	return rec.token_epoch ?? rec.created_at;
}

/** The tenant_id of a well-formed `ema:<tenant_id>:<hash>` subject, else null. */
function emaSubjectTenantId(sub: string): string | null {
	const tenantId = sub.slice(EMA_SUBJECT_PREFIX.length, sub.lastIndexOf(':'));
	return sub.startsWith(EMA_SUBJECT_PREFIX) && EMA_TENANT_ID_PATTERN.test(tenantId) ? tenantId : null;
}

/** The claims of an EMA access token that tenant liveness is judged on. */
export interface EmaTokenClaims {
	sub: string;
	tier?: unknown;
	tep?: unknown;
}

function tenantBacksToken(rec: EmaTenantRecord, claims: EmaTokenClaims, nowSeconds: number): boolean {
	return (
		rec.enabled && (rec.entitlement_expires_at ?? Infinity) > nowSeconds && claims.tier === rec.tier && claims.tep === tenantEpoch(rec)
	);
}

/**
 * Tenant-wide revocation for an already-minted EMA access token, checked on every request: the
 * token stands only while its tenant record exists and is readable, enabled, inside its
 * entitlement, on the token's tier, and on the token's epoch (`tep`; a token without one fails).
 * Disabling, deleting, re-creating or lapsing a tenant therefore cuts its tokens off within KV
 * propagation (about a minute) instead of at their expiry. A store that cannot be read throws
 * StrongStateUnavailableError (a retryable 503), never a silent accept or a 401.
 */
export async function isEmaTokenLive(
	kv: KVNamespace,
	claims: EmaTokenClaims,
	nowSeconds: number,
	kvEnvelopeKey?: Uint8Array,
): Promise<boolean> {
	const tenantId = emaSubjectTenantId(claims.sub);
	if (!tenantId) return false;
	let rec: EmaTenantRecord | null;
	try {
		rec = await readRecord(kv, tenantId, kvEnvelopeKey);
	} catch {
		throw new StrongStateUnavailableError('ema tenant liveness');
	}
	return rec !== null && tenantBacksToken(rec, claims, nowSeconds);
}

/** List up to 100 tenants, skipping unreadable records. */
export async function listEmaTenants(kv: KVNamespace, kvEnvelopeKey?: Uint8Array): Promise<EmaTenantRecord[]> {
	const { keys } = await kv.list({ prefix: TENANT_PREFIX, limit: EMA_TENANT_LIST_LIMIT });
	const records = await Promise.all(keys.map((key) => readRecord(kv, key.name.slice(TENANT_PREFIX.length), kvEnvelopeKey)));
	return records.filter((rec): rec is EmaTenantRecord => rec !== null);
}
