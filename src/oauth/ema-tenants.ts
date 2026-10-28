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

import { EmaTenantRecordSchema, type EmaTenantRecord } from '../schemas/ema';
import { OAUTH_KV_PREFIX } from '../lib/config';
import { sealKv, openKv, isSealed } from '../lib/kv-envelope';

const tenantKey = (tenantId: string) => `${OAUTH_KV_PREFIX}ema-tenant:${tenantId}`;
const TENANT_PREFIX = `${OAUTH_KV_PREFIX}ema-tenant:`;
const issuerKey = async (normalizedIssuer: string) => `${OAUTH_KV_PREFIX}ema-issuer:${await sha256Hex(normalizedIssuer)}`;

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

/**
 * Canonical form of an issuer identifier: https only, no userinfo/query/fragment,
 * lowercase host, and ONE trailing slash stripped. Throws on anything else.
 */
export function normalizeIssuer(iss: string): string {
	const url = new URL(iss);
	if (url.protocol !== 'https:') throw new Error('Issuer must use https');
	if (url.username || url.password) throw new Error('Issuer must not contain userinfo');
	if (url.search || url.hash) throw new Error('Issuer must not contain a query or fragment');
	const pathname = url.pathname.endsWith('/') ? url.pathname.slice(0, -1) : url.pathname;
	return url.origin + pathname;
}

async function readRecord(kv: KVNamespace, tenantId: string, kvEnvelopeKey?: Uint8Array): Promise<EmaTenantRecord | null> {
	const raw = await kv.get(tenantKey(tenantId));
	if (!raw) return null;
	try {
		let json = raw;
		if (kvEnvelopeKey && isSealed(raw)) json = await openKv(raw, kvEnvelopeKey);
		return EmaTenantRecordSchema.parse(JSON.parse(json));
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
	if (owner && owner !== stored.tenant_id) throw new EmaTenantConflictError();

	const previous = await readRecord(kv, stored.tenant_id, kvEnvelopeKey);
	const plaintext = JSON.stringify(stored);
	await kv.put(tenantKey(stored.tenant_id), kvEnvelopeKey ? await sealKv(plaintext, kvEnvelopeKey) : plaintext);
	await kv.put(newIndexKey, stored.tenant_id);

	if (previous && previous.issuer !== stored.issuer) {
		const oldIndexKey = await issuerKey(previous.issuer);
		if ((await kv.get(oldIndexKey)) === stored.tenant_id) await kv.delete(oldIndexKey);
	}
	return stored;
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

export async function deleteEmaTenant(kv: KVNamespace, tenantId: string, kvEnvelopeKey?: Uint8Array): Promise<void> {
	const record = await readRecord(kv, tenantId, kvEnvelopeKey);
	if (record) {
		const indexKey = await issuerKey(record.issuer);
		if ((await kv.get(indexKey)) === tenantId) await kv.delete(indexKey);
	}
	await kv.delete(tenantKey(tenantId));
}

/** List up to 100 tenants, skipping unreadable records. */
export async function listEmaTenants(kv: KVNamespace, kvEnvelopeKey?: Uint8Array): Promise<EmaTenantRecord[]> {
	const { keys } = await kv.list({ prefix: TENANT_PREFIX, limit: EMA_TENANT_LIST_LIMIT });
	const records = await Promise.all(keys.map((key) => readRecord(kv, key.name.slice(TENANT_PREFIX.length), kvEnvelopeKey)));
	return records.filter((rec): rec is EmaTenantRecord => rec !== null);
}
