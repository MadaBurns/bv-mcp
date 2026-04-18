// SPDX-License-Identifier: BUSL-1.1
import type { ClientRecord, CodeRecord } from '../schemas/oauth';
import { ClientRecordSchema, CodeRecordSchema } from '../schemas/oauth';
import { OAUTH_CLIENT_TTL_SECONDS, OAUTH_CODE_TTL_SECONDS, OAUTH_KV_PREFIX } from '../lib/config';

const clientKey = (id: string) => `${OAUTH_KV_PREFIX}client:${id}`;
const codeKey = (code: string) => `${OAUTH_KV_PREFIX}code:${code}`;
const revokedKey = (jti: string) => `${OAUTH_KV_PREFIX}revoked:${jti}`;

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
