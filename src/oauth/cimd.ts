// SPDX-License-Identifier: BUSL-1.1
/**
 * Client ID Metadata Document (CIMD) client identity.
 *
 * A CIMD client_id is an https URL naming a JSON document the client publishes
 * about itself, so the authorization server knows the client without Dynamic
 * Client Registration. Claude presents its client_id this way, and Enterprise
 * Managed Auth needs a client_id an IdP admin can configure ahead of time.
 *
 * The document is fetched through `safeFetch` (SSRF gate), never follows a
 * redirect, is size- and time-bounded, and must describe a public client whose
 * redirect URIs pass the same allowlist as a DCR registration. Only a document
 * that passes every check is cached; any failure resolves to `null`.
 */
import { z } from 'zod';
import { isAllowedOAuthRedirectUri, OAUTH_KV_PREFIX } from '../lib/config';
import { sealKv } from '../lib/kv-envelope';
import { disposeUnreadResponseBody, readJsonResponseCapped } from '../lib/response-body';
import { safeFetch } from '../lib/safe-fetch';
import type { ClientRecord } from '../schemas/oauth';
import { getClient } from './storage';

export const CLAUDE_WEB_CIMD_CLIENT_ID = 'https://claude.ai/oauth/mcp-oauth-client-metadata';
export const CLAUDE_CODE_CIMD_CLIENT_ID = 'https://claude.ai/oauth/claude-code-client-metadata';

const CIMD_CLIENT_ID_MAX_LENGTH = 512;
const CIMD_CACHE_TTL_SECONDS = 60 * 60;
const CIMD_MAX_BODY_BYTES = 5 * 1024;
const CIMD_FETCH_TIMEOUT_MS = 3_000;
const LOOPBACK_HOSTS: ReadonlySet<string> = new Set(['localhost', '127.0.0.1']);

/** A public client never carries a secret or a key set; any such field disqualifies the document. */
function isSecretBearingKey(key: string): boolean {
	return key === 'client_secret' || key.startsWith('client_secret_') || key === 'jwks';
}

const CimdDocumentSchema = z
	.object({
		client_id: z.string(),
		client_name: z.string().min(1).max(200),
		redirect_uris: z.array(z.string().refine(isAllowedOAuthRedirectUri)).min(1),
		token_endpoint_auth_method: z.literal('none').optional(),
	})
	.passthrough()
	.refine((doc) => !Object.keys(doc).some(isSecretBearingKey));

function parseUrl(raw: string): URL | null {
	try {
		return new URL(raw);
	} catch {
		return null;
	}
}

/**
 * True when `id` has the shape of a CIMD client_id: an https URL with a
 * non-root path and no userinfo, query or fragment, at most 512 characters.
 * (An https URL always parses with a non-empty host, so no separate check.)
 */
export function isCimdClientId(id: string): boolean {
	const url = id.length <= CIMD_CLIENT_ID_MAX_LENGTH ? parseUrl(id) : null;
	return url?.protocol === 'https:' && url.pathname !== '/' && `${url.username}${url.password}${url.search}${url.hash}` === '';
}

/** Validate a fetched document against the requested client_id and map it to a ClientRecord. */
function toClientRecord(doc: unknown, clientId: string): ClientRecord | null {
	const parsed = CimdDocumentSchema.safeParse(doc);
	if (!parsed.success || parsed.data.client_id !== clientId) return null;
	return {
		client_id: clientId,
		client_id_issued_at: Math.floor(Date.now() / 1000),
		redirect_uris: parsed.data.redirect_uris,
		client_name: parsed.data.client_name,
	};
}

async function fetchCimdClient(clientId: string): Promise<ClientRecord | null> {
	try {
		const response = await safeFetch(clientId, {
			method: 'GET',
			redirect: 'manual',
			headers: { accept: 'application/json' },
			signal: AbortSignal.timeout(CIMD_FETCH_TIMEOUT_MS),
		});
		if (response.status !== 200) {
			await disposeUnreadResponseBody(response);
			return null;
		}
		return toClientRecord(await readJsonResponseCapped<unknown>(response, CIMD_MAX_BODY_BYTES), clientId);
	} catch {
		// safeFetch throws on a blocked host; fetch rejects on a network failure or the timeout.
		return null;
	}
}

async function sha256Hex(value: string): Promise<string> {
	const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)));
	return Array.from(digest, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

/** Best-effort cache write under the client keyspace (`oauth:client:<cacheId>`, the key getClient reads). */
async function cacheCimdClient(kv: KVNamespace, cacheId: string, record: ClientRecord, kvEnvelopeKey?: Uint8Array): Promise<void> {
	const plaintext = JSON.stringify(record);
	const value = kvEnvelopeKey ? await sealKv(plaintext, kvEnvelopeKey) : plaintext;
	try {
		await kv.put(`${OAUTH_KV_PREFIX}client:${cacheId}`, value, { expirationTtl: CIMD_CACHE_TTL_SECONDS });
	} catch {
		// A failed cache write only costs a refetch on the next request.
	}
}

async function resolveCimdClient(kv: KVNamespace, clientId: string, kvEnvelopeKey?: Uint8Array): Promise<ClientRecord | null> {
	const cacheId = `cimd:${await sha256Hex(clientId)}`;
	const cached = await getClient(kv, cacheId, kvEnvelopeKey);
	if (cached?.client_id === clientId) return cached;
	const fetched = await fetchCimdClient(clientId);
	if (fetched) await cacheCimdClient(kv, cacheId, fetched, kvEnvelopeKey);
	return fetched;
}

/**
 * Resolve a client for an authorization request: a dynamically registered
 * client first, then — for a CIMD-shaped client_id — the cached or freshly
 * fetched metadata document. Returns `null` when neither yields a valid client.
 * KV outages on the registration lookup still throw StrongStateUnavailableError.
 */
export async function resolveClient(kv: KVNamespace, clientId: string, kvEnvelopeKey?: Uint8Array): Promise<ClientRecord | null> {
	const registered = await getClient(kv, clientId, kvEnvelopeKey);
	if (registered || !isCimdClientId(clientId)) return registered;
	return resolveCimdClient(kv, clientId, kvEnvelopeKey);
}

/** The URL with its port removed when the host is a loopback literal, else null. */
function withoutLoopbackPort(raw: string): string | null {
	const url = parseUrl(raw);
	if (!url || !LOOPBACK_HOSTS.has(url.hostname)) return null;
	url.port = '';
	return url.href;
}

/**
 * True when `requested` is one of the `registered` redirect URIs. Matching is
 * exact, except that a loopback redirect (localhost or 127.0.0.1) matches with
 * the port ignored, because native clients bind an ephemeral port at request
 * time (RFC 8252 section 7.3). Every other component must still match.
 */
export function redirectUriMatches(requested: string, registered: readonly string[]): boolean {
	if (registered.includes(requested)) return true;
	const loopback = withoutLoopbackPort(requested);
	return loopback !== null && registered.some((candidate) => withoutLoopbackPort(candidate) === loopback);
}
