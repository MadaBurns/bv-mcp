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
import { isAllowedOAuthRedirectUri } from '../lib/config';
import type { QuotaCoordinator } from '../lib/quota-coordinator';
import { disposeUnreadResponseBody, readJsonResponseCapped } from '../lib/response-body';
import { safeFetch } from '../lib/safe-fetch';
import type { ClientRecord } from '../schemas/oauth';
import { consumeCimdFetchRateLimit } from './rate-limit';
import { getCachedCimdClient, getClient, hasCimdFetchFailure, putCachedCimdClient, putCimdFetchFailure } from './storage';

export const CLAUDE_WEB_CIMD_CLIENT_ID = 'https://claude.ai/oauth/mcp-oauth-client-metadata';
export const CLAUDE_CODE_CIMD_CLIENT_ID = 'https://claude.ai/oauth/claude-code-client-metadata';

const CIMD_CLIENT_ID_MAX_LENGTH = 512;
const CIMD_CACHE_TTL_SECONDS = 60 * 60;
const CIMD_FAILURE_TTL_SECONDS = 60; // KV's minimum expirationTtl
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
 * non-root path, no explicit port (a custom port turns the fetch into a port
 * oracle against public hosts) and no userinfo, query or fragment, at most 512
 * characters. (An https URL always parses with a non-empty host, so no separate check.)
 */
export function isCimdClientId(id: string): boolean {
	const url = id.length <= CIMD_CLIENT_ID_MAX_LENGTH ? parseUrl(id) : null;
	return url?.protocol === 'https:' && url.pathname !== '/' && `${url.port}${url.username}${url.password}${url.search}${url.hash}` === '';
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

/** Optional per-request context for `resolveClient`; omitting it keeps the original (unthrottled) behavior. */
export interface ResolveClientOptions {
	/** Client IP, the principal for the cache-miss fetch limit. Without it no per-IP limit applies. */
	ip?: string;
	/** Strongly consistent counter backing the limit; without it the KV window fallback is used. */
	quotaCoordinator?: DurableObjectNamespace<QuotaCoordinator>;
}

/**
 * True when a cache miss must NOT fetch: a recent failure is negatively cached, or the IP is over its fetch limit.
 * A cache miss costs an outbound request to a caller-named host, hence the per-IP limit; a limiter fault denies too.
 */
async function fetchBlocked(kv: KVNamespace, urlHash: string, options: ResolveClientOptions): Promise<boolean> {
	if (await hasCimdFetchFailure(kv, urlHash)) return true;
	if (options.ip === undefined) return false;
	return (await consumeCimdFetchRateLimit(kv, options.ip, options.quotaCoordinator)).exceeded;
}

/**
 * Cached record, else (unless a recent failure is cached or the IP is over its fetch limit) a fresh fetch.
 * A fetch failure is negatively cached for 60s so a hostile client_id cannot drive a fetch per request;
 * a throttled or limiter-denied request fetches nothing and caches nothing.
 */
async function resolveCimdClient(
	kv: KVNamespace,
	clientId: string,
	kvEnvelopeKey: Uint8Array | undefined,
	options: ResolveClientOptions,
): Promise<ClientRecord | null> {
	const urlHash = await sha256Hex(clientId);
	const cached = await getCachedCimdClient(kv, urlHash, kvEnvelopeKey);
	if (cached?.client_id === clientId) return cached;
	if (await fetchBlocked(kv, urlHash, options)) return null;
	const fetched = await fetchCimdClient(clientId);
	if (fetched) await putCachedCimdClient(kv, urlHash, fetched, CIMD_CACHE_TTL_SECONDS, kvEnvelopeKey);
	else await putCimdFetchFailure(kv, urlHash, CIMD_FAILURE_TTL_SECONDS);
	return fetched;
}

/**
 * Resolve a client for an authorization request: a dynamically registered
 * client first, then — for a CIMD-shaped client_id — the cached or freshly
 * fetched metadata document. Returns `null` when neither yields a valid client.
 * KV outages on the registration lookup still throw StrongStateUnavailableError.
 */
export async function resolveClient(
	kv: KVNamespace,
	clientId: string,
	kvEnvelopeKey?: Uint8Array,
	options: ResolveClientOptions = {},
): Promise<ClientRecord | null> {
	const registered = await getClient(kv, clientId, kvEnvelopeKey);
	if (registered || !isCimdClientId(clientId)) return registered;
	return resolveCimdClient(kv, clientId, kvEnvelopeKey, options);
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
