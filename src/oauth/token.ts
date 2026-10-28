// SPDX-License-Identifier: BUSL-1.1
import type { Context } from 'hono';
import type { AppEnv } from '../index';
import { JwtBearerTokenRequestSchema, TokenRequestSchema, type JwtBearerTokenRequest } from '../schemas/oauth';
import type { EmaTenantRecord } from '../schemas/ema';
import { claimAssertionJti, consumeCode, getTokenVersion, StrongStateUnavailableError } from './storage';
import { signJwt, newJti, constantTimeEqual } from './jwt';
import { AssertionVerifyError, getJwksCached, sha256Hex, verifyJwsWithJwks, type JsonWebKeySet } from './jwks';
import { resolveClient } from './cimd';
import { getEmaTenantByIssuer, normalizeIssuer } from './ema-tenants';
import {
	isAllowedOAuthRedirectUri,
	MAX_REQUEST_BODY_BYTES,
	OAUTH_JWT_BEARER_GRANT_TYPE,
	OAUTH_JWT_CLOCK_SKEW_SECONDS,
	OAUTH_JWT_TTL_SECONDS,
	OAUTH_KV_PREFIX,
	OAUTH_SIGNING_SECRET_MIN_BYTES,
} from '../lib/config';
import { resolveIssuerStrict } from './discovery';
import { resolveClientIpFromRequestHeaders } from '../lib/client-ip';
import { parseEnvelopeKey } from '../lib/kv-envelope';
import { logEvent } from '../lib/log';
import { readBoundedText } from '../lib/request-body';
import { consumeOAuthRateLimit, type OAuthRateLimitResult } from './rate-limit';
import type { QuotaCoordinator } from '../lib/quota-coordinator';

// Fixed-window per-IP rate limit on /oauth/token. Token exchange happens once per OAuth
// flow for legitimate clients — 30/min is generous for humans and tight for attackers
// flooding invalid codes to burn KV ops. Kept local (not in lib/config.ts) per Phase 7 scope.
const TOKEN_RATE_LIMIT = 30;
const TOKEN_RATE_WINDOW_SECONDS = 60;

// jwt-bearer (EMA) exchanges leave the shared per-IP bucket above: every claude.ai exchange for
// every tenant arrives from Anthropic's small egress range, so 30/min per IP would throttle
// unrelated tenants against each other. They are limited per (client IP, claimed issuer) instead,
// with a per-IP ceiling as the abuse backstop (many issuers cannot multiply one IP's allowance).
const JWT_BEARER_ISSUER_RATE_LIMIT = 120;
const JWT_BEARER_IP_RATE_LIMIT = 600;
const JWT_BEARER_RATE_WINDOW_SECONDS = 60;
/** Issuer-bucket label for an assertion with no usable `iss`: all such requests share one bucket per IP. */
const UNUSABLE_ISSUER_BUCKET = 'invalid';

/** SQ-199/SQ-234: shared retryable body for a strong-state (KV/DO) outage on a bearer/token path. */
export const AUTH_STATE_UNAVAILABLE_BODY = {
	error: 'temporarily_unavailable',
	error_description: 'Authorization state is unavailable',
} as const;

const NO_STORE: Record<string, string> = { 'Cache-Control': 'no-store' };

// Identity Assertion JWT Authorization Grant (ID-JAG, draft-ietf-oauth-identity-assertion-authz-grant).
const ID_JAG_TYP = 'oauth-id-jag+jwt';
const ID_JAG_ALLOWED_ALGS = ['RS256', 'ES256'] as const;
const ID_JAG_MAX_LIFETIME_SECONDS = 3600;
const ID_JAG_MAX_CLAIM_LENGTH = 256;
/** Single resource scope: every jwt-bearer grant gets exactly this, whatever else was requested. */
const ID_JAG_GRANTED_SCOPE = 'mcp';
/** The one description for EVERY tenant-state rejection, so error text cannot enumerate trusted or lapsed issuers. */
const TENANT_NOT_ACCEPTED = 'Assertion not accepted';

/** A token-endpoint rejection: an RFC 6749 §5.2 error code and a STATIC description (never caller input). */
class TokenEndpointError extends Error {
	readonly code: string;
	readonly status: 400 | 500;

	constructor(code: string, description: string, status: 400 | 500 = 400) {
		super(description);
		this.name = 'TokenEndpointError';
		this.code = code;
		this.status = status;
	}
}

/** Atomically consume one token-endpoint request when the coordinator is bound. */
async function tokenRateLimit(
	kv: KVNamespace,
	ip: string,
	quotaCoordinator?: DurableObjectNamespace<QuotaCoordinator>,
): Promise<OAuthRateLimitResult> {
	return consumeOAuthRateLimit({
		kv,
		quotaCoordinator,
		coordinationScope: 'token',
		kvKey: `${OAUTH_KV_PREFIX}token-rl:${ip}`,
		principal: ip,
		limit: TOKEN_RATE_LIMIT,
		windowSeconds: TOKEN_RATE_WINDOW_SECONDS,
	});
}

/** Consume one jwt-bearer request from `principal`'s bucket (`label` namespaces the KV key and coordinator scope). */
function jwtBearerRateLimit(env: AppEnv['Bindings'], label: string, principal: string, limit: number): Promise<OAuthRateLimitResult> {
	return consumeOAuthRateLimit({
		kv: env.SESSION_STORE!,
		quotaCoordinator: env.QUOTA_COORDINATOR,
		coordinationScope: label,
		kvKey: `${OAUTH_KV_PREFIX}${label}-rl:${principal}`,
		principal,
		limit,
		windowSeconds: JWT_BEARER_RATE_WINDOW_SECONDS,
	});
}

/** The 503 (state unavailable) / 429 (exceeded) response for a rate-limit verdict, or null to proceed. */
function rateLimitResponse(c: Context<AppEnv>, verdict: OAuthRateLimitResult): Response | null {
	if (verdict.unavailable) {
		return c.json({ error: 'temporarily_unavailable', error_description: 'Token rate-limit state is unavailable' }, 503, {
			'Cache-Control': 'no-store',
			'Retry-After': String(verdict.retryAfterSeconds),
		});
	}
	if (verdict.exceeded) return c.json({ error: 'invalid_request', error_description: 'Too many token requests' }, 429);
	return null;
}

/** Decode a base64url string. Returns null on any non-base64url input rather than throwing. */
function base64UrlDecodeSafe(s: string): Uint8Array | null {
	if (!/^[A-Za-z0-9_-]*$/.test(s)) return null;
	const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
	try {
		const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + pad);
		const bytes = new Uint8Array(bin.length);
		for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
		return bytes;
	} catch {
		return null;
	}
}

/**
 * Verify an RFC 7636 PKCE challenge. Computes `SHA256(verifier)` and compares it
 * against the decoded `code_challenge` bytes in constant time. Only the S256
 * method is supported — the authorize schema rejects anything else, so `plain`
 * never reaches here.
 *
 * Exported for unit testing — callers in this module should use it directly.
 */
export async function verifyPkce(verifier: string, challenge: string): Promise<boolean> {
	const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)));
	const challengeBytes = base64UrlDecodeSafe(challenge);
	if (!challengeBytes) return false;
	return constantTimeEqual(digest, challengeBytes);
}

/**
 * Render a token-endpoint failure. A strong-state (KV/DO) outage is the shared retryable 503;
 * anything that is not a TokenEndpointError is a bug and propagates to the app error handler.
 */
function tokenErrorResponse(c: Context<AppEnv>, error: unknown, headers: Record<string, string> = {}): Response {
	if (error instanceof StrongStateUnavailableError) return c.json(AUTH_STATE_UNAVAILABLE_BODY, 503, NO_STORE);
	if (!(error instanceof TokenEndpointError)) throw error;
	return c.json({ error: error.code, error_description: error.message }, error.status, headers);
}

// Treat missing and too-short identically — the static description deliberately does not
// leak which branch failed, so an operator probing the endpoint can't fingerprint config.
function requireSigningSecret(secret: string | undefined): string {
	if (!secret || secret.length < OAUTH_SIGNING_SECRET_MIN_BYTES) {
		throw new TokenEndpointError('server_error', 'OAUTH_SIGNING_SECRET not configured', 500);
	}
	return secret;
}

// Fail closed when OAUTH_ISSUER is pinned and the request Host does not match it: refuse to
// mint a JWT whose iss/aud would embed an anomalous origin. When OAUTH_ISSUER is unset (BSL
// self-hosts) resolveIssuerStrict is a no-op and derives the issuer from the request Host, so
// self-hosters are unaffected. Cloudflare's route binding constrains Host in prod — this is the
// defense-in-depth layer behind it (security-audit item 9).
function requireStrictIssuer(requestUrl: string, configured: string | undefined): string {
	try {
		return resolveIssuerStrict(requestUrl, configured);
	} catch {
		throw new TokenEndpointError('invalid_request', 'Invalid issuer');
	}
}

// Clamp the JWT lifetime to the paid entitlement window (A01 token-persistence). The entitlement
// (epoch SECONDS — same units as the JWT iat/exp) is carried on the code record when a Stripe
// subscription gates the grant, and on the EMA tenant record for jwt-bearer. Without this clamp a
// lapsed entitlement would keep resolving to the paid tier for up to the flat short default if
// nobody calls /internal/oauth/revoke-subject. An already-passed entitlement is rejected rather
// than minted as an already-expired token.
function accessTokenTtlSeconds(entitlementExpiresAt: number | undefined): number {
	if (entitlementExpiresAt === undefined) return OAUTH_JWT_TTL_SECONDS;
	const remaining = entitlementExpiresAt - Math.floor(Date.now() / 1000);
	if (remaining <= 0) throw new TokenEndpointError('invalid_grant', 'Entitlement expired');
	return Math.min(OAUTH_JWT_TTL_SECONDS, remaining);
}

export interface MintAccessTokenOptions {
	subject: string;
	tier: 'owner' | 'developer' | 'enterprise';
	clientId: string;
	entitlementGeneration: number;
	/** Epoch SECONDS. The minted token never outlives it. */
	entitlementExpiresAt?: number;
	scope: string;
}

/**
 * Sign an access token for an already-authorized grant and render the RFC 6749 §5.1 response
 * (`Cache-Control: no-store`). Shared by every grant so the signing-secret floor, the issuer
 * pin, the entitlement clamp and the per-subject token version apply identically. The JWT is
 * bound to the resolved issuer with `${issuer}/mcp` as audience. `errorHeaders` is added to a
 * 4xx/5xx response (the jwt-bearer grant sends no-store on every response).
 */
export async function mintAccessToken(
	c: Context<AppEnv>,
	env: AppEnv['Bindings'],
	opts: MintAccessTokenOptions,
	errorHeaders: Record<string, string> = {},
): Promise<Response> {
	try {
		const secret = requireSigningSecret(env.OAUTH_SIGNING_SECRET);
		const issuer = requireStrictIssuer(c.req.url, env.OAUTH_ISSUER);
		const ttlSeconds = accessTokenTtlSeconds(opts.entitlementExpiresAt);
		// Read the current token-version for this subject so the minted JWT can be
		// invalidated before its natural expiry (FIND-13).
		const ver = await getTokenVersion(env.SESSION_STORE!, opts.subject, env.QUOTA_COORDINATOR);
		const token = await signJwt(
			{
				sub: opts.subject,
				jti: newJti(),
				tier: opts.tier,
				client_id: opts.clientId,
				ver,
				entitlementGeneration: opts.entitlementGeneration,
			},
			{ secret, ttlSeconds, issuer, audience: `${issuer}/mcp` },
		);
		return c.json({ access_token: token, token_type: 'Bearer', expires_in: ttlSeconds, scope: opts.scope }, 200, {
			'Cache-Control': 'no-store',
			Pragma: 'no-cache',
		});
	} catch (error) {
		return tokenErrorResponse(c, error, errorHeaders);
	}
}

type TokenForm = { body: Record<string, string> } | { failure: { status: 400 | 413 | 415; description: string } };

/** Enforce `application/x-www-form-urlencoded` and the body cap, then decode the form into a flat record. */
async function readTokenForm(request: Request): Promise<TokenForm> {
	const ct = request.headers.get('content-type') ?? '';
	if (!ct.toLowerCase().includes('application/x-www-form-urlencoded')) {
		return { failure: { status: 415, description: 'Content-Type must be application/x-www-form-urlencoded' } };
	}
	const bodyRead = await readBoundedText(request, MAX_REQUEST_BODY_BYTES);
	if (!bodyRead.ok) return { failure: { status: 413, description: 'Request body exceeds the configured limit' } };
	try {
		const body: Record<string, string> = {};
		new URLSearchParams(bodyRead.text).forEach((value, key) => {
			body[key] = value;
		});
		return { body };
	} catch {
		return { failure: { status: 400, description: 'Request body failed validation' } };
	}
}

/**
 * RFC 6749 §4.1.3 + RFC 7636 token endpoint, plus the RFC 7523 jwt-bearer grant for
 * Enterprise Managed Auth (see handleJwtBearerGrant). The authorization_code flow:
 *   1. Enforce `application/x-www-form-urlencoded` (415 otherwise).
 *   2. Dispatch on grant type BEFORE Zod so an unknown one surfaces the spec-correct
 *      `unsupported_grant_type` (the plan intentionally splits these two checks).
 *   3. Zod-validate the body; on failure return `invalid_request` with a static description
 *      (never echo `ZodError.message` — mirrors the Phase 4 register.ts hardening).
 *   4. Atomically consume the code via `consumeCode` (read + delete); reuse yields null and
 *      becomes `invalid_grant`. `client_id` + `redirect_uri` must both match what was bound
 *      at the authorize step.
 *   5. Verify PKCE (`S256`); mismatch → `invalid_grant`.
 *   6. Mint via mintAccessToken: `OAUTH_SIGNING_SECRET` absent → `server_error` 500; a JWT
 *      bound to the resolved issuer and `${issuer}/mcp` as audience, `Cache-Control: no-store`.
 *
 * Scope defaults to `mcp` when the original authorize request omitted one — keeps a
 * recognizable scope claim for downstream Bearer-path policy decisions (Phase 8).
 */
export async function handleToken(c: Context<AppEnv>): Promise<Response> {
	const env = c.env;
	const kv = env.SESSION_STORE!;
	const kvEnvelopeKey = parseEnvelopeKey(env.KV_ENVELOPE_KEY) ?? undefined;

	// Every request except a jwt-bearer exchange from a known IP is gated by the shared per-IP
	// bucket BEFORE any response (including the 415/413/400 body failures), so a flood of invalid
	// payloads still hits the cheap quota gate. Only the bounded body read precedes it, because the
	// grant type has to be known to choose the bucket; jwt-bearer is limited per (IP, issuer) in
	// handleJwtBearerGrant. An unknown IP (no cf-connecting-ip) keeps the shared bucket for every grant.
	const ip = resolveClientIpFromRequestHeaders(c.req.raw.headers);
	const form = await readTokenForm(c.req.raw);
	const ownBucket = 'body' in form && form.body.grant_type === OAUTH_JWT_BEARER_GRANT_TYPE && ip !== 'unknown';
	if (!ownBucket) {
		const limited = rateLimitResponse(c, await tokenRateLimit(kv, ip, env.QUOTA_COORDINATOR));
		if (limited) return limited;
	}
	if ('failure' in form) return c.json({ error: 'invalid_request', error_description: form.failure.description }, form.failure.status);
	const body = form.body;

	// grant_type dispatch runs BEFORE Zod so a wrong value surfaces the spec-correct
	// `unsupported_grant_type` error code rather than the generic `invalid_request`.
	if (body.grant_type === OAUTH_JWT_BEARER_GRANT_TYPE) {
		return handleJwtBearerGrant(c, body, kv, kvEnvelopeKey, ip);
	}
	if (body.grant_type !== 'authorization_code') {
		return c.json({ error: 'unsupported_grant_type', error_description: 'Unsupported grant_type' }, 400);
	}

	let parsed;
	try {
		parsed = TokenRequestSchema.parse(body);
	} catch {
		// Static description — never echo caller-controlled validation text (matches register.ts).
		return c.json({ error: 'invalid_request', error_description: 'Request body failed validation' }, 400);
	}

	let codeRec;
	try {
		codeRec = await consumeCode(kv, parsed.code, kvEnvelopeKey, env.QUOTA_COORDINATOR);
	} catch (error) {
		if (error instanceof StrongStateUnavailableError) {
			return c.json(AUTH_STATE_UNAVAILABLE_BODY, 503, {
				'Cache-Control': 'no-store',
			});
		}
		throw error;
	}
	if (!codeRec) {
		return c.json({ error: 'invalid_grant', error_description: 'Code unknown, expired, or already used' }, 400);
	}
	if (codeRec.client_id !== parsed.client_id) {
		return c.json({ error: 'invalid_grant', error_description: 'client_id mismatch' }, 400);
	}
	if (codeRec.redirect_uri !== parsed.redirect_uri) {
		return c.json({ error: 'invalid_grant', error_description: 'redirect_uri mismatch' }, 400);
	}
	// Revalidate at redemption so a legacy client/code minted before a redirect
	// policy hardening cannot be used to exchange an attacker-owned callback.
	if (!isAllowedOAuthRedirectUri(codeRec.redirect_uri)) {
		return c.json({ error: 'invalid_grant', error_description: 'redirect_uri not allowed' }, 400);
	}
	if (!(await verifyPkce(parsed.code_verifier, codeRec.code_challenge))) {
		return c.json({ error: 'invalid_grant', error_description: 'PKCE verification failed' }, 400);
	}

	return mintAccessToken(c, env, {
		subject: codeRec.subject ?? 'owner',
		tier: codeRec.tier ?? 'owner',
		clientId: parsed.client_id,
		entitlementGeneration: codeRec.entitlementGeneration ?? 1,
		entitlementExpiresAt: codeRec.entitlementExpiresAt,
		scope: codeRec.scope ?? 'mcp',
	});
}

// ─── RFC 7523 jwt-bearer grant (Enterprise Managed Auth) ────────────────────

/** What a validated ID-JAG authorizes: the tenant, the requesting client and the subject's digest. */
interface AcceptedIdJag {
	tenant: EmaTenantRecord;
	clientId: string;
	subjectHash: string;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** One base64url JSON-object segment of a compact JWS, or null for anything else. */
function decodeJsonSegment(segment: string): Record<string, unknown> | null {
	const bytes = base64UrlDecodeSafe(segment);
	try {
		const value: unknown = bytes ? JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(bytes)) : null;
		return isPlainObject(value) ? value : null;
	} catch {
		return null;
	}
}

function parseJwtBearerRequest(body: Record<string, string>): JwtBearerTokenRequest {
	const parsed = JwtBearerTokenRequestSchema.safeParse(body);
	if (!parsed.success) throw new TokenEndpointError('invalid_request', 'Request body failed validation');
	return parsed.data;
}

/**
 * The claims of a compact JWS whose header declares `typ: oauth-id-jag+jwt`, decoded WITHOUT
 * verifying the signature. Only routing (which tenant, which client) may read these claims;
 * every claim the grant relies on is re-read from the verified payload.
 */
function decodeIdJagUnverified(assertion: string): Record<string, unknown> {
	const parts = assertion.split('.');
	const header = parts.length === 3 ? decodeJsonSegment(parts[0]) : null;
	if (header?.typ !== ID_JAG_TYP) throw new TokenEndpointError('invalid_grant', 'Assertion must be a JWT of type oauth-id-jag+jwt');
	const claims = decodeJsonSegment(parts[1]);
	if (!claims) throw new TokenEndpointError('invalid_grant', 'Assertion must be a JWT of type oauth-id-jag+jwt');
	return claims;
}

/** A tenant lookup that cannot be read is an outage (503), never an untrusted issuer. */
async function lookupEmaTenant(kv: KVNamespace, issuer: string, kvEnvelopeKey?: Uint8Array): Promise<EmaTenantRecord | null> {
	try {
		return await getEmaTenantByIssuer(kv, issuer, kvEnvelopeKey);
	} catch {
		throw new StrongStateUnavailableError('ema tenant lookup');
	}
}

/** The enabled, in-entitlement tenant that allowlists `iss`. An unknown issuer is rejected even with a valid signature. */
async function resolveTrustedTenant(kv: KVNamespace, iss: unknown, now: number, kvEnvelopeKey?: Uint8Array): Promise<EmaTenantRecord> {
	const tenant = typeof iss === 'string' ? await lookupEmaTenant(kv, iss, kvEnvelopeKey) : null;
	// Unknown, disabled and lapsed tenants are indistinguishable to the caller (same code, same text).
	if (!tenant?.enabled || (tenant.entitlement_expires_at ?? Infinity) <= now) {
		throw new TokenEndpointError('invalid_grant', TENANT_NOT_ACCEPTED);
	}
	return tenant;
}

/** The requesting client must be allowlisted by the tenant AND resolve (registered or CIMD). */
async function assertClientAllowed(kv: KVNamespace, tenant: EmaTenantRecord, clientId: string, kvEnvelopeKey?: Uint8Array): Promise<void> {
	const allowed = tenant.allowed_client_ids.includes(clientId) && (await resolveClient(kv, clientId, kvEnvelopeKey)) !== null;
	if (!allowed) throw new TokenEndpointError('invalid_client', 'Client is not authorized for this issuer');
}

function verifyIdJag(assertion: string, jwks: JsonWebKeySet): Promise<{ claims: Record<string, unknown> }> {
	return verifyJwsWithJwks(assertion, { jwks, allowedAlgs: ID_JAG_ALLOWED_ALGS, expectedTyp: ID_JAG_TYP });
}

/**
 * Verify against the tenant JWKS, refetching it ONCE when no key matched (IdP key rotation).
 * The first fetch stays outside the retry so a fetch failure is not followed by a pointless
 * forced refetch; getJwksCached throttles forced refetches to one per URI per 60s.
 */
async function verifyWithJwksRefresh(kv: KVNamespace, jwksUri: string, assertion: string): Promise<Record<string, unknown>> {
	const jwks = await getJwksCached(kv, jwksUri);
	try {
		return (await verifyIdJag(assertion, jwks)).claims;
	} catch (error) {
		if (!(error instanceof AssertionVerifyError) || error.code !== 'no_key') throw error;
	}
	return (await verifyIdJag(assertion, await getJwksCached(kv, jwksUri, { forceRefresh: true }))).claims;
}

/** Verified claims; every signature, key or JWKS-fetch failure (all AssertionVerifyError) is invalid_grant. */
async function verifyIdJagSignature(kv: KVNamespace, jwksUri: string, assertion: string): Promise<Record<string, unknown>> {
	try {
		return await verifyWithJwksRefresh(kv, jwksUri, assertion);
	} catch (error) {
		if (error instanceof AssertionVerifyError) throw new TokenEndpointError('invalid_grant', 'Assertion signature is not valid');
		throw error;
	}
}

/** A string, or an array of EXACTLY one string, equal to `expected` (RFC 7519 §4.1.3 `aud` shape). */
function singleValueEquals(value: unknown, expected: string): boolean {
	const single = Array.isArray(value) && value.length === 1 ? value[0] : value;
	return single === expected;
}

function isBoundedString(value: unknown): value is string {
	return typeof value === 'string' && value.length > 0 && value.length <= ID_JAG_MAX_CLAIM_LENGTH;
}

/** exp/iat are integers, exp not past and iat not future (±skew), and the lifetime is at most 1h. */
function isTimeWindowValid(exp: unknown, iat: unknown, now: number): exp is number {
	if (!Number.isSafeInteger(exp) || !Number.isSafeInteger(iat)) return false;
	const [expiresAt, issuedAt] = [exp as number, iat as number];
	const fresh = expiresAt > now - OAUTH_JWT_CLOCK_SKEW_SECONDS && issuedAt <= now + OAUTH_JWT_CLOCK_SKEW_SECONDS;
	return fresh && expiresAt - issuedAt <= ID_JAG_MAX_LIFETIME_SECONDS;
}

/** Claim checks on the VERIFIED payload: audience is our issuer, the time window, and sub/jti shape. */
function validateIdJagClaims(claims: Record<string, unknown>, issuer: string, now: number): { sub: string; jti: string; exp: number } {
	const { aud, exp, iat, sub, jti } = claims;
	if (!singleValueEquals(aud, issuer)) throw new TokenEndpointError('invalid_grant', 'Assertion audience is not this server');
	if (!isTimeWindowValid(exp, iat, now)) throw new TokenEndpointError('invalid_grant', 'Assertion is expired or not yet valid');
	if (!isBoundedString(sub) || !isBoundedString(jti)) throw new TokenEndpointError('invalid_grant', 'Assertion sub or jti is invalid');
	return { sub, jti, exp };
}

/** A `resource` (request parameter or assertion claim), when present, must name this server's MCP endpoint. */
function assertResourceBinding(requested: string | undefined, claimed: unknown, mcpResource: string): void {
	const requestOk = requested === undefined || requested === mcpResource;
	const claimOk = claimed === undefined || singleValueEquals(claimed, mcpResource);
	if (!requestOk || !claimOk) throw new TokenEndpointError('invalid_target', 'Requested resource is not served by this server');
}

/** One-time use of each assertion: the issuer-scoped jti is claimed until 30s after it expires. */
async function claimAssertionOnce(issuer: string, jti: string, exp: number, quotaCoordinator?: DurableObjectNamespace<QuotaCoordinator>) {
	const claimed = await claimAssertionJti(issuer, jti, (exp + OAUTH_JWT_CLOCK_SKEW_SECONDS) * 1000, quotaCoordinator);
	if (!claimed) throw new TokenEndpointError('invalid_grant', 'Assertion has already been used');
}

/**
 * Validate an ID-JAG token request in the contract order (each step's failure is final):
 * shape + `typ` → trusted issuer → allowlisted, resolvable client → `client_id` claim →
 * signature → aud / time window / sub / jti → resource → one-time jti.
 */
async function acceptIdJag(
	c: Context<AppEnv>,
	body: Record<string, string>,
	kv: KVNamespace,
	kvEnvelopeKey?: Uint8Array,
): Promise<AcceptedIdJag> {
	const request = parseJwtBearerRequest(body);
	// Resolved first so a request on a non-canonical Host fails before any outbound fetch.
	const issuer = requireStrictIssuer(c.req.url, c.env.OAUTH_ISSUER);
	const now = Math.floor(Date.now() / 1000);
	const unverified = decodeIdJagUnverified(request.assertion);
	const tenant = await resolveTrustedTenant(kv, unverified.iss, now, kvEnvelopeKey);
	await assertClientAllowed(kv, tenant, request.client_id, kvEnvelopeKey);
	if (unverified.client_id !== request.client_id) throw new TokenEndpointError('invalid_grant', 'Assertion client_id does not match');
	const claims = await verifyIdJagSignature(kv, tenant.jwks_uri, request.assertion);
	const { sub, jti, exp } = validateIdJagClaims(claims, issuer, now);
	assertResourceBinding(request.resource, claims.resource, `${issuer}/mcp`);
	await claimAssertionOnce(tenant.issuer, jti, exp, c.env.QUOTA_COORDINATOR);
	return { tenant, clientId: request.client_id, subjectHash: await sha256Hex(sub) };
}

/** The normalized `iss` of an assertion payload read WITHOUT verification (cheap, no fetch), or a fixed bucket label. */
function claimedIssuerBucket(assertion: string | undefined): string {
	const payload = assertion?.split('.')[1];
	const iss = payload ? decodeJsonSegment(payload)?.iss : undefined;
	try {
		return typeof iss === 'string' ? normalizeIssuer(iss) : UNUSABLE_ISSUER_BUCKET;
	} catch {
		return UNUSABLE_ISSUER_BUCKET;
	}
}

/**
 * jwt-bearer rate limits for a KNOWN client IP: the per-IP ceiling first, then the (IP, claimed
 * issuer) bucket. The bucket key is a digest so an attacker-chosen `iss` cannot shape a KV key.
 * Returns the 429/503 response, or null to proceed.
 */
async function consumeJwtBearerLimits(c: Context<AppEnv>, assertion: string | undefined, ip: string): Promise<Response | null> {
	const ceiling = rateLimitResponse(c, await jwtBearerRateLimit(c.env, 'jwtb', ip, JWT_BEARER_IP_RATE_LIMIT));
	if (ceiling) return ceiling;
	const bucket = await sha256Hex(`${ip}|${claimedIssuerBucket(assertion)}`);
	return rateLimitResponse(c, await jwtBearerRateLimit(c.env, 'jwtb-iss', bucket, JWT_BEARER_ISSUER_RATE_LIMIT));
}

/** Host of a URL-shaped (CIMD) client_id for logs; an opaque DCR id is not logged. */
function clientIdHost(clientId: string): string {
	try {
		return new URL(clientId).host;
	} catch {
		return 'opaque';
	}
}

/**
 * RFC 7523 jwt-bearer grant carrying an Identity Assertion JWT Authorization Grant (ID-JAG)
 * from an Enterprise Managed Auth tenant's IdP. Validation order and error codes are pinned by
 * acceptIdJag; every response carries `Cache-Control: no-store`. The minted token's subject is
 * `ema:<tenant_id>:<32 hex of sha256(sub)>` at the tenant's tier (never owner), clamped to the
 * tenant entitlement, scope `mcp`, and NO refresh_token — the client re-exchanges a fresh
 * assertion from its IdP instead.
 */
async function handleJwtBearerGrant(
	c: Context<AppEnv>,
	body: Record<string, string>,
	kv: KVNamespace,
	kvEnvelopeKey: Uint8Array | undefined,
	ip: string,
): Promise<Response> {
	if (ip !== 'unknown') {
		const limited = await consumeJwtBearerLimits(c, body.assertion, ip);
		if (limited) return limited;
	}
	let grant: AcceptedIdJag;
	try {
		grant = await acceptIdJag(c, body, kv, kvEnvelopeKey);
	} catch (error) {
		return tokenErrorResponse(c, error, NO_STORE);
	}
	const { tenant, clientId, subjectHash } = grant;
	const response = await mintAccessToken(
		c,
		c.env,
		{
			subject: `ema:${tenant.tenant_id}:${subjectHash.slice(0, 32)}`,
			tier: tenant.tier,
			clientId,
			entitlementGeneration: 1,
			entitlementExpiresAt: tenant.entitlement_expires_at,
			scope: ID_JAG_GRANTED_SCOPE,
		},
		NO_STORE,
	);
	if (response.ok) {
		logEvent({
			timestamp: new Date().toISOString(),
			severity: 'info',
			category: 'oauth',
			result: 'ema_token_issued',
			details: { emaTenant: tenant.tenant_id, clientHost: clientIdHost(clientId), subHashPrefix: subjectHash.slice(0, 12) },
		});
	}
	return response;
}
