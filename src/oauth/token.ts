// SPDX-License-Identifier: BUSL-1.1
import type { Context } from 'hono';
import { TokenRequestSchema } from '../schemas/oauth';
import { consumeCode } from './storage';
import { signJwt, newJti } from './jwt';
import { OAUTH_JWT_TTL_SECONDS, OAUTH_KV_PREFIX } from '../lib/config';
import { resolveIssuer } from './discovery';

// HS256 security floor: RFC 7518 §3.2 requires a key at least as long as the hash
// output (256 bits = 32 bytes). An operator deploying with `OAUTH_SIGNING_SECRET=x`
// would otherwise happily mint tokens that are trivial to forge.
const OAUTH_SIGNING_SECRET_MIN_BYTES = 32;

// Fixed-window per-IP rate limit on /oauth/token. Token exchange happens once per OAuth
// flow for legitimate clients — 30/min is generous for humans and tight for attackers
// flooding invalid codes to burn KV ops. Kept local (not in lib/config.ts) per Phase 7 scope.
const TOKEN_RATE_LIMIT = 30;
const TOKEN_RATE_WINDOW_SECONDS = 60;

/**
 * Increment and check the per-IP token-endpoint rate limiter. Returns true if over the limit.
 *
 * Mirrors `consentRateExceeded` in authorize.ts: FIXED window keyed on `expiresAt`, pinned
 * by the first write and preserved across subsequent increments so a stream of attempts
 * cannot extend a lockout indefinitely (which is what naive `expirationTtl`-refresh would do).
 */
async function tokenRateExceeded(kv: KVNamespace, ip: string): Promise<boolean> {
	const key = `${OAUTH_KV_PREFIX}token-rl:${ip}`;
	const nowMs = Date.now();
	const raw = await kv.get(key);

	let count = 0;
	let expiresAt = nowMs + TOKEN_RATE_WINDOW_SECONDS * 1000;
	if (raw) {
		try {
			const parsed = JSON.parse(raw) as { count?: unknown; expiresAt?: unknown };
			if (typeof parsed.expiresAt === 'number' && parsed.expiresAt > nowMs) {
				count = typeof parsed.count === 'number' ? parsed.count : 0;
				expiresAt = parsed.expiresAt;
			}
		} catch {
			// Malformed — start a fresh window.
		}
	}

	if (count >= TOKEN_RATE_LIMIT) return true;

	const next = { count: count + 1, expiresAt };
	// CF KV minimum TTL is 60s; `expiresAt` is authoritative for window correctness.
	const ttl = Math.max(60, Math.ceil((expiresAt - nowMs) / 1000));
	await kv.put(key, JSON.stringify(next), { expirationTtl: ttl });
	return false;
}

function base64url(buf: ArrayBuffer): string {
	const b = new Uint8Array(buf);
	let s = '';
	for (const x of b) s += String.fromCharCode(x);
	return btoa(s).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

/**
 * Verify an RFC 7636 PKCE challenge. Computes `BASE64URL(SHA256(verifier))` and compares it
 * against the `code_challenge` captured at the authorize step. Only the S256 method is
 * supported — the authorize schema rejects anything else, so `plain` never reaches here.
 */
async function verifyPkce(verifier: string, challenge: string): Promise<boolean> {
	const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
	return base64url(digest) === challenge;
}

/**
 * RFC 6749 §4.1.3 + RFC 7636 token endpoint. Exchanges a one-time authorization code for a
 * signed JWT access token. Flow:
 *   1. Enforce `application/x-www-form-urlencoded` (415 otherwise).
 *   2. Reject unsupported grant types early with `unsupported_grant_type` (before Zod so the
 *      correct OAuth error code surfaces — the plan intentionally splits these two checks).
 *   3. Zod-validate the body; on failure return `invalid_request` with a static description
 *      (never echo `ZodError.message` — mirrors the Phase 4 register.ts hardening).
 *   4. Atomically consume the code via `consumeCode` (read + delete); reuse yields null and
 *      becomes `invalid_grant`. `client_id` + `redirect_uri` must both match what was bound
 *      at the authorize step.
 *   5. Verify PKCE (`S256`); mismatch → `invalid_grant`.
 *   6. Require `OAUTH_SIGNING_SECRET`; absent → `server_error` 500.
 *   7. Sign a JWT bound to the resolved issuer and `${issuer}/mcp` as audience, return with
 *      `Cache-Control: no-store` per RFC 6749 §5.1.
 *
 * Scope defaults to `mcp` when the original authorize request omitted one — keeps a
 * recognizable scope claim for downstream Bearer-path policy decisions (Phase 8).
 */
export async function handleToken(c: Context): Promise<Response> {
	const env = c.env as { SESSION_STORE: KVNamespace; OAUTH_SIGNING_SECRET?: string; OAUTH_ISSUER?: string };

	// Rate limit runs FIRST — before content-type / grant-type / Zod — so an attacker
	// flooding the endpoint with invalid payloads still hits the cheap KV gate.
	const ip = c.req.header('cf-connecting-ip') ?? 'unknown';
	if (await tokenRateExceeded(env.SESSION_STORE, ip)) {
		return c.json({ error: 'invalid_request', error_description: 'Too many token requests' }, 429);
	}

	const ct = c.req.header('content-type') ?? '';
	if (!ct.toLowerCase().includes('application/x-www-form-urlencoded')) {
		return c.json({ error: 'invalid_request', error_description: 'Content-Type must be application/x-www-form-urlencoded' }, 415);
	}
	const params = new URLSearchParams(await c.req.raw.clone().text());
	const body: Record<string, string> = {};
	params.forEach((v, k) => {
		body[k] = v;
	});

	// grant_type check runs BEFORE Zod so a wrong value surfaces the spec-correct
	// `unsupported_grant_type` error code rather than the generic `invalid_request`.
	if (body.grant_type !== 'authorization_code') {
		return c.json({ error: 'unsupported_grant_type', error_description: 'Only authorization_code is supported' }, 400);
	}

	let parsed;
	try {
		parsed = TokenRequestSchema.parse(body);
	} catch {
		// Static description — never echo caller-controlled validation text (matches register.ts).
		return c.json({ error: 'invalid_request', error_description: 'Request body failed validation' }, 400);
	}

	const codeRec = await consumeCode(env.SESSION_STORE, parsed.code);
	if (!codeRec) {
		return c.json({ error: 'invalid_grant', error_description: 'Code unknown, expired, or already used' }, 400);
	}
	if (codeRec.client_id !== parsed.client_id) {
		return c.json({ error: 'invalid_grant', error_description: 'client_id mismatch' }, 400);
	}
	if (codeRec.redirect_uri !== parsed.redirect_uri) {
		return c.json({ error: 'invalid_grant', error_description: 'redirect_uri mismatch' }, 400);
	}
	if (!(await verifyPkce(parsed.code_verifier, codeRec.code_challenge))) {
		return c.json({ error: 'invalid_grant', error_description: 'PKCE verification failed' }, 400);
	}

	const secret = env.OAUTH_SIGNING_SECRET;
	// Treat missing and too-short identically — the static description deliberately does not
	// leak which branch failed, so an operator probing the endpoint can't fingerprint config.
	if (!secret || secret.length < OAUTH_SIGNING_SECRET_MIN_BYTES) {
		return c.json({ error: 'server_error', error_description: 'OAUTH_SIGNING_SECRET not configured' }, 500);
	}

	const issuer = resolveIssuer(c.req.url, env.OAUTH_ISSUER);
	// `sub` and `tier` are hard-coded to `owner` because the only consent path today is
	// BV_API_KEY, and Phase 6 enforces the OWNER_ALLOW_IPS allowlist before a code is issued.
	// Phase 8 wires this claim into lib/tier-auth::resolveTier so the JWT grants owner tier
	// on /mcp without re-checking the IP (consent already did). When Phase 9+ adds tiered or
	// email-based consent, thread the authenticated identity through CodeRecord and bind it
	// here instead of the static literal.
	const token = await signJwt(
		{ sub: 'owner', jti: newJti(), tier: 'owner', client_id: parsed.client_id },
		{ secret, ttlSeconds: OAUTH_JWT_TTL_SECONDS, issuer, audience: `${issuer}/mcp` },
	);

	return c.json(
		{
			access_token: token,
			token_type: 'Bearer',
			expires_in: OAUTH_JWT_TTL_SECONDS,
			scope: codeRec.scope ?? 'mcp',
		},
		200,
		{ 'Cache-Control': 'no-store', Pragma: 'no-cache' },
	);
}
