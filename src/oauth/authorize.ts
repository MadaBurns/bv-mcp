// SPDX-License-Identifier: BUSL-1.1
import type { Context } from 'hono';
import type { AppEnv } from '../index';
import { AuthorizeQuerySchema } from '../schemas/oauth';
import { createAuthorizationCode, getClient, putCode } from './storage';
import { isAuthorizedRequest } from '../lib/auth';
import {
	isAllowedOAuthRedirectUri,
	OAUTH_CONSENT_RATE_LIMIT,
	OAUTH_CONSENT_RATE_WINDOW_SECONDS,
	OAUTH_KV_PREFIX,
	parseOwnerAllowIps,
} from '../lib/config';
import { resolveClientIpFromRequestHeaders } from '../lib/client-ip';
import { parseEnvelopeKey } from '../lib/kv-envelope';
import { readBoundedText } from '../lib/request-body';
import { consumeOAuthRateLimit, type OAuthRateLimitResult } from './rate-limit';
import type { QuotaCoordinator } from '../lib/quota-coordinator';
import { resolveIssuerStrict } from './discovery';

export const MAX_CONSENT_BODY_BYTES = 16 * 1024;

function escapeHtml(s: string): string {
	return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function renderConsentPage(params: { client_id: string; client_name?: string; query: string; errorMessage?: string }): string {
	const err = params.errorMessage ? `<p class="err">${escapeHtml(params.errorMessage)}</p>` : '';
	return `<!doctype html>
<html><head>
<meta charset="utf-8"/>
<title>Authorize ${escapeHtml(params.client_name ?? params.client_id)}</title>
<style>
 body{font:14px system-ui;background:#0b0b0b;color:#eee;display:flex;justify-content:center;padding:40px}
 .card{background:#161616;border:1px solid #333;padding:24px;border-radius:8px;max-width:440px}
 input[type=password]{width:100%;padding:8px;background:#0b0b0b;color:#fff;border:1px solid #444;border-radius:4px;margin:12px 0}
 button{background:#3aa;color:#000;padding:10px 20px;border:0;border-radius:4px;cursor:pointer;font-weight:600}
 .err{color:#f77}
 code{background:#000;padding:2px 4px;border-radius:3px}
</style>
</head><body>
 <form class="card" method="POST" action="/oauth/authorize">
  <h2>Authorize Access</h2>
  <p>Client <code>${escapeHtml(params.client_name ?? params.client_id)}</code> is requesting access to your Blackveil DNS MCP server.</p>
  ${err}
  <label>Owner API key<input type="password" name="api_key" autofocus required/></label>
  <input type="hidden" name="_q" value="${escapeHtml(params.query)}"/>
  <button type="submit">Approve</button>
 </form>
</body></html>`;
}

function securityHeaders(): HeadersInit {
	return {
		'Content-Type': 'text/html; charset=utf-8',
		'X-Frame-Options': 'DENY',
		'Content-Security-Policy': "default-src 'self'; script-src 'none'; style-src 'self' 'unsafe-inline'; object-src 'none'; frame-ancestors 'none'; form-action 'self'",
		'Cache-Control': 'no-store',
		Pragma: 'no-cache',
		'Referrer-Policy': 'no-referrer',
	};
}

function ownerOAuthEnabled(env: { ENABLE_OWNER_OAUTH?: string }): boolean {
	return env.ENABLE_OWNER_OAUTH === 'true';
}

function customerOAuthNotConfigured(): Response {
	return new Response('OAuth customer login is not configured', {
		status: 503,
		headers: {
			'Content-Type': 'text/plain; charset=utf-8',
			'Cache-Control': 'no-store',
		},
	});
}

function redirectToCustomerConsent(
	consentUrl: string | undefined,
	parsed: {
		client_id: string;
		redirect_uri: string;
		response_type: 'code';
		state: string;
		scope?: string;
		code_challenge: string;
		code_challenge_method: 'S256';
	},
): Response | null {
	if (!consentUrl) return null;
	let target: URL;
	try {
		target = new URL(consentUrl);
	} catch {
		return null;
	}

	target.searchParams.set('client_id', parsed.client_id);
	target.searchParams.set('redirect_uri', parsed.redirect_uri);
	target.searchParams.set('response_type', parsed.response_type);
	target.searchParams.set('state', parsed.state);
	target.searchParams.set('code_challenge', parsed.code_challenge);
	target.searchParams.set('code_challenge_method', parsed.code_challenge_method);
	if (parsed.scope) target.searchParams.set('scope', parsed.scope);

	return Response.redirect(target.toString(), 302);
}

/**
 * Serves the consent page for an OAuth authorization request. Validates query params via
 * Zod (`AuthorizeQuerySchema`), then verifies the client exists and the supplied `redirect_uri`
 * is registered to it. On success returns HTML with restrictive security headers (CSP, frame
 * deny, no-store). On any validation or lookup failure returns a plain-text 400 — never HTML
 * and never a redirect — to avoid open-redirect risk before `redirect_uri` is trusted.
 */
export async function handleAuthorizeGet(c: Context<AppEnv>): Promise<Response> {
	const sp = new URL(c.req.url).searchParams;
	const q: Record<string, string> = {};
	sp.forEach((value, key) => {
		q[key] = value;
	});
	let parsed;
	try {
		parsed = AuthorizeQuerySchema.parse(q);
	} catch {
		// Static description — never echo caller-controlled validation text (mirrors token.ts/register.ts).
		return new Response('Invalid authorization request', { status: 400 });
	}
	const kv = c.env.SESSION_STORE!;
	const kvEnvelopeKey = parseEnvelopeKey(c.env.KV_ENVELOPE_KEY) ?? undefined;
	const client = await getClient(kv, parsed.client_id, kvEnvelopeKey);
	if (!client) return new Response('Unknown client_id', { status: 400 });
	if (!isAllowedOAuthRedirectUri(parsed.redirect_uri) || !client.redirect_uris.includes(parsed.redirect_uri)) {
		return new Response('redirect_uri not registered to this client', { status: 400 });
	}
	if (!ownerOAuthEnabled(c.env)) {
		const customerRedirect = redirectToCustomerConsent(
			c.env.BV_WEB_OAUTH_CONSENT_URL,
			parsed,
		);
		if (customerRedirect) return customerRedirect;
		return customerOAuthNotConfigured();
	}
	// Canonicalized form; Phase 6 POST handler must re-parse via URLSearchParams and re-validate with AuthorizeQuerySchema.
	const query = new URL(c.req.url).searchParams.toString();
	return new Response(renderConsentPage({ client_id: parsed.client_id, client_name: client.client_name, query }), {
		headers: securityHeaders(),
	});
}

/** Atomically consume one owner-consent attempt when the coordinator is bound. */
async function consentRateLimit(
	kv: KVNamespace,
	ip: string,
	quotaCoordinator?: DurableObjectNamespace<QuotaCoordinator>,
): Promise<OAuthRateLimitResult> {
	return consumeOAuthRateLimit({
		kv,
		quotaCoordinator,
		coordinationScope: 'consent',
		kvKey: `${OAUTH_KV_PREFIX}consent-rl:${ip}`,
		principal: ip,
		limit: OAUTH_CONSENT_RATE_LIMIT,
		windowSeconds: OAUTH_CONSENT_RATE_WINDOW_SECONDS,
	});
}

/** Redirect back to the client's registered redirect_uri with an OAuth error + state. */
function redirectWithError(redirectUri: string, error: string, state: string | undefined, issuer: string): Response {
	const u = new URL(redirectUri);
	u.searchParams.set('error', error);
	if (state) u.searchParams.set('state', state);
	u.searchParams.set('iss', issuer);
	return Response.redirect(u.toString(), 302);
}

/**
 * Handles consent form submission for `POST /oauth/authorize`. Enforces a per-IP rate limit
 * and a bounded 16 KB form body,
 * re-validates the original query via `AuthorizeQuerySchema` (from the hidden `_q` field),
 * verifies the client and registered redirect_uri, then checks the submitted owner API key
 * in constant time against `BV_API_KEY`. On success issues a single-use authorization code
 * (60s KV TTL) and 302-redirects to the client with `?code=&state=`. On wrong key redirects
 * with `?error=access_denied&state=`. Validation failures before redirect_uri is trusted
 * return plain-text 4xx — never HTML, never a redirect.
 */
export async function handleAuthorizePost(c: Context<AppEnv>): Promise<Response> {
	const kv = c.env.SESSION_STORE!;
	const kvEnvelopeKey = parseEnvelopeKey(c.env.KV_ENVELOPE_KEY) ?? undefined;
	const ip = resolveClientIpFromRequestHeaders(c.req.raw.headers);

	const consentRate = await consentRateLimit(kv, ip, c.env.QUOTA_COORDINATOR);
	if (consentRate.unavailable) {
		return new Response('Authorization rate-limit state unavailable', {
			status: 503,
			headers: { 'Cache-Control': 'no-store', 'Retry-After': String(consentRate.retryAfterSeconds) },
		});
	}
	if (consentRate.exceeded) {
		return new Response('Too many attempts. Try again later.', { status: 429 });
	}

	const ct = c.req.header('content-type') ?? '';
	if (!ct.toLowerCase().includes('application/x-www-form-urlencoded')) {
		return new Response('Unsupported content type', { status: 415 });
	}

	const bodyRead = await readBoundedText(c.req.raw, MAX_CONSENT_BODY_BYTES);
	if (!bodyRead.ok) {
		return new Response('Form body too large', { status: 413 });
	}
	const form = new URLSearchParams(bodyRead.text);
	const apiKey = form.get('api_key') ?? '';
	const qString = form.get('_q') ?? '';

	const qParams = new URLSearchParams(qString);
	const q: Record<string, string> = {};
	qParams.forEach((v, k) => {
		q[k] = v;
	});
	let parsed;
	try {
		parsed = AuthorizeQuerySchema.parse(q);
	} catch {
		// Static description — never echo caller-controlled validation text (mirrors token.ts/register.ts).
		return new Response('Invalid authorization request', { status: 400 });
	}

	const client = await getClient(kv, parsed.client_id, kvEnvelopeKey);
	if (!client) return new Response('Unknown client_id', { status: 400 });
	if (!isAllowedOAuthRedirectUri(parsed.redirect_uri) || !client.redirect_uris.includes(parsed.redirect_uri)) {
		return new Response('redirect_uri not registered to this client', { status: 400 });
	}
	let issuer: string;
	try {
		issuer = resolveIssuerStrict(c.req.url, c.env.OAUTH_ISSUER);
	} catch {
		return new Response('Invalid issuer', { status: 400 });
	}
	if (!ownerOAuthEnabled(c.env)) {
		return redirectWithError(parsed.redirect_uri, 'temporarily_unavailable', parsed.state, issuer);
	}

	// OWNER_ALLOW_IPS gate — enforced at the OAuth consent step before BV_API_KEY verification.
	// Mirrors the Bearer-path owner-tier allowlist in lib/tier-auth.ts but applied here because
	// Phase 8 trusts the minted OAuth JWT as owner tier unconditionally (no IP re-check on every
	// MCP request). If the env var is set, only allowlisted IPs may proceed; anything else
	// redirects back with `access_denied` before any code is written. When unset we retain the
	// self-hosted / dev default of no IP gating.
	const allowed = parseOwnerAllowIps(c.env.OWNER_ALLOW_IPS);
	if (allowed.length > 0 && !allowed.includes(ip)) {
		return redirectWithError(parsed.redirect_uri, 'access_denied', parsed.state, issuer);
	}

	const expected = c.env.BV_API_KEY ?? '';
	const ok = await isAuthorizedRequest(`Bearer ${apiKey}`, expected);
	if (!ok) {
		return redirectWithError(parsed.redirect_uri, 'access_denied', parsed.state, issuer);
	}

	const code = createAuthorizationCode();
	await putCode(
		kv,
		code,
		{
			client_id: parsed.client_id,
			redirect_uri: parsed.redirect_uri,
			code_challenge: parsed.code_challenge,
			issued_at: Math.floor(Date.now() / 1000),
			...(parsed.scope ? { scope: parsed.scope } : {}),
		},
		kvEnvelopeKey,
	);

	const success = new URL(parsed.redirect_uri);
	success.searchParams.set('code', code);
	if (parsed.state) success.searchParams.set('state', parsed.state);
	success.searchParams.set('iss', issuer);
	return Response.redirect(success.toString(), 302);
}
