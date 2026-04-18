// SPDX-License-Identifier: BUSL-1.1
import type { Context } from 'hono';
import { AuthorizeQuerySchema } from '../schemas/oauth';
import { getClient, putCode } from './storage';
import { isAuthorizedRequest } from '../lib/auth';
import { OAUTH_CONSENT_RATE_LIMIT, OAUTH_CONSENT_RATE_WINDOW_SECONDS, OAUTH_KV_PREFIX } from '../lib/config';

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

/**
 * Serves the consent page for an OAuth authorization request. Validates query params via
 * Zod (`AuthorizeQuerySchema`), then verifies the client exists and the supplied `redirect_uri`
 * is registered to it. On success returns HTML with restrictive security headers (CSP, frame
 * deny, no-store). On any validation or lookup failure returns a plain-text 400 — never HTML
 * and never a redirect — to avoid open-redirect risk before `redirect_uri` is trusted.
 */
export async function handleAuthorizeGet(c: Context): Promise<Response> {
	const sp = new URL(c.req.url).searchParams;
	const q: Record<string, string> = {};
	sp.forEach((value, key) => {
		q[key] = value;
	});
	let parsed;
	try {
		parsed = AuthorizeQuerySchema.parse(q);
	} catch (err) {
		return new Response(`Invalid authorization request: ${(err as Error).message}`, { status: 400 });
	}
	const kv = (c.env as { SESSION_STORE: KVNamespace }).SESSION_STORE;
	const client = await getClient(kv, parsed.client_id);
	if (!client) return new Response('Unknown client_id', { status: 400 });
	if (!client.redirect_uris.includes(parsed.redirect_uri)) {
		return new Response('redirect_uri not registered to this client', { status: 400 });
	}
	// Canonicalized form; Phase 6 POST handler must re-parse via URLSearchParams and re-validate with AuthorizeQuerySchema.
	const query = new URL(c.req.url).searchParams.toString();
	return new Response(renderConsentPage({ client_id: parsed.client_id, client_name: client.client_name, query }), {
		headers: securityHeaders(),
	});
}

/** Generate a URL-safe opaque authorization code (~32 bytes of entropy, base64url). */
function newCode(): string {
	const bytes = new Uint8Array(32);
	crypto.getRandomValues(bytes);
	let s = '';
	for (const b of bytes) s += String.fromCharCode(b);
	return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Increment and check the per-IP consent-POST rate limiter. Returns true if over the limit. */
async function consentRateExceeded(kv: KVNamespace, ip: string): Promise<boolean> {
	const key = `${OAUTH_KV_PREFIX}consent-rl:${ip}`;
	const raw = await kv.get(key);
	const count = raw ? Number(raw) || 0 : 0;
	if (count >= OAUTH_CONSENT_RATE_LIMIT) return true;
	await kv.put(key, String(count + 1), { expirationTtl: OAUTH_CONSENT_RATE_WINDOW_SECONDS });
	return false;
}

/** Redirect back to the client's registered redirect_uri with an OAuth error + state. */
function redirectWithError(redirectUri: string, error: string, state: string | undefined): Response {
	const u = new URL(redirectUri);
	u.searchParams.set('error', error);
	if (state) u.searchParams.set('state', state);
	return Response.redirect(u.toString(), 302);
}

/**
 * Handles consent form submission for `POST /oauth/authorize`. Enforces a per-IP rate limit,
 * re-validates the original query via `AuthorizeQuerySchema` (from the hidden `_q` field),
 * verifies the client and registered redirect_uri, then checks the submitted owner API key
 * in constant time against `BV_API_KEY`. On success issues a single-use authorization code
 * (60s KV TTL) and 302-redirects to the client with `?code=&state=`. On wrong key redirects
 * with `?error=access_denied&state=`. Validation failures before redirect_uri is trusted
 * return plain-text 4xx — never HTML, never a redirect.
 */
export async function handleAuthorizePost(c: Context): Promise<Response> {
	const kv = (c.env as { SESSION_STORE: KVNamespace }).SESSION_STORE;
	const ip = c.req.header('cf-connecting-ip') ?? '0.0.0.0';

	if (await consentRateExceeded(kv, ip)) {
		return new Response('Too many attempts. Try again later.', { status: 429 });
	}

	const ct = c.req.header('content-type') ?? '';
	if (!ct.toLowerCase().includes('application/x-www-form-urlencoded')) {
		return new Response('Unsupported content type', { status: 415 });
	}

	let form: FormData;
	try {
		form = await c.req.formData();
	} catch {
		return new Response('Invalid form body', { status: 400 });
	}
	const apiKey = typeof form.get('api_key') === 'string' ? (form.get('api_key') as string) : '';
	const qString = typeof form.get('_q') === 'string' ? (form.get('_q') as string) : '';

	const qParams = new URLSearchParams(qString);
	const q: Record<string, string> = {};
	qParams.forEach((v, k) => {
		q[k] = v;
	});
	let parsed;
	try {
		parsed = AuthorizeQuerySchema.parse(q);
	} catch (err) {
		return new Response(`Invalid authorization request: ${(err as Error).message}`, { status: 400 });
	}

	const client = await getClient(kv, parsed.client_id);
	if (!client) return new Response('Unknown client_id', { status: 400 });
	if (!client.redirect_uris.includes(parsed.redirect_uri)) {
		return new Response('redirect_uri not registered to this client', { status: 400 });
	}

	const expected = (c.env as { BV_API_KEY?: string }).BV_API_KEY ?? '';
	const ok = await isAuthorizedRequest(`Bearer ${apiKey}`, expected);
	if (!ok) {
		return redirectWithError(parsed.redirect_uri, 'access_denied', parsed.state);
	}

	const code = newCode();
	await putCode(kv, code, {
		client_id: parsed.client_id,
		redirect_uri: parsed.redirect_uri,
		code_challenge: parsed.code_challenge,
		issued_at: Math.floor(Date.now() / 1000),
		...(parsed.scope ? { scope: parsed.scope } : {}),
	});

	const success = new URL(parsed.redirect_uri);
	success.searchParams.set('code', code);
	if (parsed.state) success.searchParams.set('state', parsed.state);
	return Response.redirect(success.toString(), 302);
}
