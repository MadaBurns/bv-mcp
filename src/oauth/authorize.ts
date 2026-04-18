// SPDX-License-Identifier: BUSL-1.1
import type { Context } from 'hono';
import { AuthorizeQuerySchema } from '../schemas/oauth';
import { getClient } from './storage';

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
