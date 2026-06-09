// SPDX-License-Identifier: BUSL-1.1
import type { Context } from 'hono';
import type { AppEnv } from '../index';
import { RegisterRequestSchema } from '../schemas/oauth';
import { OAUTH_KV_PREFIX, OAUTH_REDIRECT_URI_ALLOWLIST } from '../lib/config';
import { putClient } from './storage';
import { parseEnvelopeKey } from '../lib/kv-envelope';

const MAX_BODY_BYTES = 4 * 1024;

// Per-IP fixed-window rate limits for Dynamic Client Registration.
// Legitimate DCR usage is single-digit per IP per day; 10/min absorbs retries
// without enabling client-id enumeration or KV-write abuse.
const REGISTER_MINUTE_LIMIT = 10;
const REGISTER_MINUTE_WINDOW_SECONDS = 60;
const REGISTER_HOUR_LIMIT = 30;
const REGISTER_HOUR_WINDOW_SECONDS = 3600;

/**
 * Per-IP rate-limit check for /oauth/register.
 *
 * Uses the same fixed-window KV strategy as tokenRateExceeded in token.ts:
 * the window's `expiresAt` is pinned on the first write so repeated attempts
 * cannot extend the lockout. Returns `{ exceeded: true, retryAfterSeconds }` when
 * the limit is reached.
 */
async function registerRateExceeded(kv: KVNamespace, ip: string): Promise<{ exceeded: boolean; retryAfterSeconds: number }> {
	const nowMs = Date.now();

	// --- minute window ---
	const minKey = `${OAUTH_KV_PREFIX}reg-rl:min:${ip}`;
	const minRaw = await kv.get(minKey);
	let minCount = 0;
	let minExpiresAt = nowMs + REGISTER_MINUTE_WINDOW_SECONDS * 1000;
	if (minRaw) {
		try {
			const p = JSON.parse(minRaw) as { count?: unknown; expiresAt?: unknown };
			if (typeof p.expiresAt === 'number' && p.expiresAt > nowMs) {
				minCount = typeof p.count === 'number' ? p.count : 0;
				minExpiresAt = p.expiresAt;
			}
		} catch {
			// malformed — fresh window
		}
	}
	if (minCount >= REGISTER_MINUTE_LIMIT) {
		return { exceeded: true, retryAfterSeconds: Math.max(1, Math.ceil((minExpiresAt - nowMs) / 1000)) };
	}

	// --- hour window ---
	const hrKey = `${OAUTH_KV_PREFIX}reg-rl:hr:${ip}`;
	const hrRaw = await kv.get(hrKey);
	let hrCount = 0;
	let hrExpiresAt = nowMs + REGISTER_HOUR_WINDOW_SECONDS * 1000;
	if (hrRaw) {
		try {
			const p = JSON.parse(hrRaw) as { count?: unknown; expiresAt?: unknown };
			if (typeof p.expiresAt === 'number' && p.expiresAt > nowMs) {
				hrCount = typeof p.count === 'number' ? p.count : 0;
				hrExpiresAt = p.expiresAt;
			}
		} catch {
			// malformed — fresh window
		}
	}
	if (hrCount >= REGISTER_HOUR_LIMIT) {
		return { exceeded: true, retryAfterSeconds: Math.max(1, Math.ceil((hrExpiresAt - nowMs) / 1000)) };
	}

	// Both limits clear — increment counters.
	const minTtl = Math.max(60, Math.ceil((minExpiresAt - nowMs) / 1000));
	const hrTtl = Math.max(60, Math.ceil((hrExpiresAt - nowMs) / 1000));
	await Promise.all([
		kv.put(minKey, JSON.stringify({ count: minCount + 1, expiresAt: minExpiresAt }), { expirationTtl: minTtl }),
		kv.put(hrKey, JSON.stringify({ count: hrCount + 1, expiresAt: hrExpiresAt }), { expirationTtl: hrTtl }),
	]);
	return { exceeded: false, retryAfterSeconds: 0 };
}

/**
 * RFC 7591 Dynamic Client Registration endpoint. Accepts a JSON body describing a client's
 * redirect URIs and metadata, persists the record to KV, and returns an issued `client_id`.
 * Safety: enforces `application/json` Content-Type, a 4 KB body cap, and a strict redirect
 * URI allowlist (`OAUTH_REDIRECT_URI_ALLOWLIST`) before any write. The `client_id` is a
 * UUID v4 generated via Web Crypto (`crypto.randomUUID`) — unguessable and globally unique.
 */
export async function handleRegister(c: Context<AppEnv>): Promise<Response> {
	const kv = c.env.SESSION_STORE!;
	const kvEnvelopeKey = parseEnvelopeKey(c.env.KV_ENVELOPE_KEY) ?? undefined;
	const ip = c.req.header('cf-connecting-ip') ?? '0.0.0.0';
	const rl = await registerRateExceeded(kv, ip);
	if (rl.exceeded) {
		return new Response(JSON.stringify({ error: 'too_many_requests', error_description: 'Registration rate limit exceeded' }), {
			status: 429,
			headers: {
				'Content-Type': 'application/json',
				'retry-after': String(rl.retryAfterSeconds),
			},
		});
	}

	const ct = c.req.header('content-type') ?? '';
	if (!ct.toLowerCase().includes('application/json')) {
		return c.json({ error: 'invalid_request', error_description: 'Content-Type must be application/json' }, 415);
	}
	// Pre-check Content-Length so we reject oversized bodies BEFORE materializing them into a
	// string. Without this, an attacker could force the worker to allocate an arbitrarily large
	// buffer before the 4 KB cap fired. Header may be missing on chunked transfers, in which
	// case we fall through to the post-read length check as a backstop.
	const declared = Number(c.req.header('content-length') ?? '');
	if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) {
		return c.json({ error: 'invalid_request', error_description: 'Body exceeds 4 KB' }, 413);
	}
	const raw = await c.req.raw.clone().text();
	if (new TextEncoder().encode(raw).byteLength > MAX_BODY_BYTES) {
		return c.json({ error: 'invalid_request', error_description: 'Body exceeds 4 KB' }, 413);
	}

	let parsed;
	try {
		parsed = RegisterRequestSchema.parse(JSON.parse(raw));
	} catch {
		return c.json({ error: 'invalid_client_metadata', error_description: 'Request body failed validation' }, 400);
	}

	for (const uri of parsed.redirect_uris) {
		if (!OAUTH_REDIRECT_URI_ALLOWLIST.some((re) => re.test(uri))) {
			// Static description — never echo caller-controlled validation text (matches token.ts/authorize.ts).
			return c.json({ error: 'invalid_redirect_uri', error_description: 'redirect_uri not allowed' }, 400);
		}
	}

	const client_id = crypto.randomUUID();
	const rec = {
		client_id,
		client_id_issued_at: Math.floor(Date.now() / 1000),
		redirect_uris: parsed.redirect_uris,
		client_name: parsed.client_name,
		software_id: parsed.software_id,
		software_version: parsed.software_version,
	};
	await putClient(kv, rec, kvEnvelopeKey);

	return c.json(
		{
			client_id,
			client_id_issued_at: rec.client_id_issued_at,
			redirect_uris: rec.redirect_uris,
			token_endpoint_auth_method: 'none',
			grant_types: ['authorization_code'],
			response_types: ['code'],
		},
		201,
	);
}
