// SPDX-License-Identifier: BUSL-1.1
import type { Context } from 'hono';
import type { AppEnv } from '../index';
import { RegisterRequestSchema } from '../schemas/oauth';
import { isAllowedOAuthRedirectUri, OAUTH_KV_PREFIX } from '../lib/config';
import { putClient } from './storage';
import { parseEnvelopeKey } from '../lib/kv-envelope';
import { readBoundedText } from '../lib/request-body';
import { consumeOAuthRateLimit, type OAuthRateLimitResult } from './rate-limit';
import { checkOAuthDcrBudgetWithCoordinator, type OAuthDcrBudgetResult, type QuotaCoordinator } from '../lib/quota-coordinator';

export const REGISTER_MAX_BODY_BYTES = 4 * 1024;

// Per-IP fixed-window rate limits for Dynamic Client Registration.
// Legitimate DCR usage is single-digit per IP per day; 10/min absorbs retries
// without enabling client-id enumeration or KV-write abuse.
const REGISTER_MINUTE_LIMIT = 10;
const REGISTER_MINUTE_WINDOW_SECONDS = 60;
const REGISTER_HOUR_LIMIT = 30;
const REGISTER_HOUR_WINDOW_SECONDS = 3600;

// A successful DCR creates a one-year KV record. These strong, fleet-wide
// ceilings are deliberately tighter than the request limiter: normal clients
// register once, while a distributed source-rotating attacker cannot convert
// the endpoint into unbounded persistent storage.
export const REGISTER_SOURCE_DAILY_WRITE_LIMIT = 20;
export const REGISTER_GLOBAL_HOURLY_WRITE_LIMIT = 60;
export const REGISTER_GLOBAL_DAILY_WRITE_LIMIT = 250;

function isOAuthDcrBudgetResult(value: unknown): value is OAuthDcrBudgetResult {
	if (!value || typeof value !== 'object') return false;
	const candidate = value as Partial<OAuthDcrBudgetResult>;
	return (
		typeof candidate.allowed === 'boolean' &&
		(candidate.retryAfterMs === undefined || (Number.isSafeInteger(candidate.retryAfterMs) && (candidate.retryAfterMs as number) >= 0))
	);
}

async function sourceFingerprint(source: string): Promise<string> {
	const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(source));
	return Array.from(new Uint8Array(digest))
		.map((byte) => byte.toString(16).padStart(2, '0'))
		.join('');
}

/** Reserve the persistent-write budgets. Missing/malformed strong state fails closed. */
async function registerWriteRateExceeded(
	ip: string,
	quotaCoordinator?: DurableObjectNamespace<QuotaCoordinator>,
): Promise<OAuthRateLimitResult> {
	if (!quotaCoordinator) return { exceeded: true, retryAfterSeconds: 60, unavailable: true };
	try {
		const result = await checkOAuthDcrBudgetWithCoordinator(
			await sourceFingerprint(ip),
			{
				sourceDailyLimit: REGISTER_SOURCE_DAILY_WRITE_LIMIT,
				globalHourlyLimit: REGISTER_GLOBAL_HOURLY_WRITE_LIMIT,
				globalDailyLimit: REGISTER_GLOBAL_DAILY_WRITE_LIMIT,
			},
			quotaCoordinator,
		);
		if (!isOAuthDcrBudgetResult(result)) {
			return { exceeded: true, retryAfterSeconds: 60, unavailable: true };
		}
		return {
			exceeded: !result.allowed,
			retryAfterSeconds: result.allowed ? 0 : Math.max(1, Math.ceil((result.retryAfterMs ?? 60_000) / 1000)),
		};
	} catch {
		return { exceeded: true, retryAfterSeconds: 60, unavailable: true };
	}
}

/** Atomically enforce both registration windows when the coordinator is bound. */
async function registerRateExceeded(
	kv: KVNamespace,
	ip: string,
	quotaCoordinator?: DurableObjectNamespace<QuotaCoordinator>,
): Promise<OAuthRateLimitResult> {
	const minute = await consumeOAuthRateLimit({
		kv,
		quotaCoordinator,
		coordinationScope: 'register:min',
		kvKey: `${OAUTH_KV_PREFIX}reg-rl:min:${ip}`,
		principal: ip,
		limit: REGISTER_MINUTE_LIMIT,
		windowSeconds: REGISTER_MINUTE_WINDOW_SECONDS,
	});
	if (minute.exceeded || minute.unavailable) return minute;

	return consumeOAuthRateLimit({
		kv,
		quotaCoordinator,
		coordinationScope: 'register:hour',
		kvKey: `${OAUTH_KV_PREFIX}reg-rl:hr:${ip}`,
		principal: ip,
		limit: REGISTER_HOUR_LIMIT,
		windowSeconds: REGISTER_HOUR_WINDOW_SECONDS,
	});
}

/**
 * RFC 7591 Dynamic Client Registration endpoint. Accepts a JSON body describing a client's
 * redirect URIs and metadata, persists the record to KV, and returns an issued `client_id`.
 * Safety: enforces `application/json` Content-Type, a 4 KB body cap, and a strict redirect
 * parsed URL-component allowlist before any write. The `client_id` is a
 * UUID v4 generated via Web Crypto (`crypto.randomUUID`) — unguessable and globally unique.
 */
export async function handleRegister(c: Context<AppEnv>): Promise<Response> {
	const kv = c.env.SESSION_STORE!;
	const kvEnvelopeKey = parseEnvelopeKey(c.env.KV_ENVELOPE_KEY) ?? undefined;
	const ip = c.req.header('cf-connecting-ip') ?? '0.0.0.0';
	const rl = await registerRateExceeded(kv, ip, c.env.QUOTA_COORDINATOR);
	if (rl.unavailable) {
		return c.json({ error: 'temporarily_unavailable', error_description: 'Registration rate-limit state is unavailable' }, 503, {
			'Cache-Control': 'no-store',
			'Retry-After': String(rl.retryAfterSeconds),
		});
	}
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
	// Content-Length is only an early-rejection hint inside the bounded reader. The stream byte
	// count remains authoritative for chunked, compressed, or inaccurately declared requests.
	const bodyRead = await readBoundedText(c.req.raw, REGISTER_MAX_BODY_BYTES);
	if (!bodyRead.ok) {
		return c.json({ error: 'invalid_request', error_description: 'Body exceeds 4 KB' }, 413);
	}
	const raw = bodyRead.text;

	let parsed;
	try {
		parsed = RegisterRequestSchema.parse(JSON.parse(raw));
	} catch {
		return c.json({ error: 'invalid_client_metadata', error_description: 'Request body failed validation' }, 400);
	}

	for (const uri of parsed.redirect_uris) {
		if (!isAllowedOAuthRedirectUri(uri)) {
			// Static description — never echo caller-controlled validation text (matches token.ts/authorize.ts).
			return c.json({ error: 'invalid_redirect_uri', error_description: 'redirect_uri not allowed' }, 400);
		}
	}

	// Only validated registrations consume the persistent-write ceiling. The
	// existing minute/hour request limiter above still bounds malformed traffic.
	const writeBudget = await registerWriteRateExceeded(ip, c.env.QUOTA_COORDINATOR);
	if (writeBudget.unavailable) {
		return c.json({ error: 'temporarily_unavailable', error_description: 'Registration write-budget state is unavailable' }, 503, {
			'Cache-Control': 'no-store',
			'Retry-After': String(writeBudget.retryAfterSeconds),
		});
	}
	if (writeBudget.exceeded) {
		return c.json({ error: 'too_many_requests', error_description: 'Registration rate limit exceeded' }, 429, {
			'Cache-Control': 'no-store',
			'Retry-After': String(writeBudget.retryAfterSeconds),
		});
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
