// SPDX-License-Identifier: BUSL-1.1

/**
 * Internal Service Binding Routes
 *
 * Provides a direct, low-overhead path to tool handlers for Cloudflare
 * service bindings (e.g., other Workers in the same account). Bypasses
 * all public-facing middleware: CORS, authentication, rate limiting,
 * session management, and JSON-RPC framing.
 *
 * **Security model:** Service binding requests are internal to the
 * Cloudflare network and never carry a `cf-connecting-ip` header.
 * The guard middleware rejects any request with that header, ensuring
 * this route is unreachable from the public internet.
 *
 * **Usage from a consuming Worker:**
 * ```typescript
 * // wrangler.jsonc — add service binding
 * // { "services": [{ "binding": "BV_MCP", "service": "bv-dns-security-mcp" }] }
 *
 * const response = await env.BV_MCP.fetch(
 *   new Request('https://internal/internal/tools/call', {
 *     method: 'POST',
 *     headers: { 'Content-Type': 'application/json' },
 *     body: JSON.stringify({ name: 'scan_domain', arguments: { domain: 'example.com' } }),
 *   })
 * );
 * const result = await response.json();
 * ```
 */

import { Hono } from 'hono';
import { ZodError } from 'zod';
import { handleToolsCall } from './handlers/tools';
import { createAnalyticsClient } from './lib/analytics';
import { parseScoringConfigCached } from './lib/scoring-config';
import { parseCacheTtl } from './lib/config';
import { validateDomain, sanitizeDomain } from './lib/sanitize';
import { InternalToolCallSchema, BatchRequestSchema, CreateTrialKeyRequestSchema } from './schemas/internal';
import { createTrialKey, getTrialKeyStatus, revokeTrialKey, listTrialKeys } from './lib/trial-keys';
import { queryAnalyticsEngine } from './lib/analytics-engine';
import {
	queryTierToolUsage,
	queryTierLatency,
	queryTierErrorRate,
	queryTierCachePerformance,
	queryTierRateLimits,
	queryTierSessions,
	queryTierDailyTrend,
	queryTierTopTools,
	queryKeyUsage,
	queryTierDigest,
} from './lib/analytics-queries';

type InternalEnv = {
	SCAN_CACHE?: KVNamespace;
	RATE_LIMIT?: KVNamespace;
	PROFILE_ACCUMULATOR?: DurableObjectNamespace;
	MCP_ANALYTICS?: AnalyticsEngineDataset;
	PROVIDER_SIGNATURES_URL?: string;
	PROVIDER_SIGNATURES_ALLOWED_HOSTS?: string;
	PROVIDER_SIGNATURES_SHA256?: string;
	SCORING_CONFIG?: string;
	CACHE_TTL_SECONDS?: string;
	BV_DOH_ENDPOINT?: string;
	BV_DOH_TOKEN?: string;
	CF_ACCOUNT_ID?: string;
	CF_ANALYTICS_TOKEN?: string;
};

export const internalRoutes = new Hono<{ Bindings: InternalEnv }>();

/**
 * Guard: reject requests from the public internet.
 *
 * Cloudflare sets `cf-connecting-ip` on every request that arrives
 * via the public internet. Service binding calls are Worker-to-Worker
 * over Cloudflare's internal network and never carry this header.
 *
 * If the header is present, the request came from the internet —
 * return 404 to make the route invisible.
 */
internalRoutes.use('*', async (c, next) => {
	if (c.req.header('cf-connecting-ip')) {
		return c.json({ error: 'Not found' }, 404);
	}
	return next();
});

/**
 * POST /internal/tools/call
 *
 * Direct tool invocation without MCP protocol overhead.
 *
 * Request body: { "name": string, "arguments"?: Record<string, unknown> }
 * Response body: { "content": McpContent[], "isError"?: boolean }
 */
internalRoutes.post('/tools/call', async (c) => {
	let body: { name: string; arguments?: Record<string, unknown> };
	try {
		const raw = await c.req.json();
		body = InternalToolCallSchema.parse(raw);
	} catch (err) {
		if (err instanceof ZodError) {
			return c.json({ content: [{ type: 'text', text: `Invalid ${err.issues[0].path.join('.')}: ${err.issues[0].message}` }], isError: true }, 400);
		}
		return c.json({ content: [{ type: 'text', text: 'Missing required field: name' }], isError: true }, 400);
	}

	const url = new URL(c.req.url);
	const wantStructured = url.searchParams.get('format') === 'structured';

	let capturedResult: import('./lib/scoring-model').CheckResult | null = null;

	const cacheTtlSeconds = parseCacheTtl(c.env.CACHE_TTL_SECONDS);

	const result = await handleToolsCall(
		{ name: body.name, arguments: body.arguments },
		c.env.SCAN_CACHE,
		{
			providerSignaturesUrl: c.env.PROVIDER_SIGNATURES_URL,
			providerSignaturesAllowedHosts: c.env.PROVIDER_SIGNATURES_ALLOWED_HOSTS?.split(',')
				.map((h) => h.trim())
				.filter(Boolean),
			providerSignaturesSha256: c.env.PROVIDER_SIGNATURES_SHA256,
			analytics: createAnalyticsClient(c.env.MCP_ANALYTICS),
			profileAccumulator: c.env.PROFILE_ACCUMULATOR,
			waitUntil: (promise: Promise<unknown>) => c.executionCtx.waitUntil(promise),
			scoringConfig: parseScoringConfigCached(c.env.SCORING_CONFIG),
			cacheTtlSeconds,
			secondaryDoh: c.env.BV_DOH_ENDPOINT
				? { endpoint: c.env.BV_DOH_ENDPOINT, token: c.env.BV_DOH_TOKEN }
				: undefined,
			...(wantStructured ? { resultCapture: (r: import('./lib/scoring-model').CheckResult) => { capturedResult = r; } } : {}),
		},
	);

	// If structured format was requested and a CheckResult was captured (TOOL_REGISTRY tools only),
	// return the raw result instead of MCP-framed text.
	if (wantStructured && capturedResult !== null) {
		return c.json({ result: capturedResult, isError: result.isError ?? false });
	}

	return c.json(result);
});

/** Default concurrency for batch endpoint. */
const BATCH_DEFAULT_CONCURRENCY = 10;

/** Maximum request body size for batch endpoint (256 KB). */
const BATCH_MAX_BODY_BYTES = 262_144;

/**
 * POST /internal/tools/batch
 *
 * Batch tool invocation for bulk domain scanning.
 * Executes the same tool across multiple domains with controlled concurrency.
 *
 * Request body:
 *   { "domains": string[], "tool"?: string, "arguments"?: Record<string, unknown>, "concurrency"?: number }
 *
 * - `tool` defaults to "scan_domain"
 * - `arguments` are merged with `{ domain }` for each invocation
 * - `concurrency` controls parallelism (default 10, max 50)
 *
 * Query params: `?format=structured` returns raw CheckResult per domain
 *
 * Response body:
 *   { "results": Array<{ domain: string, result: unknown, isError: boolean }>, "summary": { total, succeeded, failed } }
 */
internalRoutes.post('/tools/batch', async (c) => {
	const raw = await c.req.text();
	if (raw.length > BATCH_MAX_BODY_BYTES) {
		return c.json({ error: `Request body exceeds maximum of ${BATCH_MAX_BODY_BYTES} bytes` }, 413);
	}

	let body: { tool: string; domains: string[]; arguments?: Record<string, unknown>; concurrency?: number };
	try {
		const parsed = JSON.parse(raw);
		body = BatchRequestSchema.parse(parsed);
	} catch (err) {
		if (err instanceof ZodError) {
			return c.json({ error: `Invalid ${err.issues[0].path.join('.')}: ${err.issues[0].message}` }, 400);
		}
		return c.json({ error: 'Invalid request body' }, 400);
	}

	const toolName = body.tool;
	const rawArgs = body.arguments ?? {};
	// ALLOWED_BATCH_ARGS filtering stays (security allowlist, not shape validation)
	const ALLOWED_BATCH_ARGS = new Set(['format', 'profile', 'force_refresh', 'selector', 'record_type', 'include_providers', 'mx_hosts']);
	const extraArgs: Record<string, unknown> = {};
	for (const [k, v] of Object.entries(rawArgs)) {
		if (ALLOWED_BATCH_ARGS.has(k)) extraArgs[k] = v;
	}
	const concurrency = body.concurrency ?? BATCH_DEFAULT_CONCURRENCY;

	const url = new URL(c.req.url);
	const wantStructured = url.searchParams.get('format') === 'structured';

	const cacheTtlSeconds = parseCacheTtl(c.env.CACHE_TTL_SECONDS);

	// Validate all domains upfront
	const validatedDomains: { input: string; sanitized: string | null; error?: string }[] = body.domains.map((d) => {
		if (typeof d !== 'string') return { input: String(d), sanitized: null, error: 'Invalid domain: not a string' };
		const validation = validateDomain(d);
		if (!validation.valid) return { input: d, sanitized: null, error: validation.error ?? 'Invalid domain' };
		const sanitized = sanitizeDomain(d);
		if (!sanitized) return { input: d, sanitized: null, error: 'Invalid domain after sanitization' };
		return { input: d, sanitized };
	});

	const results: { domain: string; result: unknown; isError: boolean }[] = [];
	let succeeded = 0;
	let failed = 0;

	// Process in batches with controlled concurrency
	const validEntries = validatedDomains.filter((v) => v.sanitized !== null);
	const invalidEntries = validatedDomains.filter((v) => v.sanitized === null);

	// Add validation failures immediately
	for (const entry of invalidEntries) {
		results.push({ domain: entry.input, result: { error: entry.error }, isError: true });
		failed++;
	}

	// Process valid domains in concurrent chunks
	for (let i = 0; i < validEntries.length; i += concurrency) {
		const chunk = validEntries.slice(i, i + concurrency);
		const chunkResults = await Promise.allSettled(
			chunk.map(async (entry) => {
				let capturedResult: import('./lib/scoring-model').CheckResult | null = null;

				const toolResult = await handleToolsCall(
					{ name: toolName, arguments: { ...extraArgs, domain: entry.sanitized } },
					c.env.SCAN_CACHE,
					{
						providerSignaturesUrl: c.env.PROVIDER_SIGNATURES_URL,
						providerSignaturesAllowedHosts: c.env.PROVIDER_SIGNATURES_ALLOWED_HOSTS?.split(',')
							.map((h) => h.trim())
							.filter(Boolean),
						providerSignaturesSha256: c.env.PROVIDER_SIGNATURES_SHA256,
						analytics: createAnalyticsClient(c.env.MCP_ANALYTICS),
						profileAccumulator: c.env.PROFILE_ACCUMULATOR,
						waitUntil: (promise: Promise<unknown>) => c.executionCtx.waitUntil(promise),
						scoringConfig: parseScoringConfigCached(c.env.SCORING_CONFIG),
						cacheTtlSeconds,
						secondaryDoh: c.env.BV_DOH_ENDPOINT
							? { endpoint: c.env.BV_DOH_ENDPOINT, token: c.env.BV_DOH_TOKEN }
							: undefined,
						...(wantStructured ? { resultCapture: (r: import('./lib/scoring-model').CheckResult) => { capturedResult = r; } } : {}),
					},
				);

				const isError = toolResult.isError ?? false;
				const result = wantStructured && capturedResult !== null ? capturedResult : toolResult;
				return { domain: entry.input, result, isError };
			}),
		);

		for (const settled of chunkResults) {
			if (settled.status === 'fulfilled') {
				results.push(settled.value);
				if (settled.value.isError) failed++;
				else succeeded++;
			} else {
				// Should not happen since handleToolsCall catches errors, but safety net
				const domain = chunk[chunkResults.indexOf(settled)]?.input ?? 'unknown';
				results.push({ domain, result: { error: 'Internal error' }, isError: true });
				failed++;
			}
		}
	}

	return c.json({
		results,
		summary: { total: body.domains.length, succeeded, failed },
	});
});

// ---------------------------------------------------------------------------
// Trial API Key Management
// ---------------------------------------------------------------------------

/**
 * POST /internal/trial-keys
 *
 * Create a new trial API key. Returns the raw key (shown once) and metadata.
 *
 * Request body: { "label": string, "tier"?: Tier, "expiresInDays"?: number, "maxUses"?: number }
 * Response body: { "key": string, "hash": string, "tier": string, "expiresAt": number, "maxUses": number }
 */
internalRoutes.post('/trial-keys', async (c) => {
	if (!c.env.RATE_LIMIT) {
		return c.json({ error: 'RATE_LIMIT KV namespace not configured' }, 500);
	}

	let body: { label: string; tier?: string; expiresInDays?: number; maxUses?: number };
	try {
		const raw = await c.req.json();
		body = CreateTrialKeyRequestSchema.parse(raw);
	} catch (err) {
		if (err instanceof ZodError) {
			return c.json({ error: `Invalid ${err.issues[0].path.join('.')}: ${err.issues[0].message}` }, 400);
		}
		return c.json({ error: 'Invalid request body' }, 400);
	}

	const result = await createTrialKey(c.env.RATE_LIMIT, {
		label: body.label,
		tier: body.tier as import('./lib/config').McpApiKeyTier | undefined,
		expiresInDays: body.expiresInDays,
		maxUses: body.maxUses,
	});

	return c.json({
		key: result.rawKey,
		hash: result.hash,
		tier: result.record.tier,
		expiresAt: result.record.expiresAt,
		maxUses: result.record.maxUses,
		label: result.record.label,
	});
});

/**
 * GET /internal/trial-keys/:hash
 *
 * Get the current status of a trial key by its hash.
 */
internalRoutes.get('/trial-keys/:hash', async (c) => {
	if (!c.env.RATE_LIMIT) {
		return c.json({ error: 'RATE_LIMIT KV namespace not configured' }, 500);
	}

	const hash = c.req.param('hash');
	if (!/^[0-9a-f]{64}$/.test(hash)) {
		return c.json({ error: 'Invalid hash format' }, 400);
	}

	const record = await getTrialKeyStatus(c.env.RATE_LIMIT, hash);
	if (!record) {
		return c.json({ error: 'Trial key not found' }, 404);
	}

	const now = Date.now();
	return c.json({
		...record,
		expired: now >= record.expiresAt,
		exhausted: record.currentUses >= record.maxUses,
		usesRemaining: Math.max(0, record.maxUses - record.currentUses),
		daysRemaining: Math.max(0, Math.ceil((record.expiresAt - now) / (24 * 60 * 60 * 1000))),
	});
});

/**
 * DELETE /internal/trial-keys/:hash
 *
 * Revoke (delete) a trial key.
 */
internalRoutes.delete('/trial-keys/:hash', async (c) => {
	if (!c.env.RATE_LIMIT) {
		return c.json({ error: 'RATE_LIMIT KV namespace not configured' }, 500);
	}

	const hash = c.req.param('hash');
	if (!/^[0-9a-f]{64}$/.test(hash)) {
		return c.json({ error: 'Invalid hash format' }, 400);
	}

	const deleted = await revokeTrialKey(c.env.RATE_LIMIT, hash);
	return c.json({ deleted });
});

/**
 * GET /internal/trial-keys
 *
 * List all trial keys with their current status.
 */
internalRoutes.get('/trial-keys', async (c) => {
	if (!c.env.RATE_LIMIT) {
		return c.json({ error: 'RATE_LIMIT KV namespace not configured' }, 500);
	}

	const url = new URL(c.req.url);
	const limit = Math.min(Number(url.searchParams.get('limit') ?? 100), 1000);

	const keys = await listTrialKeys(c.env.RATE_LIMIT, { limit });
	const now = Date.now();

	return c.json({
		keys: keys.map(({ hash, record }) => ({
			hash,
			...record,
			expired: now >= record.expiresAt,
			exhausted: record.currentUses >= record.maxUses,
			usesRemaining: Math.max(0, record.maxUses - record.currentUses),
		})),
		total: keys.length,
	});
});

// ─── Analytics Endpoints ───────────────────────────────────────────────

/** Validate analytics prerequisites (CF_ACCOUNT_ID + CF_ANALYTICS_TOKEN). */
function requireAnalyticsConfig(env: InternalEnv): { accountId: string; token: string } | null {
	if (!env.CF_ACCOUNT_ID || !env.CF_ANALYTICS_TOKEN) return null;
	return { accountId: env.CF_ACCOUNT_ID, token: env.CF_ANALYTICS_TOKEN };
}

/** Parse and clamp the `days` query parameter (1–90, default 7). */
function parseDays(url: URL): string {
	const raw = Number(url.searchParams.get('days') ?? 7);
	const clamped = Number.isFinite(raw) ? Math.max(1, Math.min(90, Math.round(raw))) : 7;
	return String(clamped);
}

/**
 * GET /internal/analytics/tier-summary
 *
 * Aggregated metrics across all tiers (or a single tier).
 * Query params: ?days=7&tier=developer
 *
 * Returns: tool usage, latency, error rates, cache performance,
 * rate limit hits, sessions, daily trend, and top tools per tier.
 */
internalRoutes.get('/analytics/tier-summary', async (c) => {
	const config = requireAnalyticsConfig(c.env);
	if (!config) {
		return c.json({ error: 'Analytics not configured (CF_ACCOUNT_ID + CF_ANALYTICS_TOKEN required)' }, 500);
	}

	const url = new URL(c.req.url);
	const days = parseDays(url);
	const hours = String(Number(days) * 24);
	const tier = url.searchParams.get('tier') ?? undefined;

	try {
		const [usage, latency, errors, cache, rateLimits, sessions, trend, topTools] = await Promise.all([
			queryAnalyticsEngine(config.accountId, config.token, queryTierToolUsage(days, tier)),
			queryAnalyticsEngine(config.accountId, config.token, queryTierLatency(days, tier)),
			queryAnalyticsEngine(config.accountId, config.token, queryTierErrorRate(days, tier)),
			queryAnalyticsEngine(config.accountId, config.token, queryTierCachePerformance(days, tier)),
			queryAnalyticsEngine(config.accountId, config.token, queryTierRateLimits(days, tier)),
			queryAnalyticsEngine(config.accountId, config.token, queryTierSessions(days, tier)),
			queryAnalyticsEngine(config.accountId, config.token, queryTierDailyTrend(days, tier)),
			queryAnalyticsEngine(config.accountId, config.token, queryTierTopTools(hours)),
		]);

		return c.json({
			days,
			tier: tier ?? 'all',
			usage,
			latency,
			errors,
			cache,
			rateLimits,
			sessions,
			trend,
			topTools,
		});
	} catch (err) {
		return c.json({ error: 'Analytics query failed', detail: err instanceof Error ? err.message.slice(0, 100) : 'unknown' }, 502);
	}
});

/**
 * GET /internal/analytics/key-usage
 *
 * Per-key usage breakdown.
 * Query params: ?days=7&key_hash=<prefix>
 *
 * key_hash is the 16-char prefix stored in analytics blobs.
 */
internalRoutes.get('/analytics/key-usage', async (c) => {
	const config = requireAnalyticsConfig(c.env);
	if (!config) {
		return c.json({ error: 'Analytics not configured (CF_ACCOUNT_ID + CF_ANALYTICS_TOKEN required)' }, 500);
	}

	const url = new URL(c.req.url);
	const days = parseDays(url);
	const keyHashPrefix = url.searchParams.get('key_hash') ?? undefined;

	try {
		const rows = await queryAnalyticsEngine(config.accountId, config.token, queryKeyUsage(days, keyHashPrefix));
		return c.json({ days, keyHash: keyHashPrefix ?? 'all', usage: rows });
	} catch (err) {
		return c.json({ error: 'Analytics query failed', detail: err instanceof Error ? err.message.slice(0, 100) : 'unknown' }, 502);
	}
});

/**
 * GET /internal/analytics/digest
 *
 * High-level tier digest (suitable for daily webhook reports).
 * Query params: ?days=1
 */
internalRoutes.get('/analytics/digest', async (c) => {
	const config = requireAnalyticsConfig(c.env);
	if (!config) {
		return c.json({ error: 'Analytics not configured (CF_ACCOUNT_ID + CF_ANALYTICS_TOKEN required)' }, 500);
	}

	const url = new URL(c.req.url);
	const days = parseDays(url);
	const hours = String(Number(days) * 24);

	try {
		const rows = await queryAnalyticsEngine(config.accountId, config.token, queryTierDigest(hours));
		return c.json({ days, tiers: rows });
	} catch (err) {
		return c.json({ error: 'Analytics query failed', detail: err instanceof Error ? err.message.slice(0, 100) : 'unknown' }, 502);
	}
});
