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
import { handleToolsCall } from './handlers/tools';
import { createAnalyticsClient } from './lib/analytics';
import { parseScoringConfig } from './lib/scoring-config';
import { parseCacheTtl } from './lib/config';
import { validateDomain, sanitizeDomain } from './lib/sanitize';

type InternalEnv = {
	SCAN_CACHE?: KVNamespace;
	PROFILE_ACCUMULATOR?: DurableObjectNamespace;
	MCP_ANALYTICS?: AnalyticsEngineDataset;
	PROVIDER_SIGNATURES_URL?: string;
	PROVIDER_SIGNATURES_ALLOWED_HOSTS?: string;
	PROVIDER_SIGNATURES_SHA256?: string;
	SCORING_CONFIG?: string;
	CACHE_TTL_SECONDS?: string;
	BV_DOH_ENDPOINT?: string;
	BV_DOH_TOKEN?: string;
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
	const body = await c.req.json<{ name: string; arguments?: Record<string, unknown> }>();

	if (!body.name || typeof body.name !== 'string') {
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
			scoringConfig: parseScoringConfig(c.env.SCORING_CONFIG),
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

/** Maximum domains per batch request. */
const BATCH_MAX_DOMAINS = 500;

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

	const body = JSON.parse(raw) as {
		domains: string[];
		tool?: string;
		arguments?: Record<string, unknown>;
		concurrency?: number;
	};

	if (!Array.isArray(body.domains) || body.domains.length === 0) {
		return c.json({ error: 'Missing required field: domains (non-empty array)' }, 400);
	}

	if (body.domains.length > BATCH_MAX_DOMAINS) {
		return c.json({ error: `Batch size exceeds maximum of ${BATCH_MAX_DOMAINS} domains` }, 400);
	}

	const toolName = body.tool ?? 'scan_domain';
	const extraArgs = body.arguments ?? {};
	const concurrency = Math.min(Math.max(body.concurrency ?? BATCH_DEFAULT_CONCURRENCY, 1), 50);

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
						scoringConfig: parseScoringConfig(c.env.SCORING_CONFIG),
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
