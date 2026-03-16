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

type InternalEnv = {
	SCAN_CACHE?: KVNamespace;
	PROFILE_ACCUMULATOR?: DurableObjectNamespace;
	MCP_ANALYTICS?: AnalyticsEngineDataset;
	PROVIDER_SIGNATURES_URL?: string;
	PROVIDER_SIGNATURES_ALLOWED_HOSTS?: string;
	PROVIDER_SIGNATURES_SHA256?: string;
	SCORING_CONFIG?: string;
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
		},
	);

	return c.json(result);
});
