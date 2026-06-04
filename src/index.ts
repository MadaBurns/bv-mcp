// SPDX-License-Identifier: BUSL-1.1

/**
 * DNS Security MCP Server - Main Entry Point
 *
 * Cloudflare Worker implementing the Model Context Protocol (MCP)
 * with DNS security analysis tools. Uses Hono framework for routing.
 *
 * Implements MCP transports:
 *   GET  /health        - Worker health check
 *   POST /mcp           - Streamable HTTP JSON-RPC 2.0 endpoint
 *   GET  /mcp           - Streamable HTTP SSE stream or legacy SSE bootstrap
 *   DELETE /mcp         - Session termination
 *   POST /mcp/messages  - Legacy HTTP+SSE client-to-server messages
 */

import { Hono, type Context } from 'hono';
import { cors } from 'hono/cors';
import wasm from '../crates/bv-wasm-core/pkg/bv_wasm_core_bg.wasm';
import * as bv_wasm from '../crates/bv-wasm-core/pkg/bv_wasm_core.js';

// Initialize the Wasm module
bv_wasm.initSync(wasm);

import { checkRateLimit, checkToolDailyRateLimit } from './lib/rate-limiter';
import { logEvent, logError, sanitizeHeadersForLog } from './lib/log';
import { jsonRpcError, JSON_RPC_ERRORS } from './lib/json-rpc';
import { normalizeHeaders, parseJsonRpcRequest, readRequestBody, validateContentType } from './mcp/request';
import { createSession, deleteSession, validateSession, checkSessionCreateRateLimit } from './lib/session';
import { unauthorizedResponse } from './lib/auth';
import { sseEvent, acceptsSSE, createNotificationStream, sseErrorResponse, createStreamingSseResponse } from './lib/sse';
import { createAnalyticsClient, hashForAnalytics, hashIpForAnalytics } from './lib/analytics';
import { detectMcpClient } from './lib/client-detection';
import type { JsonRpcRequest } from './lib/json-rpc';
import { buildControlPlaneRateLimitResponse, resolveSseSession, validateSessionRequest } from './mcp/route-gates';
import {
	FREE_TOOL_DAILY_LIMITS,
	MAX_REQUEST_BODY_BYTES,
	isValidOAuthSigningSecret,
	parseCacheTtl,
	parsePerCheckTimeout,
	parseScanTimeout,
} from './lib/config';
import { validateDomain, sanitizeDomain } from './lib/sanitize';
import { scanDomain } from './tools/scan-domain';
import { gradeBadge, errorBadge } from './lib/badge';
import { SERVER_VERSION } from './lib/server-version';
import { executeMcpRequest } from './mcp/execute';
import { classifyProtocolVersionHeader } from './mcp/dispatch';
import { parseScoringConfigCached } from './lib/scoring-config';
import { closeLegacyStream, enqueueLegacyMessage, openLegacySseStream } from './lib/legacy-sse';
import { resolveClientIpFromHeaders, resolveClientIpFromRequestHeaders } from './lib/client-ip';
import { internalRoutes } from './internal';
import { buildAuthorizationServerMetadata, buildProtectedResourceMetadata, resolveIssuer } from './oauth/discovery';
import { handleRegister } from './oauth/register';
import { handleAuthorizeGet, handleAuthorizePost } from './oauth/authorize';
import { handleToken } from './oauth/token';
export { QuotaCoordinator } from './lib/quota-coordinator';
export { ProfileAccumulator } from './lib/profile-accumulator';

const TEXT_ENCODER = new TextEncoder();

let hasLoggedAnalyticsBindingStatus = false;

function logAnalyticsBindingStatus(enabled: boolean): void {
	if (hasLoggedAnalyticsBindingStatus) return;
	hasLoggedAnalyticsBindingStatus = true;
	logEvent({
		timestamp: new Date().toISOString(),
		category: 'analytics',
		result: enabled ? 'enabled' : 'disabled',
		severity: enabled ? 'info' : 'warn',
		details: {
			message: enabled ? 'Analytics Engine binding detected' : 'Analytics Engine binding missing; telemetry emits are no-op',
		},
	});
}

type BvMcpEnv = {
	RATE_LIMIT?: KVNamespace;
	SCAN_CACHE?: KVNamespace;
	SESSION_STORE?: KVNamespace;
	QUOTA_COORDINATOR?: DurableObjectNamespace;
	PROFILE_ACCUMULATOR?: DurableObjectNamespace;
	MCP_ANALYTICS?: AnalyticsEngineDataset;
	BV_API_KEY?: string;
	BV_WEB?: Fetcher;
	BV_WEB_INTERNAL_KEY?: string;
	ALLOWED_ORIGINS?: string;
	PROVIDER_SIGNATURES_URL?: string;
	PROVIDER_SIGNATURES_ALLOWED_HOSTS?: string;
	PROVIDER_SIGNATURES_SHA256?: string;
	SCORING_CONFIG?: string;
	CACHE_TTL_SECONDS?: string;
	SCAN_TIMEOUT_MS?: string;
	PER_CHECK_TIMEOUT_MS?: string;
	BV_DOH_ENDPOINT?: string;
	BV_DOH_TOKEN?: string;
	BV_CERTSTREAM?: Fetcher;
	BV_CERTSTREAM_ADMIN_KEY?: string;
	BV_WHOIS?: Fetcher;
	REQUIRE_AUTH?: string;
	/** FIND-01: when 'true', the ?api_key= query-param fallback is nulled; requests proceed as free tier. */
	REJECT_QUERY_API_KEY?: string;
	ENABLE_OAUTH?: string;
	ENABLE_OWNER_OAUTH?: string;
	BV_WEB_OAUTH_CONSENT_URL?: string;
	OAUTH_ISSUER?: string;
	OAUTH_SIGNING_SECRET?: string;
	BV_INTERNAL_DEV_KEY?: string;
	BRAND_AUDIT_DB?: D1Database;
	INTELLIGENCE_DB?: D1Database;
	MCP_ACCESS_LOG_IP_ENCRYPTION_KEY?: string;
	MCP_ACCESS_LOG_IP_KEY_VERSION?: string;
	/** FIND-17: Base64-encoded 32-byte AES-256 key for app-layer KV envelope encryption of trial keys and OAuth codes. */
	KV_ENVELOPE_KEY?: string;
	BRAND_AUDIT_QUEUE?: { send(message: unknown, options?: { contentType?: 'json' }): Promise<void> };
	BRAND_AUDIT_PDF_QUEUE?: { send(message: unknown, options?: { contentType?: 'json' }): Promise<void> };
	BRAND_REPORTS?: R2Bucket;
	BV_BROWSER_RENDERER?: Fetcher;
	/** ADMIN_API_KEY for bv-browser-renderer's /pdf/html endpoint. Bearer-authed. */
	BV_BROWSER_RENDERER_KEY?: string;
	/**
	 * T13 — BlackVeil-production runtime override. When set to "tiered",
	 * `discover_brand_domains` defaults to tiered mode for callers that omit
	 * `discovery_mode`. Unset on BSL self-hosts; the public schema default
	 * (`'classic'`) wins. Wired through `ToolRuntimeOptions.discoveryModeDefault`
	 * (HTTP `/mcp` request path) and `BrandAuditConsumerDeps.discoveryModeDefault`
	 * (Cloudflare Queue consumer path) into `runBrandAuditPipeline`'s
	 * `options.env`. Set only in `.dev/wrangler.deploy.jsonc`; never in the
	 * public `wrangler.jsonc`.
	 */
	BRAND_AUDIT_DISCOVERY_MODE_DEFAULT?: string;
	/**
	 * Brand-discovery cross-Worker service bindings. Declared ONLY in the
	 * private overlay (`.dev/wrangler.deploy.jsonc`) — never in the public
	 * `wrangler.jsonc`. Enforced by
	 * `test/audits/wrangler-public-no-private-bindings.audit.test.ts`.
	 *
	 * BSL self-hosts have all three undefined; the tier-lookup closures are
	 * never constructed and tiered-mode discovery degrades to classic.
	 */
	/** Tier 1 — bv-infrastructure-graph (HTTP service binding). */
	BV_INFRA_GRAPH?: Fetcher;
	/** Optional raw authoritative DNS/BGP/RPKI/vantage probe binding. */
	BV_INFRA_PROBE?: Fetcher;
	/**
	 * Tier 2 — bv-intel-gateway (Workers RPC binding to a `WorkerEntrypoint`).
	 * Auth is enforced at the binding level; no Authorization header plumbed.
	 * Matches the consumer-side type at `src/lib/brand-tier2-evidence.ts`.
	 */
	BV_INTEL_GATEWAY?: {
		getDomainEvidence: (params: { domain: string; includeHistory?: boolean }) => Promise<unknown>;
	};
	/** Tier 0 — bv-enterprise (HTTP service binding to tenant-portfolio lookup). */
	BV_ENTERPRISE?: Fetcher;
	/**
	 * Operator-only bv-recon service binding (OSINT / package-trust / bucket-scan).
	 * Declared ONLY in the private overlay (`.dev/wrangler.deploy.jsonc`) — never in
	 * public `wrangler.jsonc`. Enforced by
	 * `test/audits/wrangler-public-no-private-bindings.audit.test.ts`.
	 * BSL self-hosts leave this undefined; bv-recon-backed tools degrade to no-op.
	 */
	BV_RECON?: Fetcher;
	/** Bearer admin token for bv-recon's adminAuthMiddleware-gated routes. */
	BV_RECON_KEY?: string;
	/**
	 * Operator-only bv-tls-probe service binding (negotiated-TLS-version detection).
	 * Declared ONLY in the private overlay (`.dev/wrangler.deploy.jsonc`) — never in
	 * public `wrangler.jsonc`. BSL self-hosts leave this undefined; the SSL check's
	 * TLS-version enrichment degrades to no-op (no finding, no score change).
	 */
	BV_TLS_PROBE?: Fetcher;
	/** Bearer token for bv-tls-probe (= bv-tls-probe's dedicated key). */
	BV_TLS_PROBE_KEY?: string;
};

import type { TierAuthResult } from './lib/tier-auth';
import { resolveTier } from './lib/tier-auth';

const app = new Hono<{
	Bindings: BvMcpEnv;
	Variables: { isAuthenticated: boolean; tierAuthResult: TierAuthResult; apiKeyInQuery: boolean };
}>();
const mcpPaths = ['/mcp', '/mcp/messages', '/mcp/sse'] as const;

import { buildBrandTierLookups } from './lib/brand-tier-lookups';

type OAuthAvailability = 'ready' | 'disabled' | 'misconfigured';

/**
 * Three-state OAuth gate. `'ready'` requires BOTH `ENABLE_OAUTH==='true'` AND a
 * valid `OAUTH_SIGNING_SECRET`. The split matters: a misconfigured deploy used
 * to expose discovery + register + authorize + consent successfully and only
 * fail at /oauth/token, after the user had committed to the consent dance and
 * the relay client (claude.ai) had no diagnostic to surface — see chaos test
 * `oauth-misconfiguration.chaos.test.ts` and the 2026-05-08 incident.
 *
 * `'misconfigured'` → 503 from every OAuth route (fail-fast at first RTT).
 * `'disabled'` → 404 (feature off, semantically distinct from "broken").
 */
function oauthAvailability(env: Pick<BvMcpEnv, 'ENABLE_OAUTH' | 'OAUTH_SIGNING_SECRET'>): OAuthAvailability {
	if (env.ENABLE_OAUTH !== 'true') return 'disabled';
	if (!isValidOAuthSigningSecret(env.OAUTH_SIGNING_SECRET)) return 'misconfigured';
	return 'ready';
}

function certstreamAuthToken(env: BvMcpEnv): string | undefined {
	return env.BV_CERTSTREAM_ADMIN_KEY || env.BV_INTERNAL_DEV_KEY;
}

function oauthDisabledResponse(): Response {
	return new Response('Not found', { status: 404 });
}

function oauthMisconfiguredResponse(): Response {
	// 503 + JSON body so OAuth clients (which expect JSON errors per RFC 6749 §5.2)
	// can render an actionable message instead of "couldn't connect".
	return new Response(
		JSON.stringify({
			error: 'service_unavailable',
			error_description: 'OAuth is enabled but the server is not configured to issue tokens',
		}),
		{ status: 503, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } },
	);
}

export { resolveClientIpFromHeaders } from './lib/client-ip';

/**
 * Electron-only URI schemes used by desktop IDE webviews (VS Code, Cursor, Windsurf).
 * Browsers cannot forge these — safe to allow without explicit ALLOWED_ORIGINS entry.
 */
const DESKTOP_IDE_SCHEMES = ['vscode-webview:', 'vscode-file:'];

/** Check if an origin is allowed for this request. Returns 'allowed' | 'denied' | 'invalid'. */
function checkOrigin(origin: string, requestUrl: string, allowedOrigins?: string): 'allowed' | 'denied' | 'invalid' {
	try {
		const parsed = new URL(origin);
		// Desktop IDE schemes (Electron-only, not forgeable by browsers)
		if (DESKTOP_IDE_SCHEMES.includes(parsed.protocol)) return 'allowed';
		// Same-origin: compare full origin (scheme+host+port) not just host
		if (parsed.origin === new URL(requestUrl).origin) return 'allowed';
	} catch {
		return 'invalid';
	}

	if (allowedOrigins) {
		const allowed = allowedOrigins
			.split(',')
			.map((value) => value.trim().toLowerCase())
			.filter((value) => value.length > 0);
		if (allowed.includes(origin.toLowerCase())) return 'allowed';
	}

	return 'denied';
}

for (const path of mcpPaths) {
	app.use(
		path,
		cors({
			origin: (origin, c) => {
				if (!origin) return '';
				const result = checkOrigin(origin, c.req.url, (c.env as BvMcpEnv).ALLOWED_ORIGINS?.trim());
				return result === 'allowed' ? origin : '';
			},
			allowMethods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
			allowHeaders: ['Content-Type', 'Accept', 'Mcp-Session-Id', 'Authorization'],
			exposeHeaders: ['Mcp-Session-Id'],
		}),
	);

	app.use(path, async (c, next) => {
		const origin = c.req.header('origin');
		if (!origin) return next();

		const result = checkOrigin(origin, c.req.url, c.env.ALLOWED_ORIGINS?.trim());
		if (result === 'allowed') return next();
		if (result === 'invalid') return new Response('Forbidden: invalid Origin header', { status: 403 });
		return new Response('Forbidden: unauthorized Origin', { status: 403 });
	});

	app.use(path, async (c, next) => {
		const authHeader = c.req.header('authorization');
		const bearerToken = authHeader?.startsWith('Bearer ') ? authHeader.slice(7).trim() : null;
		const queryToken = c.env.REJECT_QUERY_API_KEY === 'true' ? null : bearerToken ? null : (c.req.query('api_key') ?? null);
		const token = bearerToken ?? queryToken;
		const apiKeyInQuery = queryToken !== null;

		const resolvedClientIp = resolveClientIpFromRequestHeaders(c.req.raw.headers);
		const clientIp = resolvedClientIp === 'unknown' ? undefined : resolvedClientIp;
		const tierResult = await resolveTier(token, c.env, clientIp, c.req.url);
		c.set('tierAuthResult', tierResult);
		c.set('isAuthenticated', tierResult.authenticated);
		c.set('apiKeyInQuery', apiKeyInQuery);

		// If token was provided but not recognized, or if auth is required and not authenticated, reject
		if ((token && !tierResult.authenticated) || (c.env.REQUIRE_AUTH === 'true' && !tierResult.authenticated)) {
			const response = unauthorizedResponse();
			// The global post-next middleware never runs on early returns, so
			// stamp the deprecation signal here too — clients fixing their auth
			// header path should see it on 401 (the most common failure mode
			// for the deprecated `?api_key=` flow).
			if (apiKeyInQuery) {
				response.headers.set('Deprecation', 'true');
				response.headers.set('Sunset', 'Tue, 01 Dec 2026 00:00:00 GMT');
				response.headers.set('Link', '<https://github.com/MadaBurns/bv-mcp#authentication>; rel="deprecation"; type="text/html"');
			}
			return response;
		}

		return next();
	});
}

app.use('*', async (c, next) => {
	await next();
	c.header('X-Content-Type-Options', 'nosniff');
	c.header('X-Frame-Options', 'DENY');
	c.header('X-XSS-Protection', '0');
	c.header('Referrer-Policy', 'no-referrer');
	c.header('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
	c.header(
		'Content-Security-Policy',
		"default-src 'self'; script-src 'none'; style-src 'self' 'unsafe-inline'; object-src 'none'; frame-ancestors 'none'; form-action 'self'",
	);
	c.header('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');

	// RFC 8594 / draft-ietf-httpapi-deprecation-header: clients still passing the
	// API key via `?api_key=` (Smithery proxy fallback) get a deprecation signal.
	// The query form lands in CDN/edge logs whereas `Authorization: Bearer` does
	// not, so we want to drive clients to the header. Sunset 2026-12-01.
	if (c.get('apiKeyInQuery')) {
		c.header('Deprecation', 'true');
		c.header('Sunset', 'Tue, 01 Dec 2026 00:00:00 GMT');
		c.header('Link', '<https://github.com/MadaBurns/bv-mcp#authentication>; rel="deprecation"; type="text/html"');
	}
});

app.use('*', async (c, next) => {
	try {
		await next();
	} catch (err) {
		logError(err instanceof Error ? err : String(err), {
			severity: 'error',
			details: {
				method: c.req.method,
				url: c.req.url,
				headers: sanitizeHeadersForLog(c.req.raw.headers),
			},
		});
		return c.json(jsonRpcError(null, JSON_RPC_ERRORS.INTERNAL_ERROR, 'Internal server error'), 500);
	}
});

app.get('/health', (c) => {
	return c.json({
		status: 'ok',
		service: 'bv-dns-security-mcp',
		timestamp: new Date().toISOString(),
	});
});

app.get('/badge/:domain', async (c) => {
	const svgHeaders = {
		'Content-Type': 'image/svg+xml',
		'Cache-Control': 'public, max-age=300',
	};

	const ip = resolveClientIpFromRequestHeaders(c.req.raw.headers);
	const rateResult = await checkRateLimit(ip, c.env.RATE_LIMIT, c.env.QUOTA_COORDINATOR);
	if (!rateResult.allowed) {
		return new Response(errorBadge(), { status: 429, headers: svgHeaders });
	}

	const toolQuota = await checkToolDailyRateLimit(
		ip,
		'scan_domain',
		FREE_TOOL_DAILY_LIMITS.scan_domain,
		c.env.RATE_LIMIT,
		c.env.QUOTA_COORDINATOR,
	);
	if (!toolQuota.allowed) {
		return c.text('Rate limit exceeded', 429);
	}

	const rawDomain = c.req.param('domain');
	const validation = validateDomain(rawDomain);
	if (!validation.valid) {
		return new Response(errorBadge(), { status: 400, headers: svgHeaders });
	}

	const domain = sanitizeDomain(rawDomain);
	if (!domain) {
		return new Response(errorBadge(), { status: 400, headers: svgHeaders });
	}

	try {
		const result = await scanDomain(domain, c.env.SCAN_CACHE, {
			profileAccumulator: c.env.PROFILE_ACCUMULATOR,
			waitUntil: (promise: Promise<unknown>) => c.executionCtx.waitUntil(promise),
			scoringConfig: parseScoringConfigCached(c.env.SCORING_CONFIG),
			cacheTtlSeconds: parseCacheTtl(c.env.CACHE_TTL_SECONDS),
			scanTimeoutMs: parseScanTimeout(c.env.SCAN_TIMEOUT_MS),
			perCheckTimeoutMs: parsePerCheckTimeout(c.env.PER_CHECK_TIMEOUT_MS),
		});
		return new Response(gradeBadge(result.score.grade), { status: 200, headers: svgHeaders });
	} catch {
		return new Response(errorBadge(), { status: 500, headers: svgHeaders });
	}
});

app.post('/mcp', async (c) => {
	const startTime = Date.now();
	const analytics = createAnalyticsClient(c.env.MCP_ANALYTICS);
	logAnalyticsBindingStatus(analytics.enabled);
	const headersLc = normalizeHeaders(c.req.raw.headers);
	const accept = headersLc['accept'];
	const ip = resolveClientIpFromHeaders(headersLc);
	const isAuthenticated = c.get('isAuthenticated');
	const tierAuthResult = c.get('tierAuthResult');

	// Analytics context enrichment
	const cfProps = c.req.raw.cf as IncomingRequestCfProperties | undefined;
	// cfProps.country is non-tamperable (set by Cloudflare on the request object);
	// cf-ipcountry header is only a fallback for non-CF-fronted paths (rare).
	const country = (cfProps?.country as string) ?? headersLc['cf-ipcountry'] ?? 'unknown';
	const clientType = detectMcpClient(headersLc['user-agent']);
	const authTier = tierAuthResult.authenticated ? (tierAuthResult.tier ?? 'free') : 'anon';
	const keyHash = tierAuthResult.keyHash ? tierAuthResult.keyHash.slice(0, 16) : undefined;
	const sessionHash = headersLc['mcp-session-id'] ? hashForAnalytics(headersLc['mcp-session-id']) : 'none';
	const ipHash = ip !== 'unknown' ? hashIpForAnalytics(ip) : undefined;

	const contentTypeError = validateContentType(headersLc['content-type']);
	if (contentTypeError) {
		return sseErrorResponse(contentTypeError.payload!, contentTypeError.status!, accept);
	}

	const bodyReadResult = await readRequestBody(c.req.raw, MAX_REQUEST_BODY_BYTES);
	if (!bodyReadResult.ok) {
		return sseErrorResponse(bodyReadResult.payload!, bodyReadResult.status!, accept);
	}

	const parsedRequest = parseJsonRpcRequest(bodyReadResult.rawBody!);
	if (!parsedRequest.ok) {
		logError('Parse error: invalid JSON', {
			severity: 'error',
			ipHash,
			details: { bodyLength: bodyReadResult.rawBody!.length, bodyPreviewRedacted: true },
		});
		return sseErrorResponse(parsedRequest.payload!, parsedRequest.status!, accept);
	}

	const parsedBodies = parsedRequest.isBatch ? (parsedRequest.body as unknown[]) : [parsedRequest.body as JsonRpcRequest];

	// #363 item 4 — observe (never reject) the MCP-Protocol-Version request header.
	// Per MCP 2025-06-18 clients SHOULD send it on post-initialize requests; we log an
	// unsupported value for spec-awareness but deliberately do not 400 (most clients omit
	// or lag the header — a hard reject would break them). `initialize` is exempt: the
	// header is legitimately absent before negotiation. Strict rejection, if ever wanted,
	// is a one-line gate on this classification.
	const singleMethod = parsedRequest.isBatch ? undefined : (parsedBodies[0] as JsonRpcRequest | undefined)?.method;
	if (singleMethod !== 'initialize' && classifyProtocolVersionHeader(headersLc['mcp-protocol-version']) === 'unsupported') {
		logEvent({
			timestamp: new Date().toISOString(),
			severity: 'warn',
			category: 'protocol',
			result: 'Unsupported MCP-Protocol-Version header (observed, not rejected)',
			details: { protocolVersionHeader: headersLc['mcp-protocol-version'], method: singleMethod ?? 'batch' },
			ipHash,
		});
	}

	if (parsedRequest.isBatch) {
		const batch = parsedBodies;
		if (batch.length > 20) {
			return c.json(jsonRpcError(null, JSON_RPC_ERRORS.INVALID_REQUEST, 'Batch size exceeds maximum of 20 requests'), 400);
		}

		const results = await Promise.all(
			parsedBodies.map(async (entry) => {
				if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
					return {
						kind: 'response' as const,
						payload: jsonRpcError(null, JSON_RPC_ERRORS.INVALID_REQUEST, 'Invalid JSON-RPC 2.0 request'),
						headers: {},
						httpStatus: 400,
						useErrorEnvelope: true,
					};
				}

				return executeMcpRequest({
					body: entry as JsonRpcRequest,
					allowStreaming: false,
					batchMode: true,
					batchSize: parsedBodies.length,
					responseTransport: acceptsSSE(accept) ? 'sse' : 'json',
					accept,
					startTime,
					ip,
					isAuthenticated,
					tierAuthResult,
					userAgent: headersLc['user-agent'],
					sessionId: headersLc['mcp-session-id'],
					validateSession: true,
					sessionErrorMessage: 'Bad Request: missing session. Send an initialize request first to create a session.',
					createSessionOnInitialize: true,
					existingSessionId: headersLc['mcp-session-id'],
					serverVersion: SERVER_VERSION,
					rateLimitKv: c.env.RATE_LIMIT,
					quotaCoordinator: c.env.QUOTA_COORDINATOR,
					sessionStore: c.env.SESSION_STORE,
					scanCache: c.env.SCAN_CACHE,
					providerSignaturesUrl: c.env.PROVIDER_SIGNATURES_URL,
					providerSignaturesAllowedHosts: c.env.PROVIDER_SIGNATURES_ALLOWED_HOSTS,
					providerSignaturesSha256: c.env.PROVIDER_SIGNATURES_SHA256,
					analytics,
					profileAccumulator: c.env.PROFILE_ACCUMULATOR,
					intelligenceDb: c.env.INTELLIGENCE_DB,
					ipEncryptionKey: c.env.MCP_ACCESS_LOG_IP_ENCRYPTION_KEY,
					ipEncryptionKeyVersion: c.env.MCP_ACCESS_LOG_IP_KEY_VERSION,
					waitUntil: (promise: Promise<unknown>) => c.executionCtx.waitUntil(promise),
					scoringConfig: parseScoringConfigCached(c.env.SCORING_CONFIG),
					cacheTtlSeconds: parseCacheTtl(c.env.CACHE_TTL_SECONDS),
					scanTimeoutMs: parseScanTimeout(c.env.SCAN_TIMEOUT_MS),
					perCheckTimeoutMs: parsePerCheckTimeout(c.env.PER_CHECK_TIMEOUT_MS),
					secondaryDohEndpoint: c.env.BV_DOH_ENDPOINT,
					secondaryDohToken: c.env.BV_DOH_TOKEN,
					certstream: c.env.BV_CERTSTREAM,
					certstreamAuthToken: certstreamAuthToken(c.env as BvMcpEnv),
					whoisBinding: c.env.BV_WHOIS,
					reconBinding: c.env.BV_RECON,
					reconAuthToken: c.env.BV_RECON_KEY,
					tlsProbeBinding: c.env.BV_TLS_PROBE,
					tlsProbeAuthToken: c.env.BV_TLS_PROBE_KEY,
					m365Proxy: c.env.BV_WEB,
					m365ProxyAuthToken: c.env.BV_WEB_INTERNAL_KEY,
					infraProbe: c.env.BV_INFRA_PROBE,
					brandAuditDb: c.env.BRAND_AUDIT_DB,
					brandAuditQueue: c.env.BRAND_AUDIT_QUEUE,
					brandReportsR2: c.env.BRAND_REPORTS,
					browserRenderer: c.env.BV_BROWSER_RENDERER,
					discoveryModeDefault: c.env.BRAND_AUDIT_DISCOVERY_MODE_DEFAULT,
					...buildBrandTierLookups(c.env),
					principalId: keyHash ?? ipHash,
					country,
					clientType,
					authTier,
					keyHash,
					sessionHash,
					ipHash,
				});
			}),
		);

		const responsePayloads = results.flatMap((result) => (result.kind === 'response' ? [result.payload] : []));
		if (responsePayloads.length === 0) {
			return new Response(null, { status: 202 });
		}

		if (acceptsSSE(accept)) {
			const ssePayload = sseEvent(responsePayloads);
			return new Response(ssePayload, {
				status: 200,
				headers: {
					'Content-Type': 'text/event-stream',
					'Cache-Control': 'no-cache',
					'Content-Length': String(TEXT_ENCODER.encode(ssePayload).byteLength),
				},
			});
		}

		return c.json(responsePayloads, { status: 200 });
	}

	const singleResult = await executeMcpRequest({
		body: parsedBodies[0] as JsonRpcRequest,
		allowStreaming: true,
		batchMode: false,
		batchSize: 1,
		responseTransport: acceptsSSE(accept) ? 'sse' : 'json',
		accept,
		startTime,
		ip,
		isAuthenticated,
		tierAuthResult,
		userAgent: headersLc['user-agent'],
		sessionId: headersLc['mcp-session-id'],
		validateSession: true,
		sessionErrorMessage: 'Bad Request: missing session. Send an initialize request first to create a session.',
		createSessionOnInitialize: true,
		existingSessionId: headersLc['mcp-session-id'],
		serverVersion: SERVER_VERSION,
		rateLimitKv: c.env.RATE_LIMIT,
		quotaCoordinator: c.env.QUOTA_COORDINATOR,
		sessionStore: c.env.SESSION_STORE,
		scanCache: c.env.SCAN_CACHE,
		providerSignaturesUrl: c.env.PROVIDER_SIGNATURES_URL,
		providerSignaturesAllowedHosts: c.env.PROVIDER_SIGNATURES_ALLOWED_HOSTS,
		providerSignaturesSha256: c.env.PROVIDER_SIGNATURES_SHA256,
		analytics,
		profileAccumulator: c.env.PROFILE_ACCUMULATOR,
		intelligenceDb: c.env.INTELLIGENCE_DB,
		ipEncryptionKey: c.env.MCP_ACCESS_LOG_IP_ENCRYPTION_KEY,
		ipEncryptionKeyVersion: c.env.MCP_ACCESS_LOG_IP_KEY_VERSION,
		waitUntil: (promise: Promise<unknown>) => c.executionCtx.waitUntil(promise),
		scoringConfig: parseScoringConfigCached(c.env.SCORING_CONFIG),
		cacheTtlSeconds: parseCacheTtl(c.env.CACHE_TTL_SECONDS),
		scanTimeoutMs: parseScanTimeout(c.env.SCAN_TIMEOUT_MS),
		perCheckTimeoutMs: parsePerCheckTimeout(c.env.PER_CHECK_TIMEOUT_MS),
		secondaryDohEndpoint: c.env.BV_DOH_ENDPOINT,
		secondaryDohToken: c.env.BV_DOH_TOKEN,
		certstream: c.env.BV_CERTSTREAM,
		certstreamAuthToken: certstreamAuthToken(c.env as BvMcpEnv),
		whoisBinding: c.env.BV_WHOIS,
		reconBinding: c.env.BV_RECON,
		reconAuthToken: c.env.BV_RECON_KEY,
		tlsProbeBinding: c.env.BV_TLS_PROBE,
		tlsProbeAuthToken: c.env.BV_TLS_PROBE_KEY,
		m365Proxy: c.env.BV_WEB,
		m365ProxyAuthToken: c.env.BV_WEB_INTERNAL_KEY,
		infraProbe: c.env.BV_INFRA_PROBE,
		brandAuditDb: c.env.BRAND_AUDIT_DB,
		brandAuditQueue: c.env.BRAND_AUDIT_QUEUE,
		brandReportsR2: c.env.BRAND_REPORTS,
		browserRenderer: c.env.BV_BROWSER_RENDERER,
		discoveryModeDefault: c.env.BRAND_AUDIT_DISCOVERY_MODE_DEFAULT,
		...buildBrandTierLookups(c.env),
		principalId: keyHash ?? ipHash,
		country,
		clientType,
		authTier,
		keyHash,
		sessionHash,
		ipHash,
	});

	if (singleResult.kind === 'notification') {
		return new Response(null, { status: 202 });
	}

	if (singleResult.streamOperation) {
		return createStreamingSseResponse(
			singleResult.streamOperation,
			(payload) => sseEvent(payload, singleResult.eventId),
			singleResult.headers,
		);
	}

	if (acceptsSSE(accept)) {
		if (singleResult.useErrorEnvelope) {
			return sseErrorResponse(singleResult.payload, singleResult.httpStatus, accept, singleResult.headers, singleResult.eventId);
		}

		const ssePayload = sseEvent(singleResult.payload, singleResult.eventId);
		return new Response(ssePayload, {
			status: 200,
			headers: {
				'Content-Type': 'text/event-stream',
				'Cache-Control': 'no-cache',
				'Content-Length': String(TEXT_ENCODER.encode(ssePayload).byteLength),
				...singleResult.headers,
			},
		});
	}

	return Response.json(singleResult.payload, {
		status: singleResult.useErrorEnvelope ? singleResult.httpStatus : 200,
		headers: singleResult.headers,
	});
});

app.post('/mcp/messages', async (c) => {
	const startTime = Date.now();
	const analytics = createAnalyticsClient(c.env.MCP_ANALYTICS);
	logAnalyticsBindingStatus(analytics.enabled);
	const headersLc = normalizeHeaders(c.req.raw.headers);
	const ip = resolveClientIpFromHeaders(headersLc);
	const isAuthenticated = c.get('isAuthenticated');
	const tierAuthResult = c.get('tierAuthResult');
	const sessionId = c.req.query('sessionId');

	// Analytics context enrichment
	const cfProps = c.req.raw.cf as IncomingRequestCfProperties | undefined;
	// cfProps.country is non-tamperable (set by Cloudflare on the request object);
	// cf-ipcountry header is only a fallback for non-CF-fronted paths (rare).
	const country = (cfProps?.country as string) ?? headersLc['cf-ipcountry'] ?? 'unknown';
	const clientType = detectMcpClient(headersLc['user-agent']);
	const authTier = tierAuthResult.authenticated ? (tierAuthResult.tier ?? 'free') : 'anon';
	const keyHash = tierAuthResult.keyHash ? tierAuthResult.keyHash.slice(0, 16) : undefined;
	const sessionHash = sessionId ? hashForAnalytics(sessionId) : 'none';
	const ipHash = ip !== 'unknown' ? hashIpForAnalytics(ip) : undefined;

	if (!sessionId) {
		return c.json(jsonRpcError(null, JSON_RPC_ERRORS.INVALID_REQUEST, 'Bad Request: missing session'), 400);
	}

	const legacyContentTypeError = validateContentType(headersLc['content-type']);
	if (legacyContentTypeError) {
		return Response.json(legacyContentTypeError.payload, { status: legacyContentTypeError.status });
	}

	// Early session validation — return HTTP 404 directly for expired/terminated sessions
	// so legacy SSE clients see the error instead of getting 202 with an undeliverable SSE message
	if (!(await validateSession(sessionId, c.env.SESSION_STORE))) {
		closeLegacyStream(sessionId);
		return c.json(jsonRpcError(null, JSON_RPC_ERRORS.INVALID_REQUEST, 'Not Found: session expired or terminated'), 404);
	}

	const bodyReadResult = await readRequestBody(c.req.raw, MAX_REQUEST_BODY_BYTES);
	if (!bodyReadResult.ok) {
		return Response.json(bodyReadResult.payload, { status: bodyReadResult.status });
	}

	const parsedRequest = parseJsonRpcRequest(bodyReadResult.rawBody!);
	if (!parsedRequest.ok) {
		logError('Parse error: invalid JSON', {
			severity: 'error',
			ipHash,
			details: { bodyLength: bodyReadResult.rawBody!.length, bodyPreviewRedacted: true },
		});
		return Response.json(parsedRequest.payload, { status: parsedRequest.status });
	}

	const parsedBodies = parsedRequest.isBatch ? (parsedRequest.body as unknown[]) : [parsedRequest.body as JsonRpcRequest];
	const results = await Promise.all(
		parsedBodies.map(async (entry) => {
			if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
				return {
					kind: 'response' as const,
					payload: jsonRpcError(null, JSON_RPC_ERRORS.INVALID_REQUEST, 'Invalid JSON-RPC 2.0 request'),
					headers: {},
					httpStatus: 400,
					useErrorEnvelope: true,
				};
			}

			return executeMcpRequest({
				body: entry as JsonRpcRequest,
				allowStreaming: false,
				batchMode: parsedRequest.isBatch === true,
				batchSize: parsedBodies.length,
				responseTransport: 'sse',
				startTime,
				ip,
				isAuthenticated,
				tierAuthResult,
				userAgent: headersLc['user-agent'],
				sessionId,
				validateSession: false, // Session already validated at line ~450 (early HTTP 404 check)
				createSessionOnInitialize: false,
				existingSessionId: sessionId,
				serverVersion: SERVER_VERSION,
				rateLimitKv: c.env.RATE_LIMIT,
				quotaCoordinator: c.env.QUOTA_COORDINATOR,
				sessionStore: c.env.SESSION_STORE,
				scanCache: c.env.SCAN_CACHE,
				providerSignaturesUrl: c.env.PROVIDER_SIGNATURES_URL,
				providerSignaturesAllowedHosts: c.env.PROVIDER_SIGNATURES_ALLOWED_HOSTS,
				providerSignaturesSha256: c.env.PROVIDER_SIGNATURES_SHA256,
				analytics,
				profileAccumulator: c.env.PROFILE_ACCUMULATOR,
				intelligenceDb: c.env.INTELLIGENCE_DB,
				ipEncryptionKey: c.env.MCP_ACCESS_LOG_IP_ENCRYPTION_KEY,
				ipEncryptionKeyVersion: c.env.MCP_ACCESS_LOG_IP_KEY_VERSION,
				waitUntil: (promise: Promise<unknown>) => c.executionCtx.waitUntil(promise),
				scoringConfig: parseScoringConfigCached(c.env.SCORING_CONFIG),
				cacheTtlSeconds: parseCacheTtl(c.env.CACHE_TTL_SECONDS),
				scanTimeoutMs: parseScanTimeout(c.env.SCAN_TIMEOUT_MS),
				perCheckTimeoutMs: parsePerCheckTimeout(c.env.PER_CHECK_TIMEOUT_MS),
				secondaryDohEndpoint: c.env.BV_DOH_ENDPOINT,
				secondaryDohToken: c.env.BV_DOH_TOKEN,
				certstream: c.env.BV_CERTSTREAM,
				certstreamAuthToken: certstreamAuthToken(c.env as BvMcpEnv),
				whoisBinding: c.env.BV_WHOIS,
				reconBinding: c.env.BV_RECON,
				reconAuthToken: c.env.BV_RECON_KEY,
				tlsProbeBinding: c.env.BV_TLS_PROBE,
				tlsProbeAuthToken: c.env.BV_TLS_PROBE_KEY,
				m365Proxy: c.env.BV_WEB,
				m365ProxyAuthToken: c.env.BV_WEB_INTERNAL_KEY,
				infraProbe: c.env.BV_INFRA_PROBE,
				brandAuditDb: c.env.BRAND_AUDIT_DB,
				brandAuditQueue: c.env.BRAND_AUDIT_QUEUE,
				brandReportsR2: c.env.BRAND_REPORTS,
				browserRenderer: c.env.BV_BROWSER_RENDERER,
				discoveryModeDefault: c.env.BRAND_AUDIT_DISCOVERY_MODE_DEFAULT,
				...buildBrandTierLookups(c.env),
				principalId: keyHash ?? ipHash,
				country,
				clientType,
				authTier,
				keyHash,
				sessionHash,
				ipHash,
			});
		}),
	);

	const responsePayloads = results.flatMap((result) => (result.kind === 'response' ? [result.payload] : []));
	if (responsePayloads.length > 0) {
		enqueueLegacyMessage(sessionId, parsedRequest.isBatch ? responsePayloads : responsePayloads[0]);
	}

	return new Response(null, { status: 202 });
});

app.get('/mcp', async (c) => {
	if (!acceptsSSE(c.req.header('accept'))) {
		return new Response('Not Acceptable: Accept must include text/event-stream', { status: 406 });
	}

	const sessionId = c.req.header('mcp-session-id');
	const ip = resolveClientIpFromRequestHeaders(c.req.raw.headers);
	const isAuthenticated = c.get('isAuthenticated');

	// SSE notification stream uses control plane rate limiting but is counted
	// separately from other control plane methods. mcp-remote reconnects
	// aggressively on disconnection — using the shared control plane budget
	// (60/min) caused Claude Desktop to lose connectivity after the first tool
	// call. The SSE handler still counts against the shared budget to prevent
	// connection flood abuse, but authenticated clients bypass it entirely.
	const controlPlaneLimited = await buildControlPlaneRateLimitResponse(
		ip,
		c.env.RATE_LIMIT,
		'sse/stream',
		isAuthenticated,
		null,
		undefined,
		c.env.QUOTA_COORDINATOR,
	);
	if (controlPlaneLimited) {
		return controlPlaneLimited;
	}

	const sseSession = await resolveSseSession({
		sessionId,
		ip,
		sessionStore: c.env.SESSION_STORE,
	});
	if (sseSession.response) {
		return sseSession.response;
	}

	return new Response(createNotificationStream(), {
		status: 200,
		headers: {
			'Content-Type': 'text/event-stream',
			'Cache-Control': 'no-cache',
			'mcp-session-id': sseSession.sessionId!,
		},
	});
});

app.get('/mcp/sse', async (c) => {
	if (!acceptsSSE(c.req.header('accept'))) {
		return new Response('Not Acceptable: Accept must include text/event-stream', { status: 406 });
	}

	const ip = resolveClientIpFromRequestHeaders(c.req.raw.headers);
	const isAuthenticated = c.get('isAuthenticated');
	const controlPlaneLimited = await buildControlPlaneRateLimitResponse(
		ip,
		c.env.RATE_LIMIT,
		'sse/connect',
		isAuthenticated,
		null,
		undefined,
		c.env.QUOTA_COORDINATOR,
	);
	if (controlPlaneLimited) {
		return controlPlaneLimited;
	}

	if (!isAuthenticated) {
		const sessionCreateGate = await checkSessionCreateRateLimit(ip, c.env.RATE_LIMIT, c.env.QUOTA_COORDINATOR);
		if (!sessionCreateGate.allowed) {
			const retryAfterSeconds = Math.ceil((sessionCreateGate.retryAfterMs ?? 0) / 1000);
			return new Response('Rate limit exceeded', {
				status: 429,
				headers: { 'retry-after': String(retryAfterSeconds) },
			});
		}
	}

	const legacySessionId = await createSession(c.env.SESSION_STORE, createAnalyticsClient(c.env.MCP_ANALYTICS), (p) =>
		c.executionCtx.waitUntil(p),
	);
	const endpointUrl = new URL(`/mcp/messages?sessionId=${encodeURIComponent(legacySessionId)}`, c.req.url).toString();
	return openLegacySseStream(legacySessionId, endpointUrl);
});

app.delete('/mcp', async (c) => {
	const ip = resolveClientIpFromRequestHeaders(c.req.raw.headers);
	const isAuthenticated = c.get('isAuthenticated');
	const controlPlaneLimited = await buildControlPlaneRateLimitResponse(
		ip,
		c.env.RATE_LIMIT,
		'session/delete',
		isAuthenticated,
		null,
		undefined,
		c.env.QUOTA_COORDINATOR,
	);
	if (controlPlaneLimited) {
		return controlPlaneLimited;
	}

	const sessionId = c.req.header('mcp-session-id');
	const sessionError = await validateSessionRequest(
		sessionId,
		c.env.SESSION_STORE,
		null,
		'Bad Request: missing Mcp-Session-Id header. Include the session ID from your initialize response.',
	);
	if (sessionError) {
		return c.json(sessionError.payload, sessionError.status);
	}

	await deleteSession(sessionId!, c.env.SESSION_STORE);
	closeLegacyStream(sessionId!);
	const analytics = createAnalyticsClient(c.env.MCP_ANALYTICS);
	const cfProps = c.req.raw.cf as IncomingRequestCfProperties | undefined;
	const tierResult = c.get('tierAuthResult');
	analytics.emitSessionEvent({
		action: 'terminated',
		country: (cfProps?.country as string) ?? 'unknown',
		clientType: detectMcpClient(c.req.header('user-agent') ?? ''),
		authTier: tierResult.authenticated ? (tierResult.tier ?? 'free') : 'anon',
		keyHash: tierResult.keyHash ? tierResult.keyHash.slice(0, 16) : undefined,
	});
	return new Response(null, { status: 204 });
});

app.route('/internal', internalRoutes);

// OAuth 2.1 discovery endpoints (RFC 8414 + RFC 9728).
//
// Every route below dispatches on `oauthAvailability(c.env)` rather than a
// boolean. `'disabled'` → 404 (feature off). `'misconfigured'` → 503 (feature
// on but signing secret missing/short — fail-fast at first RTT instead of
// after the user completes the consent dance).
function oauthGuarded<T>(c: Context, ready: () => T | Response): T | Response {
	const state = oauthAvailability(c.env as Pick<BvMcpEnv, 'ENABLE_OAUTH' | 'OAUTH_SIGNING_SECRET'>);
	if (state === 'disabled') return oauthDisabledResponse();
	if (state === 'misconfigured') return oauthMisconfiguredResponse();
	return ready();
}

app.on('GET', ['/.well-known/oauth-authorization-server', '/.well-known/oauth-authorization-server/*'], (c) =>
	oauthGuarded(c, () => c.json(buildAuthorizationServerMetadata(resolveIssuer(c.req.url, c.env.OAUTH_ISSUER)))),
);
app.on('GET', ['/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/*'], (c) =>
	oauthGuarded(c, () => c.json(buildProtectedResourceMetadata(resolveIssuer(c.req.url, c.env.OAUTH_ISSUER)))),
);
app.post('/oauth/register', (c) => oauthGuarded(c, () => handleRegister(c)));
app.get('/oauth/authorize', (c) => oauthGuarded(c, () => handleAuthorizeGet(c)));
app.post('/oauth/authorize', (c) => oauthGuarded(c, () => handleAuthorizePost(c)));
app.post('/oauth/token', (c) => oauthGuarded(c, () => handleToken(c)));

app.all('*', (c) => {
	// Plain text — avoids mcp-remote misinterpreting JSON as an OAuth error.
	// OAuth well-known paths are handled explicitly above.
	return c.text('Not found', 404);
});

import { handleScheduled, handleDailyDigest, handleFuzzingScan, handleBrandAuditWatches } from './scheduled';
import type { ScheduledEnv } from './scheduled';
import { handleScanQueue, type ScanQueueConsumerEnv } from './tenants/queue-consumer';
import { handleBrandAuditQueue, type BrandAuditConsumerDeps } from './queue/brand-audit-consumer';
import { handleBrandAuditPdfQueue, type BrandAuditPdfConsumerDeps } from './queue/brand-audit-pdf-consumer';
import { handleTenantCycleAlerts, handleTenantWeeklyRescan, type TenantScheduledEnv } from './tenants/scheduled-handlers';

export default {
	fetch: (req: Request, env: Record<string, unknown>, ctx: ExecutionContext) => app.fetch(req, env, ctx),
	scheduled: async (event: ScheduledEvent, env: Record<string, unknown>, ctx: ExecutionContext) => {
		// Each handler is dispatched via its own waitUntil so a failure in one
		// (e.g. Tenant alert sweep throws) cannot mask the others' analytics outcome.
		if (event.cron === '0 8 * * *') {
			ctx.waitUntil(handleDailyDigest(env as ScheduledEnv));
		} else if (event.cron === '0 2 * * 0') {
			// Weekly Tenant rescan dispatch — Sunday 02:00 UTC.
			ctx.waitUntil(handleTenantWeeklyRescan(env as TenantScheduledEnv, ctx));
		} else {
			ctx.waitUntil(handleScheduled(env as ScheduledEnv));
			ctx.waitUntil(handleFuzzingScan(env as ScheduledEnv));
			ctx.waitUntil(handleTenantCycleAlerts(env as TenantScheduledEnv, ctx));
			ctx.waitUntil(handleBrandAuditWatches(env, ctx));
		}
	},
	/**
	 * Queue consumer dispatch. Routes by `batch.queue` since both
	 * `bv-scanner-queue` (tenant scans) and `brand-audit-queue` (brand-audit
	 * async path, v2.19.0+) share the same Worker entrypoint.
	 */
	queue: async (batch: MessageBatch<unknown>, env: Record<string, unknown>, ctx: ExecutionContext) => {
		logEvent({
			timestamp: new Date().toISOString(),
			category: 'queue',
			result: 'batch_received',
			severity: 'info',
			details: { queue: batch.queue, messageCount: batch.messages.length },
		});
		if (batch.queue === 'brand-audit-queue') {
			const e = env as Record<string, unknown>;
			const db = e.BRAND_AUDIT_DB as D1Database | undefined;
			if (!db) {
				// Binding missing — ack every message to avoid hot-looping. Operator
				// must provision per docs/provisioning/brand-audit-bindings.md.
				for (const m of batch.messages) m.ack();
				return;
			}
			const pdfQueue = e.BRAND_AUDIT_PDF_QUEUE as BrandAuditConsumerDeps['pdfQueue'] | undefined;
			// Phase 2b: thread the BRAND_AUDIT_QUEUE binding back into the consumer
			// so the retry-enqueue path can fire. Same binding the producer uses;
			// the consumer enqueues a `retry_attempt: 1` message back onto itself
			// when a completed audit has registrar lookup_failed candidates.
			const brandAuditQueue = e.BRAND_AUDIT_QUEUE as BrandAuditConsumerDeps['brandAuditQueue'] | undefined;
			// T13 — thread the BlackVeil-production discovery_mode override
			// into the consumer so queued audits run in tiered mode by default
			// when the operator sets `BRAND_AUDIT_DISCOVERY_MODE_DEFAULT=tiered`
			// in the private overlay. Undefined on BSL self-hosts.
			const discoveryModeDefault =
				typeof e.BRAND_AUDIT_DISCOVERY_MODE_DEFAULT === 'string' ? (e.BRAND_AUDIT_DISCOVERY_MODE_DEFAULT as string) : undefined;
			// Build tier-lookup closures from the queue Worker invocation's env.
			// Cloudflare Workers re-bind env per invocation; the request-path
			// closures constructed in `executeMcpRequest` never reach here.
			const tierLookups = buildBrandTierLookups(e as BvMcpEnv);
			// Build internalCall closure for the CSC deep-scan job. Wraps
			// handleToolsCall so the job can invoke scan_domain / discover_subdomains
			// without HTTP framing. Dynamic import keeps the queue cold-start path
			// unaffected; the import is cached after the first deep-scan message.
			const queueEnv = e as BvMcpEnv;
			const internalCall = async (tool: string, args: { domain: string }): Promise<unknown> => {
				const { handleToolsCall } = await import('./handlers/tools');
				return handleToolsCall({ name: tool, arguments: args as Record<string, unknown> }, queueEnv.SCAN_CACHE, {
					providerSignaturesUrl: queueEnv.PROVIDER_SIGNATURES_URL,
					scoringConfig: parseScoringConfigCached(queueEnv.SCORING_CONFIG),
					scanTimeoutMs: parseScanTimeout(queueEnv.SCAN_TIMEOUT_MS),
					perCheckTimeoutMs: parsePerCheckTimeout(queueEnv.PER_CHECK_TIMEOUT_MS),
					secondaryDoh: queueEnv.BV_DOH_ENDPOINT ? { endpoint: queueEnv.BV_DOH_ENDPOINT, token: queueEnv.BV_DOH_TOKEN } : undefined,
					whoisBinding: queueEnv.BV_WHOIS,
					infraProbe: queueEnv.BV_INFRA_PROBE,
					certstream: queueEnv.BV_CERTSTREAM,
					certstreamAuthToken: certstreamAuthToken(queueEnv),
					profileAccumulator: queueEnv.PROFILE_ACCUMULATOR,
					...buildBrandTierLookups(queueEnv),
				});
			};
			const deps: BrandAuditConsumerDeps = {
				db,
				pdfQueue,
				brandAuditQueue,
				discoveryModeDefault,
				whoisBinding: e.BV_WHOIS as Fetcher | undefined,
				certstream: e.BV_CERTSTREAM as Fetcher | undefined,
				internalCall,
				...tierLookups,
			};
			await handleBrandAuditQueue(batch, deps);
			return;
		}
		if (batch.queue === 'brand-audit-pdf-queue') {
			const e = env as Record<string, unknown>;
			const db = e.BRAND_AUDIT_DB as D1Database | undefined;
			const bucket = e.BRAND_REPORTS as R2Bucket | undefined;
			if (!db || !bucket) {
				// Required bindings missing — ack to avoid hot-looping.
				for (const m of batch.messages) m.ack();
				return;
			}
			// Renderer is now in-process (pdf-lib); BV_BROWSER_RENDERER + KEY
			// no longer required for brand-audit PDF generation.
			const deps: BrandAuditPdfConsumerDeps = { db, bucket, serverVersion: SERVER_VERSION };
			await handleBrandAuditPdfQueue(batch, deps);
			return;
		}
		await handleScanQueue(batch, env as ScanQueueConsumerEnv, ctx);
	},
};
