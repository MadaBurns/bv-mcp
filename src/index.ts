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

// INERT — the bv-wasm-core crate (estimateTokens / checkPermission / compaction)
// is a fully-built, fully-tested subsystem that is NOT wired into any code path
// here. It was previously `initSync`'d at module load, adding cold-start + bundle
// cost for functions nothing in the Worker ever called. The import + init were
// removed so the crate stops loading on every request. It remains a STAGED SEAM:
// the crate and its tests (test/wasm-integration.test.ts, which self-inits) are
// intentionally retained for a future wiring. Re-add the import + `initSync(wasm)`
// only when a real call site consumes an exported function. Operator note: safe
// to keep unwired; do not delete the crate.

import { checkControlPlaneRateLimit, checkDistinctDomainDailyLimit, checkGlobalDailyLimit, checkRateLimit, checkToolDailyRateLimit } from './lib/rate-limiter';
import { logEvent, logError, sanitizeHeadersForLog } from './lib/log';
import { jsonRpcError, JSON_RPC_ERRORS } from './lib/json-rpc';
import { normalizeHeaders, parseJsonRpcRequest, readRequestBody, validateContentType } from './mcp/request';
import { createSession, deleteSession, validateSession, checkSessionCreateRateLimit } from './lib/session';
import { unauthorizedResponse } from './lib/auth';
import { sseEvent, acceptsSSE, createNotificationStream, sseErrorResponse, createStreamingSseResponse } from './lib/sse';
import { createAnalyticsClient, hashDomain, hashForAnalytics, hashIpForAnalytics } from './lib/analytics';
import { detectMcpClient } from './lib/client-detection';
import { parseAnalyticsPiiLevel } from './lib/analytics-pii';
import type { JsonRpcRequest } from './lib/json-rpc';
import { buildControlPlaneRateLimitResponse, resolveSseSession, validateSessionRequest } from './mcp/route-gates';
import {
	FREE_DISTINCT_DOMAIN_DAILY_LIMIT,
	FREE_TOOL_DAILY_LIMITS,
	MAX_REQUEST_BODY_BYTES,
	isValidOAuthSigningSecret,
	parseCacheTtl,
	parseGlobalDailyLimit,
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
import { SINGLETON_ROUTING } from './lib/quota-coordinator';
export { ProfileAccumulator } from './lib/profile-accumulator';
import { resolveAccumulatorShardModeFromEnv } from './lib/profile-accumulator';

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
	/**
	 * R8 / ADAM #2 — QuotaCoordinator sharding feature flag. DEFAULT-OFF: only the
	 * literal string `'true'` enables shard routing of the per-IP quota path. Unset
	 * or any other value keeps every quota check on the single
	 * `global-quota-coordinator` instance (byte-for-byte today's behavior). Flipping
	 * it ON at a low-traffic window resets every per-IP / per-tool-daily counter ONCE
	 * (see CHANGELOG + runbook); flipping it OFF is the instant rollback lever.
	 */
	QUOTA_SHARDING_ENABLED?: string;
	/**
	 * ADAM #4 — deploy-time salt mixed into the shard-key hash so an IP-range / botnet
	 * operator cannot precompute which addresses land on a chosen shard. Only consulted
	 * when sharding is enabled. Treat a change like a flag flip (re-maps every counter).
	 */
	QUOTA_SHARD_SALT?: string;
	PROFILE_ACCUMULATOR?: DurableObjectNamespace;
	/**
	 * R10 — ProfileAccumulator write-sharding mode. Default-OFF: only the exact
	 * string `'profile'` enables per-profile sharding (6 DO instances); any other
	 * value (including unset) keeps the legacy single `global` instance, so an
	 * unset deploy is byte-for-byte identical to today. Resolved via
	 * `resolveAccumulatorShardModeFromEnv` and threaded into ToolRuntimeOptions so
	 * the /ingest write, /weights read, AND the intelligence read seams co-route.
	 * DORMANT in this branch — flipping it is a SEPARATE, separately-reviewed
	 * change deployed at a low-traffic window (watch the warm-up degradation signal).
	 */
	PROFILE_ACCUMULATOR_SHARDING?: string;
	MCP_ANALYTICS?: AnalyticsEngineDataset;
	BV_API_KEY?: string;
	/** Comma-separated IP allowlist for owner tier. When set, an owner-tier credential (static `BV_API_KEY` or owner JWT) from a non-listed client IP is downgraded to `partner` (`applyOwnerIpGate` in `lib/tier-auth.ts`). Unset/empty → owner unrestricted (self-hosted/dev). */
	OWNER_ALLOW_IPS?: string;
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
	/** Second independent static internal-dev key (owner tier, OWNER_ALLOW_IPS-gated). Lets a per-machine key be added without rotating BV_INTERNAL_DEV_KEY. */
	BV_INTERNAL_DEV_KEY_2?: string;
	BRAND_AUDIT_DB?: D1Database;
	INTELLIGENCE_DB?: D1Database;
	MCP_ANALYTICS_QUEUE?: { send(message: unknown, options?: { contentType?: 'json' }): Promise<void> };
	/** PII capture depth for mcp_access_log: coarse | standard | full. Default coarse. */
	ANALYTICS_PII_LEVEL?: string;
	/** Retention window (days) for mcp_access_log rows. Default 90. */
	ANALYTICS_RETENTION_DAYS?: string;
	/**
	 * Phase 1, decision #2 (default-off). `'true'` routes internal-source access-log
	 * writes to the `mcp_access_rollup` counter instead of per-event rows. Unset/any
	 * other value = per-event for everything (today's behavior).
	 */
	ANALYTICS_ROLLUP_INTERNAL?: string;
	/**
	 * Phase 1, decision #3 (default-off). `'true'` + the `MCP_ACCESS_LOG_ARCHIVE`
	 * binding present switches the retention cron from a hard DELETE to
	 * archive-then-delete (gzipped NDJSON, non-PII columns only) to R2.
	 */
	ANALYTICS_ARCHIVE_ENABLED?: string;
	/** Phase 1, decision #3 — R2 object lifetime (days) for archived NDJSON. Documentation-only; enforced by the bucket lifecycle rule, not code. */
	ANALYTICS_ARCHIVE_RETENTION_DAYS?: string;
	/** Phase 1, decision #3 — R2 bucket for the short-bridge access-log archive. Absent → retention cron keeps today's hard DELETE. */
	MCP_ACCESS_LOG_ARCHIVE?: R2Bucket;
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

	// ─────────────────────────────────────────────────────────────────────────
	// Scaling roadmap seams — TYPED, DEFAULT-OFF, ZERO behavior change.
	// All fields below are optional and UNUSED by runtime code today (no branch
	// reads them). They exist so Phase 2 (scheduled/queue-driven scanning) and
	// Phase 4 (Workers-for-Platforms multi-tenancy) can land without re-typing the
	// env. Typed readers live in `src/lib/scaling-flags.ts`; spec + decisions in
	// `docs/superpowers/scaling-millions-domains-multitenancy.md` (companion
	// `scaling-gates-resolved.md`). Unset on every deploy today → behavior is
	// byte-for-byte identical. (R8 quota-sharding + R10 profile-sharding flags
	// already exist above — NOT duplicated here.)
	// ─────────────────────────────────────────────────────────────────────────

	/**
	 * Phase 2 (scheduler) — D1 holding the `scan_schedule` table the cron
	 * dispatcher claim-and-advances (Form B subquery, see
	 * `scaling-millions-domains-multitenancy.md` Gate 4). TODO(phase-2): wire the
	 * scheduled handler once provisioned. Absent today → no scheduled scanning.
	 */
	SCAN_SCHEDULE_DB?: D1Database;
	/**
	 * Phase 2 (scheduler) — low-priority "slow lane" Queue the dispatcher fans
	 * claimed schedule rows onto so background re-scans never contend with the
	 * interactive `/mcp` path. TODO(phase-2): bind + add a consumer. Absent today
	 * → nothing is enqueued. See `scaling-millions-domains-multitenancy.md`.
	 */
	BV_SCANNER_SLOW_QUEUE?: Queue;
	/**
	 * Phase 2 (scheduler) — master default-OFF flag. Only the exact string
	 * `'true'` will arm the cron dispatcher in a later phase; unset/any other
	 * value keeps the scheduler dormant (today's behavior). Read via
	 * `resolveScanDispatchConfig` in `lib/scaling-flags.ts`.
	 * TODO(phase-2): consult before claiming schedule rows.
	 */
	SCAN_DISPATCH_ENABLED?: string;
	/**
	 * Phase 2 (scheduler) — max schedule rows to claim per cron tick (the
	 * `LIMIT ?` in the Form-B claim query). String (env-var); parsed + clamped by
	 * `resolveScanDispatchConfig`. Unset → a conservative built-in default that is
	 * inert while `SCAN_DISPATCH_ENABLED` is off.
	 */
	SCAN_DISPATCH_BATCH_SIZE?: string;

	/**
	 * Phase 4 (multi-tenancy) — Workers-for-Platforms dispatch namespace binding.
	 * Placeholder seam: paid tenants get a per-tenant D1 via dynamic dispatch
	 * (`env.TENANT_DISPATCH_NAMESPACE.get(name, args, { limits })`) instead of a
	 * baked binding + redeploy per tenant. TODO(phase-4): construct the tenant
	 * resolver from this when present. Absent today → string-convention binding
	 * routing only (today's behavior). See
	 * `scaling-millions-domains-multitenancy.md` Phase-4 routing spike.
	 */
	TENANT_DISPATCH_NAMESPACE?: DispatchNamespace;
	/**
	 * Phase 4 (multi-tenancy) — Cloudflare API token for the REST-by-id D1
	 * operator fallback (`d1_db_id` revival) when dynamic dispatch is unavailable.
	 * Operator-only; declared in the private overlay, never public
	 * `wrangler.jsonc`. TODO(phase-4). Absent today → no REST fallback path.
	 */
	CF_D1_API_TOKEN?: string;
	/**
	 * Phase 4 (multi-tenancy) — tenant routing mode, default-OFF. Only the exact
	 * string `'dispatch'` will select Workers-for-Platforms dynamic dispatch in a
	 * later phase; unset/any other value keeps the legacy binding-name string
	 * convention (today's behavior). Read via `resolveTenantRoutingMode` in
	 * `lib/scaling-flags.ts`. TODO(phase-4).
	 */
	TENANT_ROUTING_MODE?: string;
	/** Optional override of the global unauthenticated daily tools/call cap (clamped [10000, 5000000]). */
	GLOBAL_DAILY_TOOL_LIMIT?: string;
};

import type { TierAuthResult } from './lib/tier-auth';
import { resolveTier } from './lib/tier-auth';

/** Shared Hono app env (bindings + per-request variables). Exported so route handlers in `oauth/` can type `Context<AppEnv>` instead of casting `c.env`. */
export type AppEnv = {
	Bindings: BvMcpEnv;
	Variables: { isAuthenticated: boolean; tierAuthResult: TierAuthResult; apiKeyInQuery: boolean };
};
const app = new Hono<AppEnv>();
const mcpPaths = ['/mcp', '/mcp/messages', '/mcp/sse'] as const;
// Paths that share the MCP CORS/Origin/bearer-auth middleware stack. The
// /reports/* download route authenticates with the same credential as the
// MCP tools so its owner check matches `brand_audits.owner_id`.
const authedPaths = [...mcpPaths, '/reports/*'] as const;

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

/**
 * R8 / ADAM #2+#4 — build the QuotaCoordinator shard routing from env. DEFAULT-OFF:
 * only the exact string `'true'` enables sharding; anything else (including unset)
 * yields `SINGLETON_ROUTING`, i.e. every quota check stays on the single
 * `global-quota-coordinator` instance — byte-for-byte today's behavior.
 */
function resolveQuotaShardRouting(env: BvMcpEnv): import('./lib/quota-coordinator').ShardRouting {
	if (env.QUOTA_SHARDING_ENABLED !== 'true') return SINGLETON_ROUTING;
	return { enabled: true, salt: env.QUOTA_SHARD_SALT ?? '' };
}

/**
 * F2 — mint a server-generated correlation id for an inbound request. Prefers
 * Cloudflare's `cf-ray` (the edge request id) when present so the bv-mcp trace
 * stitches against CF's own logs, otherwise falls back to a fresh
 * `crypto.randomUUID()`. This is the single per-request id threaded through
 * `ExecuteMcpRequestOptions.correlationId` into every `logEvent` on the path —
 * distinct from the client-chosen JSON-RPC id.
 */
export function makeCorrelationId(headers: Headers): string {
	const cfRay = headers.get('cf-ray');
	if (cfRay && /^[a-zA-Z0-9-]{1,64}$/.test(cfRay)) return cfRay;
	return crypto.randomUUID();
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

for (const path of authedPaths) {
	app.use(
		path,
		cors({
			origin: (origin, c: Context<AppEnv>) => {
				if (!origin) return '';
				const result = checkOrigin(origin, c.req.url, c.env.ALLOWED_ORIGINS?.trim());
				return result === 'allowed' ? origin : '';
			},
			allowMethods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
			allowHeaders: ['Content-Type', 'Accept', 'Mcp-Session-Id', 'MCP-Protocol-Version', 'Last-Event-ID', 'Authorization'],
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

/**
 * F5 — bounded round-trip probe of a single binding for the deep-readiness mode.
 * Each probe is wrapped in `Promise.race` against a hard 1.5s ceiling so a wedged
 * binding can't hang the health endpoint (which uptime monitors poll). Any thrown
 * error or timeout → `'error'`; a successful round-trip → `'ok'`; an absent
 * binding → `'absent'` (BSL self-hosts legitimately omit these).
 */
const DEEP_HEALTH_PROBE_TIMEOUT_MS = 1500;

async function probeWithTimeout(work: () => Promise<void>): Promise<'ok' | 'error'> {
	try {
		await Promise.race([
			work(),
			new Promise<never>((_, reject) => setTimeout(() => reject(new Error('probe_timeout')), DEEP_HEALTH_PROBE_TIMEOUT_MS)),
		]);
		return 'ok';
	} catch {
		return 'error';
	}
}

async function probeScanCacheKv(kv: KVNamespace | undefined): Promise<'ok' | 'error' | 'absent'> {
	if (!kv) return 'absent';
	return probeWithTimeout(async () => {
		// Best-effort round-trip on a dedicated, short-lived health key. A get/put
		// pair exercises both read and write paths without touching live data.
		const key = `health:probe:${crypto.randomUUID()}`;
		await kv.put(key, '1', { expirationTtl: 60 });
		await kv.get(key);
		await kv.delete(key);
	});
}

async function probeQuotaCoordinator(ns: DurableObjectNamespace | undefined): Promise<'ok' | 'error' | 'absent'> {
	if (!ns) return 'absent';
	return probeWithTimeout(async () => {
		// A GET to the DO returns 405 (it only accepts POST) — that non-error
		// HTTP response still proves the DO is reachable and responding. Any
		// transport-level throw (DO unreachable) is caught and reported as error.
		const stub = ns.get(ns.idFromName('health-probe'));
		await stub.fetch('https://do/health');
	});
}

function bindingPresence(value: unknown): 'ok' | 'absent' {
	return value ? 'ok' : 'absent';
}

function envFlagEnabled(value: unknown): boolean {
	return typeof value === 'string' && value.toLowerCase() === 'true';
}

app.get('/health', async (c) => {
	const deep = c.req.query('deep');
	if (deep !== '1' && deep !== 'true') {
		// Cheap default liveness path — UNCHANGED. No binding I/O, no auth.
		return c.json({
			status: 'ok',
			service: 'bv-dns-security-mcp',
			timestamp: new Date().toISOString(),
		});
	}

	// Deep readiness mode is owner-gated: it does binding I/O (load-amplification
	// surface for an unauthenticated poller) so we require an owner-tier credential.
	// The `/health` route has no auth middleware (it isn't an mcpPath), so resolve
	// the bearer here directly. OWNER_ALLOW_IPS still applies via resolveTier.
	const authHeader = c.req.header('authorization');
	const token = authHeader?.startsWith('Bearer ') ? authHeader.slice(7).trim() : null;
	const resolvedClientIp = resolveClientIpFromRequestHeaders(c.req.raw.headers);
	const clientIp = resolvedClientIp === 'unknown' ? undefined : resolvedClientIp;
	const tier = await resolveTier(token, c.env, clientIp, c.req.url);
	if (!tier.authenticated || tier.tier !== 'owner') {
		return c.json({ error: 'forbidden', error_description: 'Deep health checks require an owner-tier credential' }, 403);
	}

	const [scanCache, quotaCoordinator] = await Promise.all([
		probeScanCacheKv(c.env.SCAN_CACHE),
		probeQuotaCoordinator(c.env.QUOTA_COORDINATOR),
	]);

	const e = c.env as Record<string, unknown>;
	const bindings = {
		scanCache,
		quotaCoordinator,
		tenantRegistryDb: bindingPresence(e.TENANT_REGISTRY_DB),
		scannerQueue: bindingPresence(e.BV_SCANNER_QUEUE),
		brandAuditDb: bindingPresence(e.BRAND_AUDIT_DB),
		brandReports: bindingPresence(e.BRAND_REPORTS),
		brandAuditQueue: bindingPresence(e.BRAND_AUDIT_QUEUE),
		brandAuditPdfQueue: bindingPresence(e.BRAND_AUDIT_PDF_QUEUE),
		alertWebhook: bindingPresence(e.ALERT_WEBHOOK_URL),
	};
	// Overall status degrades only on an actual probe error; an 'absent' binding
	// (BSL self-host) is not a failure of a provisioned dependency.
	const requireProductionBindings = envFlagEnabled(e.REQUIRE_PRODUCTION_BINDINGS);
	const degraded = Object.values(bindings).some((status) => status === 'error') || (requireProductionBindings && Object.values(bindings).some((status) => status === 'absent'));

	return c.json(
		{
			status: degraded ? 'degraded' : 'ok',
			service: 'bv-dns-security-mcp',
			timestamp: new Date().toISOString(),
			bindings,
		},
		degraded ? 503 : 200,
	);
});

/** 429 SVG badge response with an optional retry-after header (seconds). */
function badgeRateLimitResponse(svgHeaders: Record<string, string>, retryAfterMs?: number): Response {
	const headers: Record<string, string> = { ...svgHeaders };
	if (retryAfterMs !== undefined) {
		headers['retry-after'] = String(Math.ceil(retryAfterMs / 1000));
	}
	return new Response(errorBadge(), { status: 429, headers });
}

app.get('/badge/:domain', async (c) => {
	const svgHeaders = {
		'Content-Type': 'image/svg+xml',
		'Cache-Control': 'public, max-age=300',
	};

	const ip = resolveClientIpFromRequestHeaders(c.req.raw.headers);
	const rateResult = await checkRateLimit(ip, c.env.RATE_LIMIT, c.env.QUOTA_COORDINATOR);
	if (!rateResult.allowed) {
		return badgeRateLimitResponse(svgHeaders, rateResult.retryAfterMs);
	}

	// The badge runs the full scan engine unauthenticated, so it must apply the
	// SAME anti-enumeration caps the anonymous POST /mcp path enforces in
	// executeMcpRequest — not just the per-IP + per-tool caps. Without these, an
	// unauthenticated IP could scan up to 25 DISTINCT domains/day here (vs the
	// intended 12) and those scans would escape the global daily cap entirely.
	const globalResult = await checkGlobalDailyLimit(parseGlobalDailyLimit(c.env.GLOBAL_DAILY_TOOL_LIMIT), c.env.RATE_LIMIT, c.env.QUOTA_COORDINATOR);
	if (!globalResult.allowed) {
		return badgeRateLimitResponse(svgHeaders, globalResult.retryAfterMs);
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

	// Distinct-domain/day cap (tighter than the per-tool 25/day) — mirrors the
	// executeMcpRequest speed-bump so /badge can't be used to enumerate a wider
	// distinct-domain set than /mcp. Keyed on the per-IP principal; fail-open.
	const distinctResult = await checkDistinctDomainDailyLimit(ip, hashDomain(domain), FREE_DISTINCT_DOMAIN_DAILY_LIMIT, c.env.RATE_LIMIT);
	if (!distinctResult.allowed) {
		return badgeRateLimitResponse(svgHeaders, distinctResult.retryAfterMs);
	}

	try {
		const result = await scanDomain(domain, c.env.SCAN_CACHE, {
			profileAccumulator: c.env.PROFILE_ACCUMULATOR,
			profileAccumulatorShardMode: resolveAccumulatorShardModeFromEnv(c.env.PROFILE_ACCUMULATOR_SHARDING),
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
	// F2 — one server-generated correlation id per inbound request, threaded into
	// every executeMcpRequest below (and onward into every logEvent on the path)
	// so multi-line traces can be stitched. cf-ray (Cloudflare's edge request id)
	// is folded in when present for cross-correlation with CF logs.
	const correlationId = makeCorrelationId(c.req.raw.headers);
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
	// Edge colo (`cf.colo`, e.g. AKL/SYD) — appended as the trailing analytics blob so
	// per-datacenter p95/error-rate can be isolated (a single-colo regression otherwise
	// averages out across the global aggregate). Undefined off-CF / in tests → 'unknown'.
	const colo = (cfProps?.colo as string | undefined) ?? 'unknown';
	const region = (cfProps?.region as string | undefined) ?? undefined;
	const city = (cfProps?.city as string | undefined) ?? undefined;
	const latitude = (cfProps?.latitude as string | undefined) ?? undefined;
	const longitude = (cfProps?.longitude as string | undefined) ?? undefined;
	const asn = typeof cfProps?.asn === 'number' ? cfProps.asn : undefined;
	const asOrg = (cfProps?.asOrganization as string | undefined) ?? undefined;

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

	// MCP Streamable HTTP requires a 400 for an unsupported protocol-version header.
	// An absent header remains compatible with older clients and initialize is exempt
	// because protocol negotiation has not happened yet.
	const singleMethod = parsedRequest.isBatch ? undefined : (parsedBodies[0] as JsonRpcRequest | undefined)?.method;
	if (singleMethod !== 'initialize' && classifyProtocolVersionHeader(headersLc['mcp-protocol-version']) === 'unsupported') {
		logEvent({
			timestamp: new Date().toISOString(),
			severity: 'warn',
			category: 'protocol',
			result: 'Unsupported MCP-Protocol-Version header rejected',
			details: { protocolVersionHeader: headersLc['mcp-protocol-version'], method: singleMethod ?? 'batch' },
			ipHash,
		});
		return sseErrorResponse(
			jsonRpcError(null, JSON_RPC_ERRORS.INVALID_REQUEST, 'Unsupported MCP-Protocol-Version header'),
			400,
			accept,
		);
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
					correlationId,
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
					quotaShardRouting: resolveQuotaShardRouting(c.env),
					globalDailyLimit: parseGlobalDailyLimit(c.env.GLOBAL_DAILY_TOOL_LIMIT),
					sessionStore: c.env.SESSION_STORE,
					scanCache: c.env.SCAN_CACHE,
					providerSignaturesUrl: c.env.PROVIDER_SIGNATURES_URL,
					providerSignaturesAllowedHosts: c.env.PROVIDER_SIGNATURES_ALLOWED_HOSTS,
					providerSignaturesSha256: c.env.PROVIDER_SIGNATURES_SHA256,
					analytics,
					profileAccumulator: c.env.PROFILE_ACCUMULATOR,
					profileAccumulatorShardMode: resolveAccumulatorShardModeFromEnv(c.env.PROFILE_ACCUMULATOR_SHARDING),
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
					certstreamAuthToken: certstreamAuthToken(c.env),
					whoisBinding: c.env.BV_WHOIS,
					reconBinding: c.env.BV_RECON,
					reconAuthToken: c.env.BV_RECON_KEY,
					tlsProbeBinding: c.env.BV_TLS_PROBE,
					tlsProbeAuthToken: c.env.BV_TLS_PROBE_KEY,
					m365Proxy: c.env.BV_WEB,
					m365ProxyAuthToken: c.env.BV_WEB_INTERNAL_KEY,
					bvWebBenchmark: c.env.BV_WEB,
					bvWebBenchmarkAuthToken: c.env.BV_WEB_INTERNAL_KEY,
					infraProbe: c.env.BV_INFRA_PROBE,
					brandAuditDb: c.env.BRAND_AUDIT_DB,
					brandAuditQueue: c.env.BRAND_AUDIT_QUEUE,
					brandReportsR2: c.env.BRAND_REPORTS,
					publicOrigin: new URL(c.req.url).origin,
					browserRenderer: c.env.BV_BROWSER_RENDERER,
					discoveryModeDefault: c.env.BRAND_AUDIT_DISCOVERY_MODE_DEFAULT,
					...buildBrandTierLookups(c.env),
					principalId: keyHash ?? ipHash,
					country,
					clientType,
					protocolVersionHeader: headersLc['mcp-protocol-version'],
					authTier,
					keyHash,
					sessionHash,
					ipHash,
					colo,
					region,
					city,
					latitude,
					longitude,
					asn,
					asOrg,
					analyticsQueue: c.env.MCP_ANALYTICS_QUEUE,
					analyticsPiiLevel: parseAnalyticsPiiLevel(c.env.ANALYTICS_PII_LEVEL),
					rollupInternal: c.env.ANALYTICS_ROLLUP_INTERNAL === 'true',
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
		correlationId,
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
		quotaShardRouting: resolveQuotaShardRouting(c.env),
		globalDailyLimit: parseGlobalDailyLimit(c.env.GLOBAL_DAILY_TOOL_LIMIT),
		sessionStore: c.env.SESSION_STORE,
		scanCache: c.env.SCAN_CACHE,
		providerSignaturesUrl: c.env.PROVIDER_SIGNATURES_URL,
		providerSignaturesAllowedHosts: c.env.PROVIDER_SIGNATURES_ALLOWED_HOSTS,
		providerSignaturesSha256: c.env.PROVIDER_SIGNATURES_SHA256,
		analytics,
		profileAccumulator: c.env.PROFILE_ACCUMULATOR,
		profileAccumulatorShardMode: resolveAccumulatorShardModeFromEnv(c.env.PROFILE_ACCUMULATOR_SHARDING),
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
		certstreamAuthToken: certstreamAuthToken(c.env),
		whoisBinding: c.env.BV_WHOIS,
		reconBinding: c.env.BV_RECON,
		reconAuthToken: c.env.BV_RECON_KEY,
		tlsProbeBinding: c.env.BV_TLS_PROBE,
		tlsProbeAuthToken: c.env.BV_TLS_PROBE_KEY,
		m365Proxy: c.env.BV_WEB,
		m365ProxyAuthToken: c.env.BV_WEB_INTERNAL_KEY,
		bvWebBenchmark: c.env.BV_WEB,
		bvWebBenchmarkAuthToken: c.env.BV_WEB_INTERNAL_KEY,
		infraProbe: c.env.BV_INFRA_PROBE,
		brandAuditDb: c.env.BRAND_AUDIT_DB,
		brandAuditQueue: c.env.BRAND_AUDIT_QUEUE,
		brandReportsR2: c.env.BRAND_REPORTS,
		publicOrigin: new URL(c.req.url).origin,
		browserRenderer: c.env.BV_BROWSER_RENDERER,
		discoveryModeDefault: c.env.BRAND_AUDIT_DISCOVERY_MODE_DEFAULT,
		...buildBrandTierLookups(c.env),
		principalId: keyHash ?? ipHash,
		country,
		clientType,
		protocolVersionHeader: headersLc['mcp-protocol-version'],
		authTier,
		keyHash,
		sessionHash,
		ipHash,
		colo,
		region,
		city,
		latitude,
		longitude,
		asn,
		asOrg,
		analyticsQueue: c.env.MCP_ANALYTICS_QUEUE,
		analyticsPiiLevel: parseAnalyticsPiiLevel(c.env.ANALYTICS_PII_LEVEL),
		rollupInternal: c.env.ANALYTICS_ROLLUP_INTERNAL === 'true',
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
	// F2 — per-request correlation id for the legacy SSE message path.
	const correlationId = makeCorrelationId(c.req.raw.headers);
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
	const region = (cfProps?.region as string | undefined) ?? undefined;
	const city = (cfProps?.city as string | undefined) ?? undefined;
	const latitude = (cfProps?.latitude as string | undefined) ?? undefined;
	const longitude = (cfProps?.longitude as string | undefined) ?? undefined;
	const asn = typeof cfProps?.asn === 'number' ? cfProps.asn : undefined;
	const asOrg = (cfProps?.asOrganization as string | undefined) ?? undefined;

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
				correlationId,
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
				quotaShardRouting: resolveQuotaShardRouting(c.env),
				globalDailyLimit: parseGlobalDailyLimit(c.env.GLOBAL_DAILY_TOOL_LIMIT),
				sessionStore: c.env.SESSION_STORE,
				scanCache: c.env.SCAN_CACHE,
				providerSignaturesUrl: c.env.PROVIDER_SIGNATURES_URL,
				providerSignaturesAllowedHosts: c.env.PROVIDER_SIGNATURES_ALLOWED_HOSTS,
				providerSignaturesSha256: c.env.PROVIDER_SIGNATURES_SHA256,
				analytics,
				profileAccumulator: c.env.PROFILE_ACCUMULATOR,
				profileAccumulatorShardMode: resolveAccumulatorShardModeFromEnv(c.env.PROFILE_ACCUMULATOR_SHARDING),
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
				certstreamAuthToken: certstreamAuthToken(c.env),
				whoisBinding: c.env.BV_WHOIS,
				reconBinding: c.env.BV_RECON,
				reconAuthToken: c.env.BV_RECON_KEY,
				tlsProbeBinding: c.env.BV_TLS_PROBE,
				tlsProbeAuthToken: c.env.BV_TLS_PROBE_KEY,
				m365Proxy: c.env.BV_WEB,
				m365ProxyAuthToken: c.env.BV_WEB_INTERNAL_KEY,
				bvWebBenchmark: c.env.BV_WEB,
				bvWebBenchmarkAuthToken: c.env.BV_WEB_INTERNAL_KEY,
				infraProbe: c.env.BV_INFRA_PROBE,
				brandAuditDb: c.env.BRAND_AUDIT_DB,
				brandAuditQueue: c.env.BRAND_AUDIT_QUEUE,
				brandReportsR2: c.env.BRAND_REPORTS,
				publicOrigin: new URL(c.req.url).origin,
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
				region,
				city,
				latitude,
				longitude,
				asn,
				asOrg,
				analyticsQueue: c.env.MCP_ANALYTICS_QUEUE,
				analyticsPiiLevel: parseAnalyticsPiiLevel(c.env.ANALYTICS_PII_LEVEL),
				rollupInternal: c.env.ANALYTICS_ROLLUP_INTERNAL === 'true',
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
		// MCP 2025-06-18 Streamable HTTP: a GET to the MCP endpoint yields an SSE stream or 405.
		// 405 (not 406) is the status clients treat as "no SSE here, use POST" and fall back on.
		return new Response('Method Not Allowed: GET requires Accept: text/event-stream', {
			status: 405,
			headers: { Allow: 'GET, POST' },
		});
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
		// MCP 2025-06-18 Streamable HTTP: a GET to the MCP endpoint yields an SSE stream or 405.
		// 405 (not 406) is the status clients treat as "no SSE here, use POST" and fall back on.
		return new Response('Method Not Allowed: GET requires Accept: text/event-stream', {
			status: 405,
			headers: { Allow: 'GET, POST' },
		});
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

// Brand-audit PDF download — authenticated + owner-scoped, streams from R2.
// Shares the MCP bearer-auth middleware (authedPaths) so the resolved keyHash
// matches the principalId stored as `brand_audits.owner_id`. Anonymous or
// key-less callers get 401; wrong owner / unknown ids get an indistinguishable
// 404 (ID-enumeration defense, mirroring brand_audit_get_report).
app.get('/reports/:auditId/:target', async (c) => {
	const tierResult = c.get('tierAuthResult');
	const keyHash = tierResult?.authenticated && tierResult.keyHash ? tierResult.keyHash.slice(0, 16) : undefined;
	if (!keyHash) {
		return unauthorizedResponse();
	}
	// Per-IP control-plane rate limit (60/min) — each download costs a D1 query
	// + an R2 read, so even authenticated callers must not be able to hammer it.
	// Calls the limiter directly (not buildControlPlaneRateLimitResponse, whose
	// authenticated-caller exemption would make it a no-op here) and returns a
	// plain HTTP 429 since this is a REST download, not a JSON-RPC surface.
	const reportIp = resolveClientIpFromRequestHeaders(c.req.raw.headers);
	const reportRate = await checkControlPlaneRateLimit(reportIp, c.env.RATE_LIMIT, c.env.QUOTA_COORDINATOR);
	if (!reportRate.allowed) {
		const retryAfterSeconds = Math.ceil((reportRate.retryAfterMs ?? 0) / 1000);
		return new Response('Rate limit exceeded', {
			status: 429,
			headers: { 'retry-after': String(retryAfterSeconds) },
		});
	}
	const db = c.env.BRAND_AUDIT_DB;
	const bucket = c.env.BRAND_REPORTS;
	if (!db || !bucket) {
		return new Response('Not found', { status: 404 });
	}
	const { handleReportDownload } = await import('./handlers/report-download');
	return handleReportDownload(c.req.param('auditId'), c.req.param('target'), keyHash, { db, bucket });
});

app.route('/internal', internalRoutes);

// OAuth 2.1 discovery endpoints (RFC 8414 + RFC 9728).
//
// Every route below dispatches on `oauthAvailability(c.env)` rather than a
// boolean. `'disabled'` → 404 (feature off). `'misconfigured'` → 503 (feature
// on but signing secret missing/short — fail-fast at first RTT instead of
// after the user completes the consent dance).
function oauthGuarded<T>(c: Context<AppEnv>, ready: () => T | Response): T | Response {
	const state = oauthAvailability(c.env);
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

// Root-path OAuth aliases. Some MCP clients (notably Claude Desktop connectors,
// especially when given a pre-registered OAuth Client ID) skip authorization-server
// metadata discovery and assume the OAuth endpoints live at the server origin
// (/register, /authorize, /token), ignoring the /oauth/ prefix advertised in
// discovery metadata. Serving both makes the connector flow work for discovery-driven
// clients (/oauth/*) and origin-default clients (root) alike — same handlers, same
// oauthGuarded gating. Confirmed via prod tail: Claude Desktop requested GET /authorize → 404.
app.post('/register', (c) => oauthGuarded(c, () => handleRegister(c)));
app.get('/authorize', (c) => oauthGuarded(c, () => handleAuthorizeGet(c)));
app.post('/authorize', (c) => oauthGuarded(c, () => handleAuthorizePost(c)));
app.post('/token', (c) => oauthGuarded(c, () => handleToken(c)));

app.all('*', (c) => {
	// Plain text — avoids mcp-remote misinterpreting JSON as an OAuth error.
	// OAuth well-known paths are handled explicitly above.
	return c.text('Not found', 404);
});

import { handleTail } from './tail';
import { handleScheduled, handleDailyDigest, handleFuzzingScan, handleBrandAuditWatches } from './scheduled';
import type { ScheduledEnv } from './scheduled';
import { handleScanQueue, type ScanQueueConsumerEnv } from './tenants/queue-consumer';
import { handleBrandAuditQueue, type BrandAuditConsumerDeps } from './queue/brand-audit-consumer';
import { handleBrandAuditPdfQueue, type BrandAuditPdfConsumerDeps } from './queue/brand-audit-pdf-consumer';
import { handleTenantCycleAlerts, handleTenantWeeklyRescan, type TenantScheduledEnv } from './tenants/scheduled-handlers';
// Phase 2 scheduler core (ships DARK). The handlers no-op unless
// `SCAN_DISPATCH_ENABLED === 'true'` AND `SCAN_SCHEDULE_DB` is bound; the cron
// strings below are deliberately NOT added to `wrangler.jsonc`, so they never
// fire in prod until an operator adds them at enable time.
import { handleScanDispatch, handleScanRateRecompute, type ScanDispatchEnv } from './lib/scan-scheduler';

/**
 * Day-of-week names → numeric form, per the cron spec. Cloudflare accepts both
 * `SUN`-style names and `0`-style numbers in the 5th field; we cannot verify
 * from here which form CF passes back in `event.cron`, so we normalize both
 * sides of every dispatch comparison to stay correct regardless.
 */
const CRON_DOW_NAMES: Record<string, string> = {
	SUN: '0',
	MON: '1',
	TUE: '2',
	WED: '3',
	THU: '4',
	FRI: '5',
	SAT: '6',
};

/**
 * Normalize a 5-field cron expression so that the day-of-week field uses the
 * numeric form (`SUN` → `0`, …`SAT` → `6`; the alias `7` also folds to `0`).
 * Other fields (including `*`, step values, ranges) are left untouched. Already-numeric
 * DOW forms are returned unchanged (`normalizeCron` is idempotent), so this is
 * a no-op against the historically-deployed numeric literals.
 *
 * @param expr Raw cron expression (e.g. from `event.cron` or wrangler triggers).
 * @returns The expression with a numeric day-of-week field.
 */
export function normalizeCron(expr: string): string {
	const fields = expr.trim().split(/\s+/);
	if (fields.length !== 5) return expr.trim();
	const dow = fields[4].toUpperCase();
	if (dow === '7') {
		fields[4] = '0';
	} else if (CRON_DOW_NAMES[dow] !== undefined) {
		fields[4] = CRON_DOW_NAMES[dow];
	}
	return fields.join(' ');
}

/**
 * Discriminated route for a scheduled cron trigger. `'periodic'` is the
 * catch-all (the 15-min sweep) — every cron without a dedicated branch routes
 * here, so the cron-dispatch-coverage audit treats it as the explicit fallback.
 */
export type CronRoute = 'daily-digest' | 'weekly-tenant-rescan' | 'scan-dispatch' | 'scan-rate-recompute' | 'periodic';

/**
 * Map a cron expression to its dispatch route, comparing the normalized form so
 * the named (`0 2 * * SUN`) and numeric (`0 2 * * 0`) day-of-week variants are
 * treated identically. This is the single source of truth shared by the
 * `scheduled()` dispatcher and the cron-dispatch-coverage audit.
 *
 * @param cron The cron expression delivered on the scheduled event.
 * @returns The route whose handler set should run.
 */
export function routeCron(cron: string): CronRoute {
	const normalized = normalizeCron(cron);
	if (normalized === normalizeCron('0 8 * * *')) return 'daily-digest';
	if (normalized === normalizeCron('0 2 * * 0')) return 'weekly-tenant-rescan';
	// Phase 2 scheduler core (DARK). These crons are NOT in wrangler.jsonc — the
	// operator adds them at enable time; the handlers no-op while the flag is off.
	if (normalized === normalizeCron('* * * * *')) return 'scan-dispatch';
	if (normalized === normalizeCron('*/30 * * * *')) return 'scan-rate-recompute';
	return 'periodic';
}

export default {
	fetch: (req: Request, env: Record<string, unknown>, ctx: ExecutionContext) => app.fetch(req, env, ctx),
	/**
	 * Tail-consumer handler. `wrangler.jsonc` registers this Worker as its own
	 * `tail_consumers` target, so Cloudflare delivers a batch of this Worker's
	 * invocation traces here (including thrown exceptions that never reached the
	 * in-band emit path). We aggregate by colo+outcome+scriptName into the
	 * MCP_ANALYTICS dataset. Fail-open + cheap — `handleTail` never throws.
	 */
	tail: (events: TraceItem[], env: Record<string, unknown>, _ctx: ExecutionContext) => {
		handleTail(events, env as { MCP_ANALYTICS?: AnalyticsEngineDataset });
	},
	scheduled: async (event: ScheduledEvent, env: Record<string, unknown>, ctx: ExecutionContext) => {
		// Each handler is dispatched via its own waitUntil so a failure in one
		// (e.g. Tenant alert sweep throws) cannot mask the others' analytics outcome.
		//
		// `routeCron` normalizes the day-of-week field so the deployed named form
		// `0 2 * * SUN` and the numeric `0 2 * * 0` both reach the weekly branch,
		// regardless of which form Cloudflare passes verbatim in `event.cron`.
		const route = routeCron(event.cron);
		if (route === 'daily-digest') {
			ctx.waitUntil(handleDailyDigest(env as ScheduledEnv));
		} else if (route === 'weekly-tenant-rescan') {
			// Weekly Tenant rescan dispatch — Sunday 02:00 UTC.
			ctx.waitUntil(handleTenantWeeklyRescan(env as TenantScheduledEnv, ctx));
		} else if (route === 'scan-dispatch') {
			// Phase 2 scheduler (DARK) — claim-and-advance dispatch. No-ops unless
			// SCAN_DISPATCH_ENABLED === 'true' AND SCAN_SCHEDULE_DB is bound.
			ctx.waitUntil(handleScanDispatch(env as ScanDispatchEnv, ctx));
		} else if (route === 'scan-rate-recompute') {
			// Phase 2 scheduler (DARK) — persist per-lane adaptive rate to KV.
			ctx.waitUntil(handleScanRateRecompute(env as ScanDispatchEnv, ctx));
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
		// R4: async-path AE counter. The consumers below log to console only, so a
		// whole-batch throw (which Cloudflare retries) is structurally invisible to
		// `queryRecentAnomalies` (tool_call-only). Emit one fail-open `queue_batch`
		// event per dispatch carrying handler/outcome/duration/messageCount —
		// `outcome='error'` + `failureCount=messageCount` when the handler throws.
		// Behaviour-preserving: the error is re-thrown so Cloudflare's retry
		// semantics are unchanged; the emit runs in `finally`.
		const queueStartedAt = Date.now();
		let queueOutcome: 'ok' | 'error' = 'ok';
		try {
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
						profileAccumulatorShardMode: resolveAccumulatorShardModeFromEnv(queueEnv.PROFILE_ACCUMULATOR_SHARDING),
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
					certstreamAuthToken: certstreamAuthToken(e as BvMcpEnv),
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
			if (batch.queue === 'mcp-analytics-queue') {
				const { handleAnalyticsQueue } = await import('./lib/analytics-queue-consumer');
				await handleAnalyticsQueue(batch, env as import('./lib/analytics-queue-consumer').AnalyticsQueueEnv);
				return;
			}
			await handleScanQueue(batch, env as ScanQueueConsumerEnv, ctx);
		} catch (err) {
			queueOutcome = 'error';
			throw err;
		} finally {
			const messageCount = batch.messages.length;
			createAnalyticsClient((env as BvMcpEnv).MCP_ANALYTICS).emitQueueBatchEvent({
				handler: batch.queue,
				outcome: queueOutcome,
				durationMs: Date.now() - queueStartedAt,
				messageCount,
				// Whole-batch throw → every message will be retried; report the batch
				// size as the failure count. A clean dispatch reports 0.
				failureCount: queueOutcome === 'error' ? messageCount : 0,
			});
		}
	},
};
