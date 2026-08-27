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
import { logError } from './lib/log';
import { tenantRoutes } from './tenants/routes';
import { handleToolsCall, INTERNAL_BATCH_SAFE_TOOLS } from './handlers/tools';
import { isAuthorizedRequest } from './lib/auth';
import { createAnalyticsClient } from './lib/analytics';
import { parseScoringConfigCached } from './lib/scoring-config';
import { buildBrandTierLookups } from './lib/brand-tier-lookups';
import {
	AGENT_CALLER_HEADER,
	isAgentAllowedTool,
	isAgentCaller,
	MAX_REQUEST_BODY_BYTES,
	OAUTH_CODE_TTL_SECONDS,
	parseCacheTtl,
	parsePerCheckTimeout,
	parseScanTimeout,
} from './lib/config';
import { normalizeToolName } from './handlers/tool-args';
import { recordInternalAccessLog, extractAccessLogDomain } from './mcp/execute';
import { parseAnalyticsPiiLevel } from './lib/analytics-pii';
import { validateDomain, sanitizeDomain } from './lib/sanitize';
import { InternalToolCallSchema, BatchRequestSchema, CreateTrialKeyRequestSchema } from './schemas/internal';
import { InternalOAuthGrantRequestSchema } from './schemas/oauth';
import { createTrialKey, getTrialKeyStatus, revokeTrialKey, listTrialKeys } from './lib/trial-keys';
import { parseEnvelopeKey } from './lib/kv-envelope';
import { queryAnalyticsEngine } from './lib/analytics-engine';
import { buildCodeRecordFromEntitlement } from './oauth/entitlements';
import { resolveIssuer } from './oauth/discovery';
import { resolveAccumulatorShardModeFromEnv } from './lib/profile-accumulator';
import { readBoundedText } from './lib/request-body';
import {
	createAuthorizationCode,
	getClient,
	putCode,
	bumpTokenVersion,
	bumpTokenVersionIdempotently,
	raiseMinimumEntitlementGeneration,
} from './oauth/storage';
import type { QuotaCoordinator } from './lib/quota-coordinator';
import { computeStrongIdempotencyKeys, STRONG_IDEMPOTENCY_TTL_SECONDS } from './lib/request-dedup';
import { deriveCanonicalTenantPrincipal } from './lib/auth-principal';
import { adoptAnonymousBrandAuditWatchInternal, reconcileLegacyBrandAuditOwner } from './lib/brand-audit-owner-reconciliation';
import { isStrongDistinctSecurityCapability, type McpSecurityCriticalSecretKey } from './lib/security-capabilities';
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
	queryGeoRollup,
	resolveAnalyticsDataset,
} from './lib/analytics-queries';

type InternalEnv = Partial<Record<McpSecurityCriticalSecretKey, string | undefined>> & {
	SESSION_STORE?: KVNamespace;
	SCAN_CACHE?: KVNamespace;
	RATE_LIMIT?: KVNamespace;
	QUOTA_COORDINATOR?: DurableObjectNamespace<QuotaCoordinator>;
	PROFILE_ACCUMULATOR?: DurableObjectNamespace;
	/** R10 - ProfileAccumulator write-sharding mode (default-off). See BvMcpEnv in index.ts. */
	PROFILE_ACCUMULATOR_SHARDING?: string;
	MCP_ANALYTICS?: AnalyticsEngineDataset;
	/**
	 * Optional AE DATASET-name override for the `/internal/analytics/*` read queries.
	 * Defaults in code to `bv_dns_security_mcp` (the dataset the `MCP_ANALYTICS`
	 * binding writes to) via `resolveAnalyticsDataset`. NOT the Worker binding name.
	 */
	ANALYTICS_DATASET?: string;
	PROVIDER_SIGNATURES_URL?: string;
	PROVIDER_SIGNATURES_ALLOWED_HOSTS?: string;
	PROVIDER_SIGNATURES_SHA256?: string;
	SCORING_CONFIG?: string;
	CACHE_TTL_SECONDS?: string;
	SCAN_TIMEOUT_MS?: string;
	PER_CHECK_TIMEOUT_MS?: string;
	BV_DOH_ENDPOINT?: string;
	BV_DOH_TOKEN?: string;
	BV_WHOIS?: Fetcher;
	BV_INFRA_PROBE?: Fetcher;
	BV_RECON?: Fetcher;
	BV_RECON_KEY?: string;
	CF_ACCOUNT_ID?: string;
	CF_ANALYTICS_TOKEN?: string;
	BV_WEB_INTERNAL_KEY?: string;
	/** Web-only capability for OAuth authorization-code and trial-key issuance. */
	BV_MCP_OAUTH_MINT_KEY?: string;
	/** Revocation-only capability for entitlement/token invalidation; cannot mint. */
	BV_MCP_OAUTH_REVOKE_KEY?: string;
	/** Canonical public OAuth issuer; required by the paid internal grant handoff. */
	OAUTH_ISSUER?: string;
	/** Dedicated credential for tenant orchestration; never accepted by tool or OAuth routes. */
	BV_MCP_TENANT_KEY?: string;
	/**
	 * Dedicated bv-web/ops capability for tenant-scoped tool delegation. This is
	 * the only bearer allowed to accompany X-Tenant + X-Auth-Tier on /tools/*.
	 * Never fall back to the fleet-wide BV_WEB_INTERNAL_KEY.
	 */
	BV_MCP_TOOL_DELEGATION_KEY?: string;
	/** Ops-only capability for tenant-scoped Brand Watch list/delete cleanup. */
	BV_MCP_WATCH_CLEANUP_KEY?: string;
	/** Dedicated M365 read capability; referenced here only to reject secret reuse. */
	BV_MCP_M365_KEY?: string;
	/** Outbound Brand Drift capability; comparison-only on inbound internal doors. */
	BV_MCP_BRAND_WEBHOOK_KEY?: string;
	/**
	 * Independent internal-door credential for the BizFit mobile Worker (`claude-proxy`),
	 * accepted on /internal/tools/* ONLY — never /analytics/* or /tenants/*.
	 *
	 * Exists so a lower-trust consumer is not handed `BV_WEB_INTERNAL_KEY`, which is a
	 * BIDIRECTIONAL shared bearer with bv-web-prod (bv-web-prod → here, and here → bv-web-prod's
	 * validate-key / get_domain_rank benchmark / M365 proxy). A separate slot means the mobile
	 * Worker can be rotated or revoked without touching bv-web-prod, and a leak on the mobile
	 * side does not expose bv-web-prod's credential in either direction.
	 *
	 * Same rationale as the BV_INTERNAL_DEV_KEY / BV_INTERNAL_DEV_KEY_2 pair in
	 * src/lib/tier-auth.ts: add a per-consumer key without rotating the incumbent.
	 */
	BV_MOBILE_INTERNAL_KEY?: string;
	/**
	 * Opt-out flag for the defense-in-depth bearer gate on /tools/* and /analytics/*.
	 * Default: gate is ACTIVE (bearer required). Set to 'false' to disable the bearer
	 * requirement and rely solely on the cf-connecting-ip network guard.
	 */
	REQUIRE_INTERNAL_AUTH?: string;
	/**
	 * Brand-discovery cross-Worker service bindings. Operator-deploy only —
	 * declared in `.dev/wrangler.deploy.jsonc`, never in the public
	 * `wrangler.jsonc`. Mirrors the `BvMcpEnv` declarations in `src/index.ts`
	 * so internal callers (`/internal/tools/{call,batch}` — load tests, ops
	 * scripts, service-binding invocations from bv-web) get the same tiered
	 * discovery behaviour as the public `/mcp` path.
	 */
	BV_INFRA_GRAPH?: Fetcher;
	BV_INTEL_GATEWAY?: {
		getDomainEvidence: (params: { domain: string; includeHistory?: boolean }) => Promise<unknown>;
	};
	BV_ENTERPRISE?: Fetcher;
	/**
	 * D1 + Queue backing the async brand-audit subsystem (`discover_brand_domains_start`,
	 * `brand_audit_batch_start`, `register_brand_audit_watch`). Bound to the SAME worker
	 * as the public `/mcp` path (`BvMcpEnv` in `src/index.ts`) — the internal door MUST
	 * thread them into the tool runtime options or the async `*_start` tools short-circuit
	 * to `unprovisioned` with no `auditId` (the caller polls forever, nothing is stored).
	 * Absent on BSL self-hosts → the tools degrade cleanly to `unprovisioned`.
	 */
	BRAND_AUDIT_DB?: D1Database;
	BRAND_AUDIT_QUEUE?: { send(message: unknown, options?: { contentType?: 'json' }): Promise<void> };
	/** FIND-17: Base64-encoded 32-byte AES-256 key for app-layer KV envelope encryption. */
	KV_ENVELOPE_KEY?: string;
	/** D1 store backing mcp_access_log — precise per-customer usage/forensics. Mirrors BvMcpEnv in index.ts. */
	INTELLIGENCE_DB?: D1Database;
	/** Base64-encoded 32-byte AES-256-GCM key used to decrypt `mcp_access_log.ip_ciphertext` in the forensics endpoint. */
	MCP_ACCESS_LOG_IP_ENCRYPTION_KEY?: string;
	/** Key version tag persisted alongside `ip_ciphertext`. Mirrors BvMcpEnv in index.ts. */
	MCP_ACCESS_LOG_IP_KEY_VERSION?: string;
	/** Cloudflare Queue producer for the analytics access-log path (B1 internal-path logging). Absent → inline insert. */
	MCP_ANALYTICS_QUEUE?: { send(message: unknown, options?: { contentType?: 'json' }): Promise<void> };
	/** Operator-chosen PII capture depth for the access log. Undefined → 'coarse'. */
	ANALYTICS_PII_LEVEL?: string;
};

type InternalPrincipal = 'web' | 'mobile' | 'tenant' | 'tenant-tool' | 'watch-cleanup' | 'network';
type InternalAppEnv = { Bindings: InternalEnv; Variables: { internalPrincipal: InternalPrincipal } };

/** Printable, non-whitespace HTTP token bounded before it reaches strong state. */
function parseIdempotencyKey(value: string | undefined): string | undefined | null {
	if (value === undefined) return undefined;
	if (!/^[\x21-\x7e]{8,200}$/.test(value)) return null;
	return value;
}

type ToolDoorIdentity = { principalId: string; authTier: 'free' | 'developer' | 'enterprise' | 'owner' };

const INTERNAL_OWNER_SCOPED_BRAND_TOOLS = new Set([
	'discover_brand_domains_start',
	'discover_brand_domains_status',
	'discover_brand_domains_findings',
	'brand_audit_batch_start',
	'brand_audit_status',
	'brand_audit_get_report',
	'list_brand_audit_watches',
	'register_brand_audit_watch',
	'delete_brand_audit_watch',
]);

/** Exact least-privilege surface reachable with tenant delegation. */
const TENANT_DELEGATED_TOOLS: ReadonlySet<string> = new Set([
	'register_brand_audit_watch',
	'list_brand_audit_watches',
	'delete_brand_audit_watch',
]);

const WATCH_CLEANUP_TOOLS: ReadonlySet<string> = new Set(['list_brand_audit_watches', 'delete_brand_audit_watch']);

function dedicatedCapability(env: InternalEnv, key: McpSecurityCriticalSecretKey): string | null {
	const value = env[key];
	return typeof value === 'string' && isStrongDistinctSecurityCapability(env, key) ? value : null;
}

async function reconcileTrustedTenantBrandOwner(input: {
	db: D1Database | undefined;
	internalPrincipal: InternalPrincipal;
	tenantHeader: string | undefined;
	canonicalOwnerId: string;
	toolName: string;
	args: Record<string, unknown> | undefined;
}): Promise<{ ok: true } | { ok: false; status: 400 | 409 | 503; error: string }> {
	if (
		!input.db ||
		(input.internalPrincipal !== 'tenant-tool' && input.internalPrincipal !== 'watch-cleanup') ||
		!input.tenantHeader ||
		!INTERNAL_OWNER_SCOPED_BRAND_TOOLS.has(input.toolName)
	) {
		return { ok: true };
	}

	try {
		await reconcileLegacyBrandAuditOwner(input.db, `tenant:${input.tenantHeader}`, input.canonicalOwnerId);
		if (input.toolName !== 'list_brand_audit_watches' && input.toolName !== 'delete_brand_audit_watch') {
			return { ok: true };
		}

		const fingerprint = input.args?.legacyWebhookTokenFingerprint;
		if (fingerprint === undefined) return { ok: true };
		if (typeof fingerprint !== 'string') return { ok: false, status: 400, error: 'invalid_legacy_watch_proof' };
		const watchId = input.toolName === 'delete_brand_audit_watch' ? input.args?.watchId : undefined;
		if (watchId !== undefined && typeof watchId !== 'string') {
			return { ok: false, status: 400, error: 'invalid_legacy_watch_id' };
		}
		const adoption = await adoptAnonymousBrandAuditWatchInternal(input.db, {
			canonicalOwnerId: input.canonicalOwnerId,
			webhookTokenFingerprint: fingerprint,
			...(typeof watchId === 'string' ? { watchId } : {}),
		});
		if (adoption.status === 'ambiguous') {
			return { ok: false, status: 409, error: 'legacy_watch_ambiguous' };
		}
		return { ok: true };
	} catch (error) {
		logError(error instanceof Error ? error : 'Brand owner reconciliation failed', {
			category: 'brand_audit_owner_reconciliation',
			severity: 'error',
		});
		return { ok: false, status: 503, error: 'brand_owner_reconciliation_unavailable' };
	}
}

/**
 * Resolve the storage/quota owner for a direct tool call. Tenant identity is a
 * trusted delegation assertion accepted only after a dedicated narrow tenant
 * capability has authenticated. bv-web derives both headers from its session
 * and subscription store; ops may use its separate list/delete-only cleanup
 * capability. Other callers receive server-owned principals rather than the
 * cross-caller `anonymous` bucket.
 */
async function resolveToolDoorIdentity(
	principal: InternalPrincipal,
	tenantHeader: string | undefined,
	tierHeader: string | undefined,
	callerHeader: string | undefined,
	oauthIssuer: string | undefined,
): Promise<{ ok: true; identity: ToolDoorIdentity } | { ok: false; status: 400 | 403 | 503; error: string }> {
	const hasTenantContext = tenantHeader !== undefined || tierHeader !== undefined;
	if (principal === 'tenant-tool' || principal === 'watch-cleanup') {
		if (!tenantHeader || !tierHeader) return { ok: false, status: 400, error: 'incomplete_tenant_context' };
		if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(tenantHeader)) {
			return { ok: false, status: 400, error: 'invalid_tenant_context' };
		}
		if (tierHeader !== 'developer' && tierHeader !== 'enterprise') {
			return { ok: false, status: 400, error: 'invalid_auth_tier' };
		}
		if (!oauthIssuer) return { ok: false, status: 503, error: 'oauth_issuer_not_configured' };
		try {
			return {
				ok: true,
				identity: {
					principalId: await deriveCanonicalTenantPrincipal(oauthIssuer, tenantHeader),
					authTier: tierHeader,
				},
			};
		} catch {
			return { ok: false, status: 503, error: 'oauth_issuer_invalid' };
		}
	}
	if (hasTenantContext) {
		return { ok: false, status: 403, error: 'tenant_context_not_allowed' };
	}

	if (principal === 'web') {
		const caller = callerHeader && /^[a-z0-9][a-z0-9_-]{0,63}$/.test(callerHeader) ? callerHeader : 'default';
		return { ok: true, identity: { principalId: `system:web:${caller}`, authTier: 'owner' } };
	}
	return { ok: true, identity: { principalId: `system:${principal}`, authTier: 'free' } };
}

export const internalRoutes = new Hono<InternalAppEnv>();

/**
 * Pure decision used by the guard middleware. Cloudflare sets `cf-connecting-ip`
 * authoritatively on every public-internet request and never on service-binding
 * calls, so its presence is the only signal we trust. The Host header is
 * attacker-influenced and must not be used to bypass this check.
 */
export function isPublicInternetRequest(headers: { cfConnectingIp: string | null; host: string | null }): boolean {
	return Boolean(headers.cfConnectingIp);
}

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
	if (isPublicInternetRequest({ cfConnectingIp: c.req.header('cf-connecting-ip') ?? null, host: c.req.header('host') ?? null })) {
		return c.json({ error: 'Not found' }, 404);
	}
	return next();
});

/**
 * Defense-in-depth bearer gate for /tools/*, /analytics/*, and /tenants/*.
 *
 * **Secure by default (FIND-12):** the gate is ACTIVE unless explicitly opted
 * out. Callers must present `Authorization: Bearer <one of the accepted keys>`.
 * Set `REQUIRE_INTERNAL_AUTH=false` to disable and rely solely on the
 * cf-connecting-ip network guard (e.g. during a controlled migration window).
 *
 * Takes the list of env var names whose values are accepted on the routes it fronts, so a
 * per-consumer credential can be granted to one route group without granting it everywhere.
 * `/tools/*` accepts general web/mobile credentials plus the separate web
 * delegation and ops cleanup capabilities; only those two narrow principals
 * may send tenant context, and each has an exact tool allowlist.
 * `/analytics/*` accepts only `BV_WEB_INTERNAL_KEY`; `/tenants/*` accepts only
 * `BV_MCP_TENANT_KEY`.
 *
 * Fail-closed: if the gate is active but NONE of its accepted keys is configured (unset or
 * empty), the route returns 503 rather than silently passing unauthenticated requests.
 *
 * Unlike trialKeysAuthGate (which always enforces because it mints credentials),
 * this gate can be disabled at the operator's explicit request via the env flag.
 *
 * NOTE (cross-repo): callers must send the credential dedicated to their route
 * family. The general web bearer is deliberately not accepted by tenant or
 * OAuth/trial administration routes.
 *
 * Registered BEFORE the route handlers below — Hono middleware applies only to
 * routes registered after the .use() call.
 */
const internalLenientAuthGate = (
	acceptedKeys: ReadonlyArray<
		'BV_WEB_INTERNAL_KEY' | 'BV_MOBILE_INTERNAL_KEY' | 'BV_MCP_TENANT_KEY' | 'BV_MCP_TOOL_DELEGATION_KEY' | 'BV_MCP_WATCH_CLEANUP_KEY'
	>,
): import('hono').MiddlewareHandler<InternalAppEnv> => {
	return async (c, next) => {
		if (c.env.REQUIRE_INTERNAL_AUTH === 'false') {
			// Explicitly opted out — rely on the network guard (cf-connecting-ip) alone.
			c.set('internalPrincipal', 'network');
			return next();
		}
		// Empty strings are dropped, not treated as credentials: `wrangler secret put` will
		// store an empty value, and an empty expected token must never authorize anything nor
		// count towards "a credential is configured" below.
		const expected = acceptedKeys
			.map((name) => ({ name, key: c.env[name] }))
			.filter(
				(entry): entry is { name: (typeof acceptedKeys)[number]; key: string } => typeof entry.key === 'string' && entry.key.length > 0,
			);
		// Tenant delegation is higher trust than the fleet/mobile/tool credentials.
		// Weak or reused configuration is a deployment error, never an auth match:
		// otherwise a holder of the colliding lower-trust secret inherits tenant
		// assertion authority merely by adding headers.
		if (acceptedKeys.includes('BV_MCP_TOOL_DELEGATION_KEY') && c.env.BV_MCP_TOOL_DELEGATION_KEY !== undefined) {
			if (!dedicatedCapability(c.env, 'BV_MCP_TOOL_DELEGATION_KEY')) {
				return c.json({ error: 'internal_auth_secret_misconfigured' }, 503, { 'Cache-Control': 'no-store' });
			}
		}
		if (acceptedKeys.includes('BV_MCP_WATCH_CLEANUP_KEY') && c.env.BV_MCP_WATCH_CLEANUP_KEY !== undefined) {
			if (!dedicatedCapability(c.env, 'BV_MCP_WATCH_CLEANUP_KEY')) {
				return c.json({ error: 'internal_auth_secret_misconfigured' }, 503, { 'Cache-Control': 'no-store' });
			}
		}
		if (expected.length === 0) {
			// Misconfig: gate is active but no key configured for this route group — fail closed.
			return c.json({ error: 'internal_auth_not_configured' }, 503, { 'Cache-Control': 'no-store' });
		}
		const header = c.req.header('authorization');
		// Every candidate is evaluated (no `||` short-circuit) so the number of constant-time
		// comparisons performed does not vary with WHICH key matched.
		const matches = await Promise.all(expected.map((entry) => isAuthorizedRequest(header, entry.key)));
		if (!matches.some(Boolean)) {
			return c.json({ error: 'unauthorized' }, 401, { 'Cache-Control': 'no-store' });
		}
		// Retain the authenticated principal for authorization. Dedicated tenant
		// delegation collisions have already failed closed above.
		const matchedNames = expected.filter((_entry, index) => matches[index]).map((entry) => entry.name);
		const principal: InternalPrincipal = matchedNames.includes('BV_MOBILE_INTERNAL_KEY')
			? 'mobile'
			: matchedNames.includes('BV_MCP_TENANT_KEY')
				? 'tenant'
				: matchedNames.includes('BV_MCP_TOOL_DELEGATION_KEY')
					? 'tenant-tool'
					: matchedNames.includes('BV_MCP_WATCH_CLEANUP_KEY')
						? 'watch-cleanup'
						: 'web';
		c.set('internalPrincipal', principal);
		return next();
	};
};
const webOnlyGate = internalLenientAuthGate(['BV_WEB_INTERNAL_KEY']);
const webAndTenantToolGate = internalLenientAuthGate(['BV_MCP_TOOL_DELEGATION_KEY', 'BV_MCP_WATCH_CLEANUP_KEY', 'BV_WEB_INTERNAL_KEY']);
const webMobileAndTenantToolGate = internalLenientAuthGate([
	'BV_MOBILE_INTERNAL_KEY',
	'BV_MCP_TOOL_DELEGATION_KEY',
	'BV_MCP_WATCH_CLEANUP_KEY',
	'BV_WEB_INTERNAL_KEY',
]);
/**
 * Tenant orchestration is an authorization boundary, so its dedicated bearer
 * cannot be disabled by the legacy tools/analytics migration escape hatch.
 */
const tenantOnlyGate: import('hono').MiddlewareHandler<InternalAppEnv> = async (c, next) => {
	const expected = dedicatedCapability(c.env, 'BV_MCP_TENANT_KEY');
	if (!expected) {
		return c.json({ error: 'internal_auth_not_configured' }, 503, { 'Cache-Control': 'no-store' });
	}
	if (!(await isAuthorizedRequest(c.req.header('authorization'), expected))) {
		return c.json({ error: 'unauthorized' }, 401, { 'Cache-Control': 'no-store' });
	}
	c.set('internalPrincipal', 'tenant');
	return next();
};

/**
 * The exact internal paths `BV_MOBILE_INTERNAL_KEY` may reach. Everything else under
 * /internal/* stays web-key-only.
 *
 * Deliberately `/tools/call` and NOT all of `/tools/*`: `/tools/batch` takes `domains: string[]`
 * plus a caller-set `concurrency`, so one request there fans out a scan across many domains. The
 * mobile Worker's client posts to `/tools/call` and nothing else, so a leak of its key must not
 * become a bulk-scanning capability. Full mount path — `internalRoutes` is mounted at `/internal`
 * in src/index.ts.
 */
const MOBILE_ACCESSIBLE_PATHS: ReadonlySet<string> = new Set(['/internal/tools/call']);

// One registration, not two: Hono runs EVERY matching middleware in registration order, so a
// narrow `.use('/tools/call', …)` plus a broad `.use('/tools/*', …)` would run both on
// /tools/call and the broader web-only gate would then reject a valid mobile bearer. Selecting
// the gate per-request inside a single registration is what keeps that correct.
internalRoutes.use('/tools/*', (c, next) =>
	(MOBILE_ACCESSIBLE_PATHS.has(new URL(c.req.url).pathname) ? webMobileAndTenantToolGate : webAndTenantToolGate)(c, next),
);
internalRoutes.use('/analytics/*', webOnlyGate);
internalRoutes.use('/tenants/*', tenantOnlyGate);

// Tenant orchestrator routes (per tenant-Scalable-Architecture-Design.md §4.1).
// Mounted after the mandatory dedicated-bearer gate above. Unlike the legacy
// tools/analytics gate, tenant authorization ignores REQUIRE_INTERNAL_AUTH.
internalRoutes.route('/tenants', tenantRoutes);

/**
 * POST /internal/tools/call
 *
 * Direct tool invocation without MCP protocol overhead.
 *
 * Request body: { "name": string, "arguments"?: Record<string, unknown> }
 * Response body: { "content": McpContent[], "isError"?: boolean }
 */
internalRoutes.post('/tools/call', async (c) => {
	const startTime = Date.now();
	const idempotencyKey = parseIdempotencyKey(c.req.header('idempotency-key'));
	if (idempotencyKey === null) {
		return c.json({ error: 'invalid_idempotency_key' }, 400, { 'Cache-Control': 'no-store' });
	}
	// Body-size guard before JSON parse: prevents a service-binding caller (or an
	// attacker who bypasses the network guard) from forcing the Worker to
	// materialize an arbitrarily large payload in memory before Zod rejects it.
	// Mirrors the public /mcp limit (MAX_REQUEST_BODY_BYTES = 10 KB).
	const bodyRead = await readBoundedText(c.req.raw, MAX_REQUEST_BODY_BYTES);
	if (!bodyRead.ok) {
		return c.json(
			{ content: [{ type: 'text', text: `Request body exceeds maximum of ${MAX_REQUEST_BODY_BYTES} bytes` }], isError: true },
			413,
		);
	}
	const raw = bodyRead.text;

	let body: { name: string; arguments?: Record<string, unknown> };
	try {
		body = InternalToolCallSchema.parse(JSON.parse(raw));
	} catch (err) {
		if (err instanceof ZodError) {
			return c.json(
				{ content: [{ type: 'text', text: `Invalid ${err.issues[0].path.join('.')}: ${err.issues[0].message}` }], isError: true },
				400,
			);
		}
		return c.json({ content: [{ type: 'text', text: 'Missing required field: name' }], isError: true }, 400);
	}
	const normalizedToolName = normalizeToolName(body.name);
	if (c.get('internalPrincipal') === 'tenant-tool' && !TENANT_DELEGATED_TOOLS.has(normalizedToolName)) {
		return c.json({ error: 'tenant_tool_not_allowed' }, 403, { 'Cache-Control': 'no-store' });
	}
	if (c.get('internalPrincipal') === 'watch-cleanup' && !WATCH_CLEANUP_TOOLS.has(normalizedToolName)) {
		return c.json({ error: 'watch_cleanup_tool_not_allowed' }, 403, { 'Cache-Control': 'no-store' });
	}

	const identity = await resolveToolDoorIdentity(
		c.get('internalPrincipal'),
		c.req.header('x-tenant'),
		c.req.header('x-auth-tier'),
		c.req.header(AGENT_CALLER_HEADER),
		c.env.OAUTH_ISSUER,
	);
	if (!identity.ok) return c.json({ error: identity.error }, identity.status, { 'Cache-Control': 'no-store' });
	const brandOwnerReconciliation = await reconcileTrustedTenantBrandOwner({
		db: c.env.BRAND_AUDIT_DB,
		internalPrincipal: c.get('internalPrincipal'),
		tenantHeader: c.req.header('x-tenant'),
		canonicalOwnerId: identity.identity.principalId,
		toolName: normalizedToolName,
		args: body.arguments,
	});
	if (!brandOwnerReconciliation.ok) {
		return c.json({ error: brandOwnerReconciliation.error }, brandOwnerReconciliation.status, { 'Cache-Control': 'no-store' });
	}

	// The mobile credential is a scan-only capability. Authorization is derived
	// from the matched bearer, never from the caller-controlled X-BV-Caller header.
	if (c.get('internalPrincipal') === 'mobile' && normalizedToolName !== 'scan_domain') {
		return c.json({ error: 'mobile_tool_not_allowed' }, 403, { 'Cache-Control': 'no-store' });
	}

	// Agent-chat caller: enforce the read-only allowlist (defense-in-depth; bv-web
	// also gates, but this is the boundary-side guard). Normalize the alias first
	// (scan → scan_domain) so a legitimate aliased call isn't wrongly rejected.
	// See docs/design/agent-chat-tool-allowlist.md.
	if (isAgentCaller(c.req.header(AGENT_CALLER_HEADER)) && !isAgentAllowedTool(normalizedToolName)) {
		return c.json({ error: 'agent_tool_not_allowed' }, 403, { 'Cache-Control': 'no-store' });
	}

	const url = new URL(c.req.url);
	const wantStructured = url.searchParams.get('format') === 'structured';

	let capturedResult: import('@blackveil/dns-checks/scoring').CheckResult | null = null;

	const cacheTtlSeconds = parseCacheTtl(c.env.CACHE_TTL_SECONDS);

	const result = await handleToolsCall({ name: body.name, arguments: body.arguments }, c.env.SCAN_CACHE, {
		providerSignaturesUrl: c.env.PROVIDER_SIGNATURES_URL,
		providerSignaturesAllowedHosts: c.env.PROVIDER_SIGNATURES_ALLOWED_HOSTS?.split(',')
			.map((h) => h.trim())
			.filter(Boolean),
		providerSignaturesSha256: c.env.PROVIDER_SIGNATURES_SHA256,
		analytics: createAnalyticsClient(c.env.MCP_ANALYTICS),
		profileAccumulator: c.env.PROFILE_ACCUMULATOR,
		profileAccumulatorShardMode: resolveAccumulatorShardModeFromEnv(c.env.PROFILE_ACCUMULATOR_SHARDING),
		waitUntil: (promise: Promise<unknown>) => c.executionCtx.waitUntil(promise),
		scoringConfig: parseScoringConfigCached(c.env.SCORING_CONFIG),
		cacheTtlSeconds,
		scanTimeoutMs: parseScanTimeout(c.env.SCAN_TIMEOUT_MS),
		perCheckTimeoutMs: parsePerCheckTimeout(c.env.PER_CHECK_TIMEOUT_MS),
		secondaryDoh: c.env.BV_DOH_ENDPOINT ? { endpoint: c.env.BV_DOH_ENDPOINT, token: c.env.BV_DOH_TOKEN } : undefined,
		whoisBinding: c.env.BV_WHOIS,
		infraProbe: c.env.BV_INFRA_PROBE,
		// Recon backend (bv2-recon) — powers scan_buckets_* / osint_investigate_*.
		// The internal door (recon-sweep caller) MUST wire these or those tools
		// always degrade to the "unprovisioned" stub even when BV_RECON is bound,
		// which silently stalled the bv2-ops recon-sweep queue (fixed 2026-06-23).
		reconBinding: c.env.BV_RECON,
		reconAuthToken: c.env.BV_RECON_KEY,
		// Async brand-audit subsystem (discover_brand_domains_start /
		// brand_audit_batch_start / register_brand_audit_watch). Same
		// failure mode as the recon binding above: without these the
		// async *_start tools short-circuit to `unprovisioned` with no
		// auditId, so the bv2-ops csc-discovery sweep polls forever and
		// stores nothing. Bound to the same worker as the public path.
		brandAuditDb: c.env.BRAND_AUDIT_DB,
		brandAuditQueue: c.env.BRAND_AUDIT_QUEUE,
		rateLimitKv: c.env.RATE_LIMIT,
		quotaCoordinator: c.env.QUOTA_COORDINATOR,
		principalId: identity.identity.principalId,
		authTier: identity.identity.authTier,
		...(idempotencyKey
			? {
					idempotencyKey,
					idempotencyPrincipal: identity.identity.principalId,
				}
			: {}),
		// Tier 0/1/2 lookup closures — internal callers (load tests, bv-web
		// service binding, ops scripts) get the same tiered discovery path as
		// public `/mcp`. Closures stay `undefined` on BSL self-hosts where
		// the bindings aren't provisioned.
		...buildBrandTierLookups(c.env),
		...(wantStructured
			? {
					resultCapture: (r: import('@blackveil/dns-checks/scoring').CheckResult) => {
						capturedResult = r;
					},
				}
			: {}),
	});

	// B1: record an internal-source access-log row for domain-bearing tools (parity
	// with the public path, which only logs domain-bearing calls). No-domain tools
	// (extractAccessLogDomain → undefined) write no row. ip/ipHash sentinel 'unknown',
	// key_hash null, x-bv-caller → client_type. Best-effort via waitUntil.
	const accessLogDomain = extractAccessLogDomain(body.arguments);
	if (accessLogDomain) {
		recordInternalAccessLog({
			toolName: normalizeToolName(body.name),
			domain: accessLogDomain,
			status: result.isError ? 'error' : 'pass',
			clientType: c.req.header(AGENT_CALLER_HEADER) ?? null,
			intelligenceDb: c.env.INTELLIGENCE_DB,
			analyticsQueue: c.env.MCP_ANALYTICS_QUEUE,
			analyticsPiiLevel: parseAnalyticsPiiLevel(c.env.ANALYTICS_PII_LEVEL),
			ipEncryptionKey: c.env.MCP_ACCESS_LOG_IP_ENCRYPTION_KEY,
			ipEncryptionKeyVersion: c.env.MCP_ACCESS_LOG_IP_KEY_VERSION,
			startTime,
			waitUntil: (p: Promise<unknown>) => c.executionCtx.waitUntil(p),
		});
	}

	// If structured format was requested and a CheckResult was captured (TOOL_REGISTRY
	// CheckResult tools), return the raw CheckResult instead of MCP-framed text.
	if (wantStructured && capturedResult !== null) {
		return c.json({ result: capturedResult, isError: result.isError ?? false });
	}
	// Custom-shape tools (e.g. prioritize_csc_leads, map_csc_products, scan_domain) don't
	// produce a CheckResult but DO set structuredContent. Surface that report under the
	// top-level `result` field the internal door contract uses (bv-web's door reads
	// `payload.result`; without this it would only see `structuredContent`, a different
	// field, and get undefined). ADDITIVE — the MCP-framed `content`/`structuredContent`
	// are preserved, so existing `?format=structured` callers that read them are unaffected.
	if (wantStructured && result.structuredContent !== undefined) {
		return c.json({ ...result, result: result.structuredContent });
	}

	return c.json(result);
});

/**
 * POST /internal/oauth/grants
 *
 * Internal bv-web handoff endpoint for paid customer OAuth consent. bv-web
 * authenticates the user and subscription, then asks bv-mcp to create the
 * one-time authorization code bound to the original client, redirect URI, and PKCE challenge.
 */
internalRoutes.post('/oauth/grants', async (c) => {
	const expected = dedicatedCapability(c.env, 'BV_MCP_OAUTH_MINT_KEY');
	if (!expected) {
		return c.json({ error: 'internal_auth_not_configured' }, 503, { 'Cache-Control': 'no-store' });
	}

	if (!(await isAuthorizedRequest(c.req.header('authorization'), expected))) {
		return c.json({ error: 'unauthorized' }, 401, { 'Cache-Control': 'no-store' });
	}

	if (!c.env.SESSION_STORE) {
		return c.json({ error: 'session_store_not_configured' }, 500, { 'Cache-Control': 'no-store' });
	}

	let body;
	try {
		const bodyRead = await readBoundedText(c.req.raw, MAX_REQUEST_BODY_BYTES);
		if (!bodyRead.ok) return c.json({ error: 'request_too_large' }, 413, { 'Cache-Control': 'no-store' });
		body = InternalOAuthGrantRequestSchema.parse(JSON.parse(bodyRead.text));
	} catch {
		return c.json({ error: 'invalid_grant_request' }, 400, { 'Cache-Control': 'no-store' });
	}

	const kvEnvelopeKey = parseEnvelopeKey(c.env.KV_ENVELOPE_KEY) ?? undefined;
	const client = await getClient(c.env.SESSION_STORE, body.clientId, kvEnvelopeKey);
	if (!client) {
		return c.json({ error: 'unknown_client' }, 400, { 'Cache-Control': 'no-store' });
	}
	if (!client.redirect_uris.includes(body.redirectUri)) {
		return c.json({ error: 'redirect_uri_not_registered' }, 400, { 'Cache-Control': 'no-store' });
	}
	// Service-binding requests use a synthetic `https://internal` URL, so the
	// public issuer cannot safely be derived from the request Host. Require the
	// operator-pinned issuer before minting a code or an RFC 9207 response.
	if (!c.env.OAUTH_ISSUER) {
		return c.json({ error: 'oauth_issuer_not_configured' }, 503, { 'Cache-Control': 'no-store' });
	}
	let issuer: string;
	try {
		issuer = resolveIssuer(c.req.url, c.env.OAUTH_ISSUER);
		const parsedIssuer = new URL(issuer);
		if (parsedIssuer.protocol !== 'https:' || parsedIssuer.username || parsedIssuer.password || parsedIssuer.search || parsedIssuer.hash) {
			throw new Error('invalid issuer');
		}
	} catch {
		return c.json({ error: 'oauth_issuer_invalid' }, 503, { 'Cache-Control': 'no-store' });
	}

	const code = createAuthorizationCode();
	await putCode(
		c.env.SESSION_STORE,
		code,
		buildCodeRecordFromEntitlement({
			clientId: body.clientId,
			redirectUri: body.redirectUri,
			codeChallenge: body.codeChallenge,
			...(body.scope ? { scope: body.scope } : {}),
			entitlement: body.entitlement,
		}),
		kvEnvelopeKey,
	);

	const redirectTo = new URL(body.redirectUri);
	redirectTo.searchParams.set('code', code);
	redirectTo.searchParams.set('state', body.state);
	redirectTo.searchParams.set('iss', issuer);
	return c.json({ redirectTo: redirectTo.toString(), expiresIn: OAUTH_CODE_TTL_SECONDS }, 200, {
		'Cache-Control': 'no-store',
		Pragma: 'no-cache',
	});
});

/**
 * POST /internal/oauth/revoke-subject
 *
 * Raises the subject's minimum entitlement generation, invalidating JWTs
 * minted for an older subscription state while preserving grants minted after
 * a later re-authorization. Legacy callers without a generation retain the
 * token-version bump behaviour.
 *
 * Secured behind its own revocation-only bearer — 503 when
 * BV_MCP_OAUTH_REVOKE_KEY is unset, 401 on missing/wrong bearer. The mint key
 * is deliberately not accepted here, and this key is never accepted by grant
 * or trial-key issuance routes.
 *
 * Request body: { "sub": string, "minEntitlementGeneration"?: number }
 * Response body: { "ok": true, "minEntitlementGeneration": number }
 *             or { "ok": true, "version": number } for legacy requests
 */
internalRoutes.post('/oauth/revoke-subject', async (c) => {
	const expected = dedicatedCapability(c.env, 'BV_MCP_OAUTH_REVOKE_KEY');
	if (!expected) {
		return c.json({ error: 'internal_auth_not_configured' }, 503, { 'Cache-Control': 'no-store' });
	}
	if (!(await isAuthorizedRequest(c.req.header('authorization'), expected))) {
		return c.json({ error: 'unauthorized' }, 401, { 'Cache-Control': 'no-store' });
	}
	if (!c.env.SESSION_STORE) {
		return c.json({ error: 'session_store_not_configured' }, 500, { 'Cache-Control': 'no-store' });
	}
	const idempotencyKey = parseIdempotencyKey(c.req.header('idempotency-key'));
	if (idempotencyKey === null) {
		return c.json({ error: 'invalid_idempotency_key' }, 400, { 'Cache-Control': 'no-store' });
	}

	let body: { sub: string; minEntitlementGeneration?: number };
	try {
		const bodyRead = await readBoundedText(c.req.raw, MAX_REQUEST_BODY_BYTES);
		if (!bodyRead.ok) return c.json({ error: 'request_too_large' }, 413, { 'Cache-Control': 'no-store' });
		const raw: unknown = JSON.parse(bodyRead.text);
		if (typeof raw !== 'object' || raw === null || typeof (raw as Record<string, unknown>).sub !== 'string') {
			throw new Error('invalid');
		}
		const minEntitlementGeneration = (raw as Record<string, unknown>).minEntitlementGeneration;
		if (
			minEntitlementGeneration !== undefined &&
			(!Number.isSafeInteger(minEntitlementGeneration) || (minEntitlementGeneration as number) < 1)
		) {
			throw new Error('invalid');
		}
		body = raw as { sub: string; minEntitlementGeneration?: number };
	} catch {
		return c.json(
			{ error: 'Invalid request body: sub must be a string and minEntitlementGeneration must be a positive safe integer when provided' },
			400,
			{ 'Cache-Control': 'no-store' },
		);
	}

	const sub = (body.sub as string).trim();
	if (!sub) {
		return c.json({ error: 'Invalid request body: sub must be a non-empty string' }, 400, { 'Cache-Control': 'no-store' });
	}
	if (body.minEntitlementGeneration !== undefined) {
		try {
			const minEntitlementGeneration = await raiseMinimumEntitlementGeneration(
				c.env.SESSION_STORE,
				sub,
				body.minEntitlementGeneration,
				c.env.QUOTA_COORDINATOR,
			);
			return c.json({ ok: true, minEntitlementGeneration }, 200, { 'Cache-Control': 'no-store' });
		} catch {
			return c.json({ error: 'authorization_state_unavailable' }, 503, { 'Cache-Control': 'no-store' });
		}
	}

	let version: number;
	try {
		if (idempotencyKey) {
			if (!c.env.QUOTA_COORDINATOR) {
				return c.json({ error: 'idempotency_state_unavailable' }, 503, { 'Cache-Control': 'no-store' });
			}
			const idempotency = await computeStrongIdempotencyKeys('oauth_revoke_subject', 'internal:oauth-grant', idempotencyKey, { sub });
			const result = await bumpTokenVersionIdempotently(
				c.env.SESSION_STORE,
				sub,
				idempotency.coordinationKey,
				idempotency.requestHash,
				Date.now() + STRONG_IDEMPOTENCY_TTL_SECONDS * 1000,
				c.env.QUOTA_COORDINATOR,
			);
			if (result.state === 'conflict') {
				return c.json({ error: 'idempotency_key_conflict' }, 409, { 'Cache-Control': 'no-store' });
			}
			version = result.value;
		} else {
			version = await bumpTokenVersion(c.env.SESSION_STORE, sub, c.env.QUOTA_COORDINATOR);
		}
	} catch {
		return c.json({ error: 'authorization_state_unavailable' }, 503, { 'Cache-Control': 'no-store' });
	}
	return c.json({ ok: true, version }, 200, { 'Cache-Control': 'no-store' });
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
	const batchStartTime = Date.now();
	const bodyRead = await readBoundedText(c.req.raw, BATCH_MAX_BODY_BYTES);
	if (!bodyRead.ok) {
		return c.json({ error: `Request body exceeds maximum of ${BATCH_MAX_BODY_BYTES} bytes` }, 413);
	}
	const raw = bodyRead.text;

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
	if (c.get('internalPrincipal') === 'tenant-tool' || c.get('internalPrincipal') === 'watch-cleanup') {
		return c.json({ error: 'tenant_batch_not_allowed' }, 403, { 'Cache-Control': 'no-store' });
	}

	const identity = await resolveToolDoorIdentity(
		c.get('internalPrincipal'),
		c.req.header('x-tenant'),
		c.req.header('x-auth-tier'),
		c.req.header(AGENT_CALLER_HEADER),
		c.env.OAUTH_ISSUER,
	);
	if (!identity.ok) return c.json({ error: identity.error }, identity.status, { 'Cache-Control': 'no-store' });
	const brandOwnerReconciliation = await reconcileTrustedTenantBrandOwner({
		db: c.env.BRAND_AUDIT_DB,
		internalPrincipal: c.get('internalPrincipal'),
		tenantHeader: c.req.header('x-tenant'),
		canonicalOwnerId: identity.identity.principalId,
		toolName: normalizeToolName(body.tool),
		args: body.arguments,
	});
	if (!brandOwnerReconciliation.ok) {
		return c.json({ error: brandOwnerReconciliation.error }, brandOwnerReconciliation.status, { 'Cache-Control': 'no-store' });
	}

	const normalizedToolName = normalizeToolName(body.tool);
	if (!INTERNAL_BATCH_SAFE_TOOLS.has(normalizedToolName)) {
		return c.json({ error: 'batch_tool_not_allowed' }, 403, { 'Cache-Control': 'no-store' });
	}

	// Agent-chat caller: same read-only allowlist as /tools/call (normalize alias first).
	if (isAgentCaller(c.req.header(AGENT_CALLER_HEADER)) && !isAgentAllowedTool(normalizedToolName)) {
		return c.json({ error: 'agent_tool_not_allowed' }, 403, { 'Cache-Control': 'no-store' });
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
				let capturedResult: import('@blackveil/dns-checks/scoring').CheckResult | null = null;

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
						profileAccumulatorShardMode: resolveAccumulatorShardModeFromEnv(c.env.PROFILE_ACCUMULATOR_SHARDING),
						waitUntil: (promise: Promise<unknown>) => c.executionCtx.waitUntil(promise),
						scoringConfig: parseScoringConfigCached(c.env.SCORING_CONFIG),
						cacheTtlSeconds,
						scanTimeoutMs: parseScanTimeout(c.env.SCAN_TIMEOUT_MS),
						perCheckTimeoutMs: parsePerCheckTimeout(c.env.PER_CHECK_TIMEOUT_MS),
						secondaryDoh: c.env.BV_DOH_ENDPOINT ? { endpoint: c.env.BV_DOH_ENDPOINT, token: c.env.BV_DOH_TOKEN } : undefined,
						whoisBinding: c.env.BV_WHOIS,
						infraProbe: c.env.BV_INFRA_PROBE,
						// Async brand-audit subsystem — parity with the single-call door
						// so a batched brand tool can also reach the D1 store + queue.
						brandAuditDb: c.env.BRAND_AUDIT_DB,
						brandAuditQueue: c.env.BRAND_AUDIT_QUEUE,
						rateLimitKv: c.env.RATE_LIMIT,
						quotaCoordinator: c.env.QUOTA_COORDINATOR,
						principalId: identity.identity.principalId,
						authTier: identity.identity.authTier,
						// Tier 0/1/2 lookup closures — batch invocations of brand tools
						// from internal callers must also exercise tiered mode when the
						// bindings are provisioned.
						...buildBrandTierLookups(c.env),
						...(wantStructured
							? {
									resultCapture: (r: import('@blackveil/dns-checks/scoring').CheckResult) => {
										capturedResult = r;
									},
								}
							: {}),
					},
				);

				const isError = toolResult.isError ?? false;

				// B1: one internal-source access-log row per processed domain (decision 4).
				// entry.sanitized is the canonical scanned domain (non-null within validEntries).
				recordInternalAccessLog({
					toolName: normalizeToolName(toolName),
					domain: entry.sanitized as string,
					status: isError ? 'error' : 'pass',
					clientType: c.req.header(AGENT_CALLER_HEADER) ?? null,
					intelligenceDb: c.env.INTELLIGENCE_DB,
					analyticsQueue: c.env.MCP_ANALYTICS_QUEUE,
					analyticsPiiLevel: parseAnalyticsPiiLevel(c.env.ANALYTICS_PII_LEVEL),
					ipEncryptionKey: c.env.MCP_ACCESS_LOG_IP_ENCRYPTION_KEY,
					ipEncryptionKeyVersion: c.env.MCP_ACCESS_LOG_IP_KEY_VERSION,
					startTime: batchStartTime,
					waitUntil: (p: Promise<unknown>) => c.executionCtx.waitUntil(p),
				});

				// Parity with the single-call door (`/internal/tools/call`): under
				// `?format=structured`, `result` is the tool's PAYLOAD, never the
				// MCP frame. Two kinds of tool produce that payload differently:
				//
				//   1. TOOL_REGISTRY CheckResult tools → captured via `resultCapture`.
				//   2. Custom-shape tools (scan_domain, prioritize_csc_leads,
				//      map_csc_products, … — the `NON_CHECK_RESULT_TOOLS` set) produce
				//      no CheckResult but DO set `structuredContent`.
				//
				// Case 2 previously fell through to `toolResult`, so a batched
				// custom-shape tool returned the MCP frame while a batched check tool
				// returned a bare payload — the same `payload.result` read could not
				// serve both. That asymmetry is the bug this branch fixes.
				const structuredPayload = capturedResult ?? toolResult.structuredContent;
				const result = wantStructured && structuredPayload !== undefined && structuredPayload !== null ? structuredPayload : toolResult;
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
 * Auth gate for /trial-keys (collection) and /trial-keys/* (item) — these routes
 * mint API credentials, so the network guard is not enough on its own. Mirrors
 * the /oauth/grants pattern: 503 if BV_MCP_OAUTH_MINT_KEY is unset (mis-deploy),
 * 401 on missing/bad bearer.
 */
const trialKeysAuthGate: import('hono').MiddlewareHandler<InternalAppEnv> = async (c, next) => {
	const expected = dedicatedCapability(c.env, 'BV_MCP_OAUTH_MINT_KEY');
	if (!expected) {
		return c.json({ error: 'internal_auth_not_configured' }, 503, { 'Cache-Control': 'no-store' });
	}
	if (!(await isAuthorizedRequest(c.req.header('authorization'), expected))) {
		return c.json({ error: 'unauthorized' }, 401, { 'Cache-Control': 'no-store' });
	}
	return next();
};
internalRoutes.use('/trial-keys', trialKeysAuthGate);
internalRoutes.use('/trial-keys/*', trialKeysAuthGate);

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
		const bodyRead = await readBoundedText(c.req.raw, MAX_REQUEST_BODY_BYTES);
		if (!bodyRead.ok) return c.json({ error: `Request body exceeds maximum of ${MAX_REQUEST_BODY_BYTES} bytes` }, 413);
		body = CreateTrialKeyRequestSchema.parse(JSON.parse(bodyRead.text));
	} catch (err) {
		if (err instanceof ZodError) {
			return c.json({ error: `Invalid ${err.issues[0].path.join('.')}: ${err.issues[0].message}` }, 400);
		}
		return c.json({ error: 'Invalid request body' }, 400);
	}

	const kvEnvelopeKey = parseEnvelopeKey(c.env.KV_ENVELOPE_KEY) ?? undefined;
	const result = await createTrialKey(
		c.env.RATE_LIMIT,
		{
			label: body.label,
			tier: body.tier as import('./lib/config').McpApiKeyTier | undefined,
			expiresInDays: body.expiresInDays,
			maxUses: body.maxUses,
		},
		kvEnvelopeKey,
	);

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

	const kvEnvelopeKeyForGet = parseEnvelopeKey(c.env.KV_ENVELOPE_KEY) ?? undefined;
	const record = await getTrialKeyStatus(c.env.RATE_LIMIT, hash, kvEnvelopeKeyForGet);
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

	try {
		const deleted = await revokeTrialKey(c.env.RATE_LIMIT, hash, c.env.QUOTA_COORDINATOR);
		return c.json({ deleted });
	} catch {
		return c.json({ error: 'trial_revocation_state_unavailable' }, 503, { 'Cache-Control': 'no-store', 'Retry-After': '30' });
	}
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

	const kvEnvelopeKeyForList = parseEnvelopeKey(c.env.KV_ENVELOPE_KEY) ?? undefined;
	const keys = await listTrialKeys(c.env.RATE_LIMIT, { limit }, kvEnvelopeKeyForList);
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

/** Validate analytics prerequisites (CF_ACCOUNT_ID + CF_ANALYTICS_TOKEN) + resolve the AE dataset name. */
function requireAnalyticsConfig(env: InternalEnv): { accountId: string; token: string; dataset: string } | null {
	if (!env.CF_ACCOUNT_ID || !env.CF_ANALYTICS_TOKEN) return null;
	return { accountId: env.CF_ACCOUNT_ID, token: env.CF_ANALYTICS_TOKEN, dataset: resolveAnalyticsDataset(env.ANALYTICS_DATASET) };
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
			queryAnalyticsEngine(config.accountId, config.token, queryTierToolUsage(days, tier, config.dataset)),
			queryAnalyticsEngine(config.accountId, config.token, queryTierLatency(days, tier, config.dataset)),
			queryAnalyticsEngine(config.accountId, config.token, queryTierErrorRate(days, tier, config.dataset)),
			queryAnalyticsEngine(config.accountId, config.token, queryTierCachePerformance(days, tier, config.dataset)),
			queryAnalyticsEngine(config.accountId, config.token, queryTierRateLimits(days, tier, config.dataset)),
			queryAnalyticsEngine(config.accountId, config.token, queryTierSessions(days, tier, config.dataset)),
			queryAnalyticsEngine(config.accountId, config.token, queryTierDailyTrend(days, tier, config.dataset)),
			queryAnalyticsEngine(config.accountId, config.token, queryTierTopTools(hours, config.dataset)),
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
		const rows = await queryAnalyticsEngine(config.accountId, config.token, queryKeyUsage(days, keyHashPrefix, config.dataset));
		return c.json({ days, keyHash: keyHashPrefix ?? 'all', usage: rows });
	} catch (err) {
		return c.json({ error: 'Analytics query failed', detail: err instanceof Error ? err.message.slice(0, 100) : 'unknown' }, 502);
	}
});

/**
 * GET /internal/analytics/usage  (D1, precise — not sampled)
 * Per-customer (key_hash) call counts over a bounded window.
 * Query: ?days=7&key_hash=<16-char prefix>
 */
internalRoutes.get('/analytics/usage', async (c) => {
	const db = c.env.INTELLIGENCE_DB;
	if (!db) return c.json({ error: 'Analytics store not configured (INTELLIGENCE_DB required)' }, 500);
	const url = new URL(c.req.url);
	const days = Number(parseDays(url));
	const windowSec = days * 86400;
	const keyHash = url.searchParams.get('key_hash') ?? undefined;
	// Differentiate internal (bv-web service-binding `/internal/tools/*`) from external
	// (public `/mcp`) traffic. Legacy rows predate the `source` column → COALESCE to
	// 'public'. An unrecognized `?source=` value is ignored (treated as 'all'), matching
	// the endpoint's lenient posture — only the known set is ever bound into the filter.
	const sourceParam = url.searchParams.get('source');
	const sourceFilter = sourceParam === 'public' || sourceParam === 'internal' ? sourceParam : undefined;
	try {
		const filters: string[] = [`created_at >= (strftime('%s','now') - ?)`];
		const binds: unknown[] = [windowSec];
		if (keyHash) {
			filters.push('key_hash = ?');
			binds.push(keyHash);
		}
		if (sourceFilter) {
			filters.push(`COALESCE(source, 'public') = ?`);
			binds.push(sourceFilter);
		}
		const sql = `SELECT key_hash, tool_name, COALESCE(source, 'public') AS source, COUNT(*) AS calls, MAX(created_at) AS last_seen
			   FROM mcp_access_log WHERE ${filters.join(' AND ')}
			   GROUP BY key_hash, tool_name, COALESCE(source, 'public') ORDER BY calls DESC LIMIT 500`;
		const { results } = await db
			.prepare(sql)
			.bind(...binds)
			.all();
		return c.json({ days: String(days), keyHash: keyHash ?? 'all', source: sourceFilter ?? 'all', usage: results ?? [] });
	} catch (err) {
		return c.json({ error: 'Usage query failed', detail: err instanceof Error ? err.message.slice(0, 100) : 'unknown' }, 502);
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
		const rows = await queryAnalyticsEngine(config.accountId, config.token, queryTierDigest(hours, config.dataset));
		return c.json({ days, tiers: rows });
	} catch (err) {
		return c.json({ error: 'Analytics query failed', detail: err instanceof Error ? err.message.slice(0, 100) : 'unknown' }, 502);
	}
});

/**
 * GET /internal/analytics/geo (AE, sampled) — geographic rollup for dashboards.
 *
 * Counts per country/region/city/asn from `tool_call`. Query params: ?days=7
 */
internalRoutes.get('/analytics/geo', async (c) => {
	const config = requireAnalyticsConfig(c.env);
	if (!config) {
		return c.json({ error: 'Analytics not configured (CF_ACCOUNT_ID + CF_ANALYTICS_TOKEN required)' }, 500);
	}
	const days = parseDays(new URL(c.req.url));
	try {
		const rows = await queryAnalyticsEngine(config.accountId, config.token, queryGeoRollup(days, config.dataset));
		return c.json({ days, geo: rows });
	} catch (err) {
		return c.json({ error: 'Geo query failed', detail: err instanceof Error ? err.message.slice(0, 100) : 'unknown' }, 502);
	}
});

/**
 * Strict bearer gate for the forensics re-identification surface.
 *
 * Unlike `internalLenientAuthGate`, this gate IGNORES `REQUIRE_INTERNAL_AUTH=false`
 * and ALWAYS enforces — the endpoint decrypts raw client IPs, so the network
 * guard alone is insufficient. Fail-closed: 503 if `BV_WEB_INTERNAL_KEY` is unset
 * (mis-deploy), 401 on missing/wrong bearer. Registered BEFORE the route below.
 */
const internalStrictAuthGate: import('hono').MiddlewareHandler<{ Bindings: InternalEnv }> = async (c, next) => {
	const expected = c.env.BV_WEB_INTERNAL_KEY;
	if (!expected) return c.json({ error: 'internal_auth_not_configured' }, 503, { 'Cache-Control': 'no-store' });
	if (!(await isAuthorizedRequest(c.req.header('authorization'), expected))) {
		return c.json({ error: 'unauthorized' }, 401, { 'Cache-Control': 'no-store' });
	}
	return next();
};
internalRoutes.use('/analytics/forensics', internalStrictAuthGate);

/**
 * GET /internal/analytics/forensics (D1, STRICT) — recent events with DECRYPTED IP.
 *
 * Operator-only re-identification surface; every call writes a self-audit row
 * into the `mcp_access_log_audit` table in INTELLIGENCE_DB (`action = analytics.forensics.decrypt`).
 * Query: ?days=1&key_hash=<prefix>&ip_hash=<hash>
 */
internalRoutes.get('/analytics/forensics', async (c) => {
	const db = c.env.INTELLIGENCE_DB;
	if (!db) return c.json({ error: 'Analytics store not configured (INTELLIGENCE_DB required)' }, 500);
	const { decryptIpEvidence } = await import('./mcp/execute');
	const url = new URL(c.req.url);
	const days = Number(parseDays(url));
	const windowSec = days * 86400;
	const ipHash = url.searchParams.get('ip_hash');
	const keyHash = url.searchParams.get('key_hash');
	try {
		const filters: string[] = [`created_at >= (strftime('%s','now') - ?)`];
		const binds: unknown[] = [windowSec];
		if (ipHash) {
			filters.push('ip_hash = ?');
			binds.push(ipHash);
		}
		if (keyHash) {
			filters.push('key_hash = ?');
			binds.push(keyHash);
		}
		const { results } = await db
			.prepare(
				`SELECT created_at, ip_ciphertext, ip_key_version, ip_masked, ip_hash, key_hash, country, ptr_hostname, tool_name, domain
				FROM mcp_access_log WHERE ${filters.join(' AND ')} ORDER BY created_at DESC LIMIT 200`,
			)
			.bind(...binds)
			.all();
		const key = c.env.MCP_ACCESS_LOG_IP_ENCRYPTION_KEY;
		const events = await Promise.all(
			(results ?? []).map(async (r) => {
				const row = r as Record<string, unknown>;
				const ip = row.ip_ciphertext ? await decryptIpEvidence(String(row.ip_ciphertext), key) : null;
				return { ...row, ip: ip ?? row.ip_masked ?? null, ip_ciphertext: undefined };
			}),
		);

		// Self-audit: record WHO decrypted WHAT SCOPE into mcp_access_log_audit — a table in
		// INTELLIGENCE_DB (the same DB the forensics handler already binds), NOT the tenants
		// registry `audit_events` (a SEPARATE D1 this handler has no binding to — writing there
		// would throw "no such table" on every call). `scope` is JSON {days, filters, count} so
		// the trail captures the actual re-identification scope, not just that one occurred. A
		// failed audit write is LOGGED at warn (not silently swallowed) so monitoring can catch a
		// broken trail; the response still returns (fail-open, matching the codebase ethos).
		const auditScope = JSON.stringify({ days, ipHashFilter: ipHash ?? null, keyHashFilter: keyHash ?? null, resultCount: events.length });
		await db
			.prepare(`INSERT INTO mcp_access_log_audit (id, actor, action, ip_hash, scope, outcome) VALUES (?, ?, ?, ?, ?, ?)`)
			.bind(crypto.randomUUID(), 'internal_bearer', 'analytics.forensics.decrypt', ipHash ?? null, auditScope, 'success')
			.run()
			.catch((auditErr) =>
				logError(auditErr instanceof Error ? auditErr : String(auditErr), {
					severity: 'warn',
					category: 'audit',
					details: { event: 'analytics.forensics.decrypt', auditWriteFailed: true },
				}),
			);

		return c.json({ days: String(days), count: events.length, events });
	} catch (err) {
		return c.json({ error: 'Forensics query failed', detail: err instanceof Error ? err.message.slice(0, 100) : 'unknown' }, 502);
	}
});

internalRoutes.use('/analytics/erase', internalStrictAuthGate);

/**
 * POST /internal/analytics/erase (D1, STRICT) — data-subject erasure.
 *
 * Deletes every `mcp_access_log` row matching the given `key_hash` and/or
 * `ip_hash` (at least one required; both = AND). The `mcp_access_log_audit`
 * trail is deliberately NOT erased — the self-audit row written below is the
 * durable evidence that the erasure happened. Same strict bearer gate as
 * forensics: this endpoint destroys evidence, so the network guard alone is
 * insufficient. Query: ?key_hash=<hash>&ip_hash=<hash>
 */
internalRoutes.post('/analytics/erase', async (c) => {
	const db = c.env.INTELLIGENCE_DB;
	if (!db) return c.json({ error: 'Analytics store not configured (INTELLIGENCE_DB required)' }, 500);
	const url = new URL(c.req.url);
	const ipHash = url.searchParams.get('ip_hash');
	const keyHash = url.searchParams.get('key_hash');
	if (!ipHash && !keyHash) return c.json({ error: 'Missing required parameter: key_hash or ip_hash' }, 400);
	try {
		const filters: string[] = [];
		const binds: unknown[] = [];
		if (ipHash) {
			filters.push('ip_hash = ?');
			binds.push(ipHash);
		}
		if (keyHash) {
			filters.push('key_hash = ?');
			binds.push(keyHash);
		}
		const result = await db
			.prepare(`DELETE FROM mcp_access_log WHERE ${filters.join(' AND ')}`)
			.bind(...binds)
			.run();
		const deleted = result.meta?.changes ?? 0;

		const auditScope = JSON.stringify({ ipHashFilter: ipHash ?? null, keyHashFilter: keyHash ?? null, deleted });
		await db
			.prepare(`INSERT INTO mcp_access_log_audit (id, actor, action, ip_hash, scope, outcome) VALUES (?, ?, ?, ?, ?, ?)`)
			.bind(crypto.randomUUID(), 'internal_bearer', 'analytics.subject.erase', ipHash ?? null, auditScope, 'success')
			.run()
			.catch((auditErr) =>
				logError(auditErr instanceof Error ? auditErr : String(auditErr), {
					severity: 'warn',
					category: 'audit',
					details: { event: 'analytics.subject.erase', auditWriteFailed: true },
				}),
			);

		return c.json({ deleted, key_hash: keyHash ?? null, ip_hash: ipHash ?? null });
	} catch (err) {
		return c.json({ error: 'Erase failed', detail: err instanceof Error ? err.message.slice(0, 100) : 'unknown' }, 502);
	}
});
