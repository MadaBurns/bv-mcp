// SPDX-License-Identifier: BUSL-1.1
// bv-oversize-ok: executeMcpRequest is the ordered session→concurrency→quota→policy gate chain; decomposing it is a separate, security-reviewed change

import {
	checkToolDailyRateLimit,
	checkGlobalDailyLimit,
	checkIpScopedQuotaBatch,
	checkIpDailyLimit,
	checkDistinctDomainDailyLimit,
	acquireConcurrencySlot,
	releaseConcurrencySlot,
} from '../lib/rate-limiter';
import { logEvent, logError } from '../lib/log';
import { jsonRpcError, JSON_RPC_ERRORS, JsonRpcClientError, isJsonRpcNotification, sanitizeErrorMessage } from '../lib/json-rpc';
import { buildControlPlaneRateLimitResponse, validateSessionRequest } from './route-gates';
import {
	AGGREGATE_QUOTA_COUNTER,
	FREE_TOOL_DAILY_LIMITS,
	FREE_IP_DAILY_LIMIT,
	FREE_DISTINCT_DOMAIN_DAILY_LIMIT,
	FORCE_REFRESH_DAILY_LIMIT,
	GLOBAL_DAILY_TOOL_LIMIT,
	TIER_AGGREGATE_DAILY_LIMITS,
	TIER_CONCURRENT_LIMITS,
	buildUpgradeData,
	evaluateToolPolicy,
	tierToolDailyLimit,
	type McpApiKeyTier,
} from '../lib/config';
import { normalizeToolName } from '../handlers/tool-args';
import { shardIndexForKey, isQuotaShardSaltMissing } from '../lib/quota-coordinator';
import { acceptsSSE } from '../lib/sse';
import { dispatchMcpMethod } from './dispatch';
import { validateJsonRpcRequest } from './request';
import type { JsonRpcRequest } from '../lib/json-rpc';
import type { QuotaCoordinator } from '../lib/quota-coordinator';
import type { AnalyticsClient } from '../lib/analytics';
import { hashDomain } from '../lib/analytics';
import { piiAllows } from '../lib/analytics-pii';
import { extractProtocolHeaders, readJsonRpcErrorPayload } from './response';
import {
	extractAccessLogDomain,
	getDomainFromParams,
	getToolCallLogInput,
	isMeteredForceRefresh,
	recordMcpAccessLog,
	__recordMcpAccessLogForTest,
	recordInternalAccessLog,
	accessLogInsertSql,
	accessLogBindings,
	type RecordInternalAccessLogInput,
} from './access-log';
import { encryptIpEvidence, decryptIpEvidence } from './ip-evidence';
import { emitRequestAnalytics, recordMcpToolErrorIfUnknownTool } from './request-telemetry';
import {
	buildAuthRequiredResponse,
	buildGatedToolResponse,
	buildInternalOnlyToolResponse,
	buildTierQuotaExceededResponse,
} from './responses';

// Re-exports: every name that was exported from this module before the split stays importable from here.
export {
	extractAccessLogDomain,
	encryptIpEvidence,
	decryptIpEvidence,
	__recordMcpAccessLogForTest,
	recordInternalAccessLog,
	accessLogInsertSql,
	accessLogBindings,
};
export type { RecordInternalAccessLogInput };

export type ProcessedRequestResult =
	| {
			kind: 'notification';
	  }
	| {
			kind: 'response';
			payload: unknown;
			headers: Record<string, string>;
			httpStatus: number;
			useErrorEnvelope: boolean;
			eventId?: string;
			streamOperation?: Promise<unknown>;
	  };

export interface ExecuteMcpRequestOptions {
	body: JsonRpcRequest;
	accept?: string;
	allowStreaming: boolean;
	batchMode: boolean;
	batchSize: number;
	responseTransport: 'json' | 'sse';
	startTime: number;
	/**
	 * F2 — server-generated per-request correlation id (`crypto.randomUUID()`),
	 * minted at the Worker entry point in `src/index.ts` and threaded here so
	 * every `logEvent`/`logError` on the request path carries the same id,
	 * letting multi-line traces be stitched. Optional: undefined on legacy/test
	 * call sites that do not mint one. Distinct from the client JSON-RPC id.
	 */
	correlationId?: string;
	ip: string;
	isAuthenticated: boolean;
	tierAuthResult?: import('../lib/tier-auth').TierAuthResult;
	/**
	 * D2 contract-flag gate switch, sourced from `env.ENFORCE_CONTRACT_FLAG_GATE`
	 * via `isContractFlagGateEnabled`. Default/undefined = OFF (no behavior change);
	 * activate only together with the bv-web-prod developer-claim carve-out.
	 */
	contractFlagGateEnabled?: boolean;
	userAgent?: string;
	sessionId?: string;
	validateSession: boolean;
	sessionErrorMessage?: string;
	createSessionOnInitialize?: boolean;
	existingSessionId?: string;
	serverVersion: string;
	rateLimitKv?: KVNamespace;
	quotaCoordinator?: DurableObjectNamespace<QuotaCoordinator>;
	/**
	 * R8 — QuotaCoordinator shard routing (flag + salt). Built from
	 * `QUOTA_SHARDING_ENABLED` / `QUOTA_SHARD_SALT` at the index.ts seam. Omitted →
	 * `SINGLETON_ROUTING` (sharding OFF, today's behavior).
	 */
	quotaShardRouting?: import('../lib/quota-coordinator').ShardRouting;
	sessionStore?: KVNamespace;
	scanCache?: KVNamespace;
	providerSignaturesUrl?: string;
	providerSignaturesAllowedHosts?: string;
	providerSignaturesSha256?: string;
	analytics?: AnalyticsClient;
	profileAccumulator?: DurableObjectNamespace;
	/**
	 * ProfileAccumulator write-sharding mode (R10, default-off). Sourced from
	 * `env.PROFILE_ACCUMULATOR_SHARDING` via `resolveAccumulatorShardModeFromEnv`
	 * at the index.ts construction sites; threaded down to ToolRuntimeOptions so
	 * the /ingest write, the /weights read, and the intelligence read seams all
	 * resolve the SAME per-profile shard. `'global'`/undefined = legacy (unchanged).
	 */
	profileAccumulatorShardMode?: import('../lib/profile-accumulator').AccumulatorShardMode;
	waitUntil?: (promise: Promise<unknown>) => void;
	scoringConfig?: import('@blackveil/dns-checks/scoring').ScoringConfig;
	cacheTtlSeconds?: number;
	scanTimeoutMs?: number;
	perCheckTimeoutMs?: number;
	/** `WEB_POSTURE_ENABLED` kill switch for scan_domain's non-scoring web posture section. */
	webPostureEnabled?: boolean;
	/** Custom secondary DoH endpoint URL (bv-dns). */
	secondaryDohEndpoint?: string;
	/** Auth token for custom secondary DoH. */
	secondaryDohToken?: string;
	country?: string;
	clientType?: string;
	/**
	 * B1 — access-log request-path origin. Defaults to `'public'` on the public
	 * /mcp path; the internal service-binding recorder passes `'internal'`. Stored
	 * in the `mcp_access_log.source` column.
	 */
	source?: string;
	/**
	 * Phase 1, decision #2 — when on AND the event is internal-source, route the
	 * access-log write to the low-cardinality `mcp_access_rollup` counter instead
	 * of a per-event row/queue insert. Sourced from `ANALYTICS_ROLLUP_INTERNAL` at
	 * the index.ts seam. Default-off; undefined/false = per-event for everything
	 * (today's behavior). External (`source !== 'internal'`) traffic is unaffected.
	 */
	rollupInternal?: boolean;
	/** Raw `MCP-Protocol-Version` request header (threaded to dispatch for STRUCTURED_RESULT comment trimming). */
	protocolVersionHeader?: string;
	authTier?: string;
	sessionHash?: string;
	/** Full 256-bit authenticated principal hash for authorization, ownership, and abuse controls. */
	keyHash?: string;
	/** Truncated principal hash for analytics only (first 16 chars of SHA-256). */
	analyticsKeyHash?: string;
	/** Verified, discriminated identity for the internal M365 resolver. */
	m365Identity?: import('../tools/m365/proxy').M365PrincipalIdentity;
	/** FNV-1a hash of cf-connecting-ip (`i_` prefix) for per-IP analytics filtering. */
	ipHash?: string;
	/** Cloudflare edge colo (`request.cf.colo`) for per-datacenter analytics grouping. Appended as the trailing blob on mcp_request/tool_call events. */
	colo?: string;
	/** Enrichment from request.cf — populated at the index.ts seam, consumed by the access-log producer + AE geo blobs. */
	region?: string;
	city?: string;
	latitude?: string;
	longitude?: string;
	asn?: number;
	asOrg?: string;
	/** Cloudflare Queue producer for the analytics access-log path. Absent on BSL self-hosts → inline insert fallback. */
	analyticsQueue?: { send(message: unknown, options?: { contentType?: 'json' }): Promise<void> };
	/** Operator-chosen PII capture depth. Undefined → treated as 'coarse' by the producer. */
	analyticsPiiLevel?: import('../lib/analytics-pii').AnalyticsPiiLevel;
	/** D1 binding for privacy-preserving MCP access logs. */
	intelligenceDb?: D1Database;
	/** Base64-encoded AES-GCM key for encrypted abuse-investigation IP evidence. */
	ipEncryptionKey?: string;
	ipEncryptionKeyVersion?: string;
	certstream?: { fetch: typeof fetch };
	certstreamAuthToken?: string;
	/** SSLMate Cert Spotter API token for CT queries. Absent → unauthenticated. */
	certspotterToken?: string;
	/** TypeSafe (Jev) API key for STANDALONE judgment calls. Absent → deterministic path. Never reaches the score. */
	typesafeApiKey?: string;
	whoisBinding?: { fetch: typeof fetch };
	/** Operator-only bv-recon service binding. Fail-soft; absent on BSL self-hosts. */
	reconBinding?: { fetch: typeof fetch };
	/** Bearer admin token forwarded to bv-recon. */
	reconAuthToken?: string;
	/** Operator-only bv-tls-probe service binding (negotiated-TLS-version detection). Fail-soft; absent on BSL self-hosts. */
	tlsProbeBinding?: { fetch: typeof fetch };
	/** Bearer token forwarded to bv-tls-probe. */
	tlsProbeAuthToken?: string;
	/** Service binding to bv-web's internal M365 proxy surface. Fail-soft; absent when bv-web is not provisioned. */
	m365Proxy?: { fetch: typeof fetch };
	/** Dedicated bearer (BV_MCP_M365_KEY) forwarded to bv-web's internal M365 endpoints. */
	m365ProxyAuthToken?: string;
	/** Service binding to bv-web (BV_WEB) used by get_domain_rank to call the C1 benchmark endpoint. Fail-soft; absent on BSL self-hosts. */
	bvWebBenchmark?: { fetch: typeof fetch };
	/** Bearer token (BV_WEB_INTERNAL_KEY) forwarded to the C1 benchmark endpoint. */
	bvWebBenchmarkAuthToken?: string;
	infraProbe?: { fetch: typeof fetch };
	/** D1 binding for the brand-audit DB. v2.21.2+. */
	brandAuditDb?: D1Database;
	/** Cloudflare Queue producer for brand-audit batch path. v2.21.2+. */
	brandAuditQueue?: { send(message: unknown, options?: { contentType?: 'json' }): Promise<void> };
	asyncBatchQueue?: import('../tools/batch-scan-async').AsyncBatchQueueProducer;
	asyncBatchKv?: KVNamespace;
	/** R2 bucket binding for brand-audit PDF reports. v2.21.2+. */
	brandReportsR2?: R2Bucket;
	/**
	 * Public origin of the inbound request (e.g. https://dns-mcp.blackveilsecurity.com),
	 * used by brand_audit_get_report to build the authenticated `/reports/...`
	 * PDF download URL. Absent on the internal service-binding path → the tool
	 * emits a relative path instead.
	 */
	publicOrigin?: string;
	/**
	 * Full `WWW-Authenticate` header VALUE for an UNAUTHENTICATED call to a paid-only tool.
	 * When set, that gate returns HTTP 401 + this challenge (so a client that starts OAuth
	 * on a 401, e.g. Claude's Connect card, can discover the protected-resource metadata);
	 * absent → the legacy 403 (self-hosts without OAuth, where the PRM URL would 404).
	 * The JSON-RPC body is identical either way. Authenticated free/agent 403s never use it.
	 */
	unauthChallenge?: string;
	/** Service binding to bv-browser-renderer Worker. v2.21.2+. */
	browserRenderer?: { fetch: typeof fetch };
	/** principalId for the calling user — required by enforceBrandAuditQuota and IDOR-cache fix. v2.21.2+. */
	principalId?: string;
	/**
	 * T13 — runtime-default for `discover_brand_domains` discovery_mode.
	 * Sourced from `env.BRAND_AUDIT_DISCOVERY_MODE_DEFAULT`. `'tiered'` flips
	 * the default; undefined leaves the public schema default (`'classic'`)
	 * in charge. Threaded into `ToolRuntimeOptions.discoveryModeDefault`
	 * which `brand_audit_single` reads.
	 */
	discoveryModeDefault?: string;
	/**
	 * Tier 0/1/2 lookup closures wrapping the private brand-discovery service
	 * bindings (`BV_ENTERPRISE`, `BV_INFRA_GRAPH`, `BV_INTEL_GATEWAY`).
	 * Constructed at the production seam in `src/index.ts` when the bindings
	 * + `BV_WEB_INTERNAL_KEY` are provisioned. Undefined on BSL self-hosts.
	 * Threaded into `ToolRuntimeOptions` so `discover_brand_domains` and
	 * `brand_audit_single` can forward them through to `discoverBrandDomains`.
	 */
	tier0Lookup?: (domain: string) => Promise<import('../lib/brand-tier0-enterprise').Tier0Result>;
	tier1Lookup?: (domain: string) => Promise<import('../lib/brand-tier1-graph').Tier1Result>;
	tier2Lookup?: (domain: string) => Promise<import('../lib/brand-tier2-evidence').Tier2Result>;
	/**
	 * Global daily tools/call cap across ALL unauthenticated callers. Defaults
	 * to the GLOBAL_DAILY_TOOL_LIMIT constant; index.ts populates it from the
	 * GLOBAL_DAILY_TOOL_LIMIT env var via parseGlobalDailyLimit() so operators
	 * can throttle without a code deploy.
	 */
	globalDailyLimit?: number;
}

export async function executeMcpRequest(options: ExecuteMcpRequestOptions): Promise<ProcessedRequestResult> {
	const validationError = validateJsonRpcRequest(options.body);
	if (validationError) {
		emitRequestAnalytics(options, typeof options.body?.method === 'string' ? options.body.method : 'invalid', 'error', true);
		return {
			kind: 'response',
			payload: validationError.payload,
			headers: {},
			httpStatus: validationError.status,
			useErrorEnvelope: true,
			eventId: options.body.id != null ? String(options.body.id) : undefined,
		};
	}

	const { id, method, params } = options.body;
	const eventId = id != null ? String(id) : undefined;
	const accessLogInput = getToolCallLogInput(method, params as Record<string, unknown> | undefined);

	if (options.batchMode && options.batchSize > 1 && method === 'initialize') {
		emitRequestAnalytics(options, method, 'error', true);
		return {
			kind: 'response',
			payload: jsonRpcError(
				id,
				JSON_RPC_ERRORS.INVALID_REQUEST,
				'Invalid JSON-RPC batch request: initialize cannot be batched with other messages',
			),
			headers: {},
			httpStatus: 400,
			useErrorEnvelope: true,
			eventId,
		};
	}

	// PUBLIC-PATH-ONLY internal-only gate. map_registrar_products (INTERNAL_ONLY_TOOLS) is
	// removed from the public /mcp surface: reject BEFORE any tier branching so it
	// applies to ALL callers (unauthenticated, free, developer, owner) with the same
	// unknown-tool result — no existence leak, no 403. The internal path
	// (src/internal.ts → handleToolsCall) never reaches executeMcpRequest, so the
	// tool stays callable there and via the direct prioritize_portfolio_leads function call.
	if (method === 'tools/call') {
		const internalOnlyNameRaw =
			typeof params === 'object' && params !== null && 'name' in params ? (params as Record<string, unknown>).name : undefined;
		const internalOnlyName = typeof internalOnlyNameRaw === 'string' ? normalizeToolName(internalOnlyNameRaw) : '';
		// Only the internal-only verdict is acted on here: it is the highest-precedence
		// block in evaluateToolPolicy, so reading it alone keeps this gate exactly where
		// it has always been (before tier branching) while the DECISION comes from the
		// shared chokepoint. The remaining blocks are read at their existing sites below.
		const internalOnlyPolicy = evaluateToolPolicy({
			surface: 'public',
			tool: internalOnlyName,
			authenticated: options.isAuthenticated === true,
			tier: options.tierAuthResult?.tier ?? null,
		});
		if (!internalOnlyPolicy.allowed && internalOnlyPolicy.block === 'internal_only') {
			return buildInternalOnlyToolResponse(id, internalOnlyName, method, options, eventId, accessLogInput);
		}
		// SQ-520: AGGREGATE_QUOTA_COUNTER is the per-key total's counter name, not a tool. A
		// client-supplied `name` of the same string would reach the per-tool counter AND the
		// aggregate on one key (every call counted twice, and the total drainable by name).
		// Normalised names are only trimmed and lowercased, so no counter spelling is
		// unreachable from the wire; reserve the name here, before any quota is consumed. The
		// result is the genuine unknown-tool payload the dispatch path would return anyway.
		if (internalOnlyName === AGGREGATE_QUOTA_COUNTER) {
			return buildInternalOnlyToolResponse(id, internalOnlyName, method, options, eventId, accessLogInput);
		}
	}

	let rateHeaders: Record<string, string> = {};
	/** Per-key total to consume once the session and concurrency gates pass (SQ-494/SQ-520). */
	let aggregateQuota: { tier: McpApiKeyTier; principalId: string; limit: number } | undefined;
	if (!options.isAuthenticated && method === 'tools/call') {
		const globalDailyLimit = options.globalDailyLimit ?? GLOBAL_DAILY_TOOL_LIMIT;
		const globalResult = await checkGlobalDailyLimit(globalDailyLimit, options.rateLimitKv, options.quotaCoordinator, options.analytics);
		if (!globalResult.allowed) {
			const globalHeaders: Record<string, string> = {};
			if (globalResult.retryAfterMs !== undefined) {
				globalHeaders['retry-after'] = String(Math.ceil(globalResult.retryAfterMs / 1000));
			}
			options.analytics?.emitRateLimitEvent({
				limitType: 'daily_global',
				toolName: 'n/a',
				limit: globalDailyLimit,
				remaining: 0,
				country: options.country,
				authTier: options.authTier,
			});
			emitRequestAnalytics(options, method, 'error', true);
			if (accessLogInput) {
				recordMcpAccessLog(options, { ...accessLogInput, rateLimited: true, status: 'unknown' });
			}
			return {
				kind: 'response',
				payload: jsonRpcError(
					id,
					JSON_RPC_ERRORS.RATE_LIMITED,
					'Service capacity reached for today. Please try again tomorrow or deploy your own instance.',
				),
				headers: globalHeaders,
				httpStatus: 429,
				useErrorEnvelope: true,
				eventId,
			};
		}

		// FIND-02: per-IP daily cap prevents one source consuming a disproportionate share
		// of the global free budget while staying under per-minute/hour limits.
		const ipDailyResult = await checkIpDailyLimit(options.ip, options.rateLimitKv);
		if (!ipDailyResult.allowed) {
			const ipDailyHeaders: Record<string, string> = {};
			if (ipDailyResult.retryAfterMs !== undefined) {
				ipDailyHeaders['retry-after'] = String(Math.ceil(ipDailyResult.retryAfterMs / 1000));
			}
			options.analytics?.emitRateLimitEvent({
				limitType: 'daily_ip',
				toolName: 'n/a',
				limit: FREE_IP_DAILY_LIMIT,
				remaining: 0,
				country: options.country,
				authTier: options.authTier,
			});
			emitRequestAnalytics(options, method, 'error', true);
			if (accessLogInput) {
				recordMcpAccessLog(options, { ...accessLogInput, rateLimited: true, status: 'unknown' });
			}
			return {
				kind: 'response',
				payload: jsonRpcError(
					id,
					JSON_RPC_ERRORS.RATE_LIMITED,
					'Rate limit exceeded. Daily request limit reached for this IP. Please try again tomorrow.',
					// Cross-tool per-IP daily ceiling — a free-tier volume limit an upgrade
					// raises. Anchored to the free spine (scan_domain); channel is self_serve
					// regardless of tool (isVolume429). Prose unchanged (no public-surface churn).
					buildUpgradeData('scan_domain', true),
				),
				headers: ipDailyHeaders,
				httpStatus: 429,
				useErrorEnvelope: true,
				eventId,
			};
		}

		// R8: resolve the tool name up front (pure — no quota side effects) so the
		// batched per-IP quota evaluation can fold the scoped-rate + per-tool-daily
		// checks into ONE QuotaCoordinator round trip routed to the IP's shard,
		// instead of two serial round trips to the global singleton.
		const toolNameRaw =
			typeof params === 'object' && params !== null && 'name' in params ? (params as Record<string, unknown>).name : undefined;
		const toolName = typeof toolNameRaw === 'string' ? normalizeToolName(toolNameRaw) : '';
		const toolDailyLimit = toolName ? FREE_TOOL_DAILY_LIMITS[toolName] : undefined;

		// Gated/auth-required tools are rejected (401/403) without ever recording a
		// per-tool-daily count in the serial path (their gate returns before the
		// tool-daily check). Preserve that EXACTLY by excluding tool-daily from the
		// batch for those tools — scoped-rate still runs for everyone (slot consumed),
		// matching the prior checkRateLimit-first ordering.
		const unauthPolicy = evaluateToolPolicy({ surface: 'public', tool: toolName, authenticated: false, tier: null });
		const toolGated = !unauthPolicy.allowed && (unauthPolicy.block === 'auth_required' || unauthPolicy.block === 'paid_only');
		const batchToolDailyLimit = !toolGated ? toolDailyLimit : undefined;

		const quotaBatch = await checkIpScopedQuotaBatch(options.ip, toolName, batchToolDailyLimit, {
			kv: options.rateLimitKv,
			quotaCoordinator: options.quotaCoordinator,
			routing: options.quotaShardRouting,
			// ADAM #6: surface every coordinator-batch bypass as an observable degradation
			// signal so an operator sees the quota guardrail is running degraded.
			onDegradation: (reason) =>
				options.analytics?.emitDegradationEvent({
					degradationType: 'quota_coordinator_fallback',
					component: reason,
					country: options.country,
					clientType: options.clientType as import('../lib/client-detection').McpClientType,
					authTier: options.authTier,
				}),
		});
		// R8 per-shard observability + salt-missing config guard (Phase 3, decisions
		// #3/#4). Only meaningful while sharding is ON; SINGLETON_ROUTING (the default)
		// skips both — byte-for-byte today's behavior. The shard index is the SAME
		// derivation the batch routed on (IP + salt), so the emitted distribution mirrors
		// real shard load (skew detection via queryQuotaShardSkew). Fail-open telemetry.
		const shardRouting = options.quotaShardRouting;
		if (shardRouting?.enabled) {
			const shardCtx = {
				country: options.country,
				clientType: options.clientType as import('../lib/client-detection').McpClientType,
				authTier: options.authTier,
			};
			options.analytics?.emitQuotaShardEvent({ shardIndex: shardIndexForKey(options.ip, shardRouting.salt), ...shardCtx });
			if (isQuotaShardSaltMissing(shardRouting)) {
				options.analytics?.emitDegradationEvent({
					degradationType: 'quota_shard_salt_missing',
					component: 'quota_coordinator',
					...shardCtx,
				});
			}
		}

		const rateResult = quotaBatch.rate;
		const minuteResetEpoch = Math.ceil(Date.now() / 60_000) * 60;
		rateHeaders = {
			'x-ratelimit-limit': '50',
			'x-ratelimit-remaining': String(rateResult.minuteRemaining),
			'x-ratelimit-reset': String(minuteResetEpoch),
		};
		if (!rateResult.allowed) {
			if (rateResult.retryAfterMs !== undefined) {
				rateHeaders['retry-after'] = String(Math.ceil(rateResult.retryAfterMs / 1000));
			}
			options.analytics?.emitRateLimitEvent({
				limitType: 'minute',
				toolName: 'n/a',
				limit: 50,
				remaining: rateResult.minuteRemaining,
				country: options.country,
				authTier: options.authTier,
			});
			emitRequestAnalytics(options, method, 'error', true);
			if (accessLogInput) {
				recordMcpAccessLog(options, { ...accessLogInput, rateLimited: true, status: 'unknown' });
			}
			return {
				kind: 'response',
				payload: jsonRpcError(
					id,
					JSON_RPC_ERRORS.RATE_LIMITED,
					`Rate limit exceeded. Retry after ${Math.ceil((rateResult.retryAfterMs ?? 0) / 1000)}s`,
				),
				headers: rateHeaders,
				httpStatus: 429,
				useErrorEnvelope: true,
				eventId,
			};
		}

		// Auth-required tools (identity_secops M365 reads) must NEVER be reached by an
		// unauthenticated caller: dispatch would forward to bv-web's internal M365 proxy
		// carrying the trusted internal bearer with keyHash:undefined. Reject before
		// dispatch with HTTP 401 + an allowlisted ("Invalid") message prefix.
		if (!unauthPolicy.allowed && unauthPolicy.block === 'auth_required') {
			return buildAuthRequiredResponse(id, toolName, method, options, eventId, accessLogInput);
		}
		if (!unauthPolicy.allowed && unauthPolicy.block === 'paid_only') {
			return buildGatedToolResponse(id, toolName, method, options, eventId, accessLogInput, options.unauthChallenge);
		}
		if (toolDailyLimit !== undefined) {
			// Verdict came from the batched evaluate above (same round trip as scoped-rate).
			// Fall back to a direct call only in the (unreachable) case the batch omitted it.
			const toolQuotaResult =
				quotaBatch.toolDaily ??
				(await checkToolDailyRateLimit(options.ip, toolName, toolDailyLimit, options.rateLimitKv, options.quotaCoordinator));
			const dailyResetEpoch = Math.ceil(Date.now() / 86_400_000) * 86_400;
			rateHeaders['x-quota-limit'] = String(toolQuotaResult.limit);
			rateHeaders['x-quota-remaining'] = String(toolQuotaResult.remaining);
			rateHeaders['x-quota-reset'] = String(dailyResetEpoch);
			rateHeaders['x-quota-tier'] = 'free';
			if (!toolQuotaResult.allowed) {
				if (toolQuotaResult.retryAfterMs !== undefined) {
					rateHeaders['retry-after'] = String(Math.ceil(toolQuotaResult.retryAfterMs / 1000));
				}
				options.analytics?.emitRateLimitEvent({
					limitType: 'daily_tool',
					toolName,
					limit: toolDailyLimit,
					remaining: 0,
					country: options.country,
					authTier: options.authTier ?? 'anon',
				});
				emitRequestAnalytics(options, method, 'error', true);
				if (accessLogInput) {
					recordMcpAccessLog(options, { ...accessLogInput, rateLimited: true, status: 'unknown' });
				}
				return {
					kind: 'response',
					payload: jsonRpcError(
						id,
						JSON_RPC_ERRORS.RATE_LIMITED,
						`Rate limit exceeded. ${toolName} is limited to ${toolDailyLimit} requests per day for free tier users.`,
						// Additive self-serve upgrade affordance (prose unchanged): a free caller
						// who exhausted a per-tool daily allotment converts by upgrading. Volume
						// ceilings are always self_serve (see resolveUpgradeChannel isVolume429).
						buildUpgradeData(toolName, true),
					),
					headers: rateHeaders,
					httpStatus: 429,
					useErrorEnvelope: true,
					eventId,
				};
			}
		}

		// FIND-06: sub-limit force_refresh requests so free-tier callers cannot
		// bypass the scan cache repeatedly and amplify backend load.
		const argsRaw =
			typeof params === 'object' && params !== null && 'arguments' in params ? (params as Record<string, unknown>).arguments : undefined;

		if (isMeteredForceRefresh(toolName, argsRaw)) {
			const forceRefreshResult = await checkToolDailyRateLimit(
				options.ip,
				'__force_refresh__',
				FORCE_REFRESH_DAILY_LIMIT,
				options.rateLimitKv,
				options.quotaCoordinator,
			);
			const dailyResetEpoch = Math.ceil(Date.now() / 86_400_000) * 86_400;
			rateHeaders['x-quota-limit'] = String(forceRefreshResult.limit);
			rateHeaders['x-quota-remaining'] = String(forceRefreshResult.remaining);
			rateHeaders['x-quota-reset'] = String(dailyResetEpoch);
			rateHeaders['x-quota-tier'] = 'free';
			if (!forceRefreshResult.allowed) {
				if (forceRefreshResult.retryAfterMs !== undefined) {
					rateHeaders['retry-after'] = String(Math.ceil(forceRefreshResult.retryAfterMs / 1000));
				}
				options.analytics?.emitRateLimitEvent({
					limitType: 'daily_tool',
					toolName: '__force_refresh__',
					limit: FORCE_REFRESH_DAILY_LIMIT,
					remaining: 0,
					country: options.country,
					authTier: options.authTier ?? 'anon',
				});
				emitRequestAnalytics(options, method, 'error', true);
				if (accessLogInput) {
					recordMcpAccessLog(options, { ...accessLogInput, rateLimited: true, status: 'unknown' });
				}
				return {
					kind: 'response',
					payload: jsonRpcError(
						id,
						JSON_RPC_ERRORS.RATE_LIMITED,
						`Rate limit exceeded. force_refresh is limited to ${FORCE_REFRESH_DAILY_LIMIT} requests per day for free tier users.`,
					),
					headers: rateHeaders,
					httpStatus: 429,
					useErrorEnvelope: true,
					eventId,
				};
			}
		}

		// Distinct-domain/day speed-bump: cap how many DISTINCT domains one
		// unauthenticated IP can scan per day across domain-bearing tools.
		const args = argsRaw && typeof argsRaw === 'object' && !Array.isArray(argsRaw) ? (argsRaw as Record<string, unknown>) : undefined;
		const ddcDomain = extractAccessLogDomain(args);
		if (ddcDomain) {
			// The domain slot is recorded before dispatch/validation intentionally: the cap throttles
			// distinct-domain enumeration, not just successful scans, so invalid calls still consume a slot.
			const ddcResult = await checkDistinctDomainDailyLimit(
				options.ip,
				hashDomain(ddcDomain),
				FREE_DISTINCT_DOMAIN_DAILY_LIMIT,
				options.rateLimitKv,
				options.quotaCoordinator,
				options.quotaShardRouting,
			);
			if (!ddcResult.allowed) {
				const ddcHeaders: Record<string, string> = {};
				if (ddcResult.retryAfterMs !== undefined) {
					ddcHeaders['retry-after'] = String(Math.ceil(ddcResult.retryAfterMs / 1000));
				}
				const dailyResetEpoch = Math.ceil(Date.now() / 86_400_000) * 86_400;
				ddcHeaders['x-quota-limit'] = String(FREE_DISTINCT_DOMAIN_DAILY_LIMIT);
				ddcHeaders['x-quota-remaining'] = '0';
				ddcHeaders['x-quota-reset'] = String(dailyResetEpoch);
				ddcHeaders['x-quota-tier'] = 'free';
				options.analytics?.emitRateLimitEvent({
					limitType: 'distinct_domain',
					toolName,
					limit: FREE_DISTINCT_DOMAIN_DAILY_LIMIT,
					remaining: 0,
					country: options.country,
					authTier: options.authTier ?? 'anon',
				});
				emitRequestAnalytics(options, method, 'error', true);
				if (accessLogInput) {
					recordMcpAccessLog(options, { ...accessLogInput, rateLimited: true, status: 'unknown' });
				}
				return {
					kind: 'response',
					payload: jsonRpcError(
						id,
						JSON_RPC_ERRORS.RATE_LIMITED,
						`Rate limit exceeded. Free tier is limited to ${FREE_DISTINCT_DOMAIN_DAILY_LIMIT} distinct domains per day. Authenticate for a higher limit.`,
						buildUpgradeData(toolName || 'scan_domain', true),
					),
					headers: ddcHeaders,
					httpStatus: 429,
					useErrorEnvelope: true,
					eventId,
				};
			}
		}
	} else if (options.tierAuthResult?.authenticated && options.tierAuthResult.tier && method === 'tools/call') {
		// Authenticated tier-based rate limiting (keyed by API key hash, not IP)
		const tier = options.tierAuthResult.tier;
		const principalId = options.tierAuthResult.keyHash ?? options.ip;

		const toolNameRaw =
			typeof params === 'object' && params !== null && 'name' in params ? (params as Record<string, unknown>).name : undefined;
		const toolName = typeof toolNameRaw === 'string' ? normalizeToolName(toolNameRaw) : 'unknown';

		// Per-tool tier override takes precedence over flat tier limit
		const dailyLimit = tierToolDailyLimit(tier, toolName);

		const authedPolicy = evaluateToolPolicy({
			surface: 'public',
			tool: toolName,
			authenticated: true,
			tier,
			hasContractFlag: options.tierAuthResult.contractFlag === true,
			contractFlagGateEnabled: options.contractFlagGateEnabled === true,
		});
		if (!authedPolicy.allowed && authedPolicy.block === 'paid_only') {
			return buildGatedToolResponse(id, toolName, method, options, eventId, accessLogInput);
		}

		// D2 contract-flag gate (INERT unless ENFORCE_CONTRACT_FLAG_GATE=true). Catches
		// the caller the tier check above lets through: a PAID tier (dailyLimit != 0,
		// e.g. developer) hitting an enumeration/recon tool WITHOUT the per-contract
		// flag → same sales-channel 403 as an unpaid caller, so a cheap paid seat can't
		// buy the enumeration corpus. `owner` bypasses; the flag is the entitlement for
		// everyone else. Default OFF → contractFlagBlocks() returns false → no-op.
		if (!authedPolicy.allowed && authedPolicy.block === 'contract_flag') {
			return buildGatedToolResponse(id, toolName, method, options, eventId, accessLogInput);
		}

		const tierQuotaResult = await checkToolDailyRateLimit(principalId, toolName, dailyLimit, options.rateLimitKv, options.quotaCoordinator);
		const tierDailyResetEpoch = Math.ceil(Date.now() / 86_400_000) * 86_400;
		rateHeaders['x-quota-limit'] = String(tierQuotaResult.limit);
		rateHeaders['x-quota-remaining'] = String(tierQuotaResult.remaining);
		rateHeaders['x-quota-reset'] = String(tierDailyResetEpoch);
		rateHeaders['x-quota-tier'] = tier;
		if (!tierQuotaResult.allowed) {
			const message = `Rate limit exceeded. ${tier} tier is limited to ${dailyLimit} requests per day.`;
			const denial = { tier, counter: toolName, limit: dailyLimit, result: tierQuotaResult, message };
			return buildTierQuotaExceededResponse(id, denial, method, options, rateHeaders, eventId, accessLogInput);
		}

		// SQ-494: per-key total across ALL tools, on top of the per-tool cap above. SQ-520:
		// only RECORDED here; it is consumed below, after the session and concurrency gates,
		// so a call those gates reject never burns the total. (The per-tool counter above
		// still runs first: moving it too would change which denial wins when both trip.)
		// Uncapped (Infinity) tiers short-circuit inside checkToolDailyRateLimit with no
		// counter round trip.
		aggregateQuota = { tier, principalId, limit: TIER_AGGREGATE_DAILY_LIMITS[tier] };
	}

	// Per-tier concurrency limiting deferred to after notification check (below).
	let concurrencyPrincipalId: string | undefined;

	if (method !== 'tools/call') {
		const controlPlaneLimited = await buildControlPlaneRateLimitResponse(
			options.ip,
			options.rateLimitKv,
			method,
			options.isAuthenticated,
			id,
			options.accept,
			options.quotaCoordinator,
			options.quotaShardRouting,
		);
		if (controlPlaneLimited) {
			emitRequestAnalytics(options, method, 'error', true);
			return {
				kind: 'response',
				payload: await readJsonRpcErrorPayload(controlPlaneLimited),
				headers: extractProtocolHeaders(controlPlaneLimited),
				httpStatus: controlPlaneLimited.status,
				useErrorEnvelope: true,
				eventId,
			};
		}
	}

	// Authenticated users can call read-only protocol methods without a session (e.g. Smithery
	// proxy-style clients that discover tools via ?api_key= before establishing a session).
	const isSessionlessProtocolMethod =
		options.isAuthenticated &&
		(method === 'tools/list' || method === 'resources/list' || method === 'prompts/list' || method === 'prompts/get' || method === 'ping');

	// Notifications are fire-and-forget at the JSON-RPC layer, but they are still
	// subsequent HTTP requests and therefore must carry a valid assigned session.
	if (options.validateSession && method !== 'initialize' && !isSessionlessProtocolMethod) {
		const sessionError = await validateSessionRequest(
			options.sessionId,
			options.sessionStore,
			id,
			options.sessionErrorMessage ?? 'Bad Request: missing session. Send an initialize request first to create a session.',
		);
		if (sessionError) {
			// An unrecognized or expired caller-supplied ID is never recreated. A random
			// 256-bit value proves possession, not that this server issued it; reviving it
			// would let authenticated callers turn arbitrary IDs into durable KV writes.
			// MCP clients must initialize again and accept the newly assigned session ID.
			emitRequestAnalytics(options, method, 'error', true);
			return {
				kind: 'response',
				payload: sessionError.payload,
				headers: {},
				httpStatus: sessionError.status,
				useErrorEnvelope: true,
				eventId,
			};
		}
	}

	// Per JSON-RPC 2.0, a notification is a request WITHOUT an `id` member. An explicit
	// `id: null` is a valid (if discouraged) id that REQUIRES a response, so it must NOT be
	// collapsed into a notification. We treat a request as a notification when EITHER its
	// method is in the `notifications/*` namespace (which carries no response by definition,
	// even if a client erroneously attaches `id: null`) OR the `id` member is absent entirely.
	const isNotification = isJsonRpcNotification(options.body);
	if (isNotification && method !== 'initialize') {
		emitRequestAnalytics(options, method, 'ok', false);
		return { kind: 'notification' };
	}

	// Per-tier concurrency limiting for tools/call (after notification early-return)
	if (method === 'tools/call') {
		const tier = options.tierAuthResult?.authenticated && options.tierAuthResult.tier ? options.tierAuthResult.tier : ('free' as const);
		const concurrencyLimit = TIER_CONCURRENT_LIMITS[tier];
		concurrencyPrincipalId =
			options.tierAuthResult?.authenticated && options.tierAuthResult.keyHash ? options.tierAuthResult.keyHash : options.ip;

		if (concurrencyLimit !== Infinity) {
			const concurrencyResult = acquireConcurrencySlot(concurrencyPrincipalId, concurrencyLimit);
			if (!concurrencyResult.allowed) {
				const concurrencyHeaders: Record<string, string> = {
					...rateHeaders,
					'retry-after': String(Math.ceil((concurrencyResult.retryAfterMs ?? 1000) / 1000)),
				};
				options.analytics?.emitRateLimitEvent({
					limitType: 'concurrency' as 'minute',
					toolName: 'n/a',
					limit: concurrencyLimit,
					remaining: 0,
					country: options.country,
					authTier: options.authTier ?? tier,
				});
				emitRequestAnalytics(options, method, 'error', true);
				if (accessLogInput) {
					recordMcpAccessLog(options, { ...accessLogInput, rateLimited: true, status: 'unknown' });
				}
				return {
					kind: 'response',
					payload: jsonRpcError(
						id,
						JSON_RPC_ERRORS.RATE_LIMITED,
						`Rate limit exceeded. ${tier} tier is limited to ${concurrencyLimit} concurrent requests.`,
					),
					headers: concurrencyHeaders,
					httpStatus: 429,
					useErrorEnvelope: true,
					eventId,
				};
			}
		} else {
			// owner tier: unlimited, no slot tracking needed
			concurrencyPrincipalId = undefined;
		}
	}

	// SQ-494/SQ-520: the per-key total, consumed only for a call that cleared the session and
	// concurrency gates above. An allowed call keeps the per-tool x-quota-* headers and adds
	// x-quota-total-remaining for capped tiers; a denial reports the total that tripped, and
	// hands back the concurrency slot it was holding.
	if (aggregateQuota) {
		const { tier, principalId, limit: aggregateLimit } = aggregateQuota;
		const aggregateResult = await checkToolDailyRateLimit(
			principalId,
			AGGREGATE_QUOTA_COUNTER,
			aggregateLimit,
			options.rateLimitKv,
			options.quotaCoordinator,
		);
		if (!aggregateResult.allowed) {
			if (concurrencyPrincipalId) releaseConcurrencySlot(concurrencyPrincipalId);
			rateHeaders['x-quota-limit'] = String(aggregateResult.limit);
			rateHeaders['x-quota-remaining'] = String(aggregateResult.remaining);
			const message = `Rate limit exceeded. ${tier} tier is limited to ${aggregateLimit} requests per day across all tools.`;
			const denial = { tier, counter: AGGREGATE_QUOTA_COUNTER, limit: aggregateLimit, result: aggregateResult, message };
			return buildTierQuotaExceededResponse(id, denial, method, options, rateHeaders, eventId, accessLogInput);
		}
		if (Number.isFinite(aggregateLimit)) rateHeaders['x-quota-total-remaining'] = String(aggregateResult.remaining);
	}

	if (options.allowStreaming && method === 'tools/call' && options.responseTransport === 'sse' && acceptsSSE(options.accept)) {
		const dispatchPromise = dispatchMcpMethod({
			id,
			method,
			params,
			ip: options.ip,
			isAuthenticated: options.isAuthenticated,
			rateHeaders,
			serverVersion: options.serverVersion,
			rateLimitKv: options.rateLimitKv,
			quotaCoordinator: options.quotaCoordinator,
			quotaShardRouting: options.quotaShardRouting,
			sessionRateLimitPrincipal:
				options.tierAuthResult?.authenticated && options.tierAuthResult.keyHash
					? `key:${options.tierAuthResult.keyHash.slice(0, 40)}`
					: options.ip,
			sessionStore: options.sessionStore,
			sessionId: options.sessionId,
			scanCache: options.scanCache,
			providerSignaturesUrl: options.providerSignaturesUrl,
			providerSignaturesAllowedHosts: options.providerSignaturesAllowedHosts,
			providerSignaturesSha256: options.providerSignaturesSha256,
			analytics: options.analytics,
			profileAccumulator: options.profileAccumulator,
			profileAccumulatorShardMode: options.profileAccumulatorShardMode,
			waitUntil: options.waitUntil,
			createSessionOnInitialize: options.createSessionOnInitialize,
			existingSessionId: options.existingSessionId,
			scoringConfig: options.scoringConfig,
			cacheTtlSeconds: options.cacheTtlSeconds,
			scanTimeoutMs: options.scanTimeoutMs,
			perCheckTimeoutMs: options.perCheckTimeoutMs,
			webPostureEnabled: options.webPostureEnabled,
			secondaryDohEndpoint: options.secondaryDohEndpoint,
			secondaryDohToken: options.secondaryDohToken,
			country: options.country,
			clientType: options.clientType,
			protocolVersionHeader: options.protocolVersionHeader,
			authTier: options.authTier,
			colo: options.colo,
			region: options.region,
			// PII-gate the AE city blob so ANALYTICS_PII_LEVEL governs Analytics Engine the
			// same way it governs the D1 log: city only at standard+. region/asn stay (coarse).
			city: piiAllows(options.analyticsPiiLevel ?? 'coarse', 'city') ? options.city : undefined,
			asn: options.asn,
			certstream: options.certstream,
			certstreamAuthToken: options.certstreamAuthToken,
			whoisBinding: options.whoisBinding,
			reconBinding: options.reconBinding,
			reconAuthToken: options.reconAuthToken,
			tlsProbeBinding: options.tlsProbeBinding,
			tlsProbeAuthToken: options.tlsProbeAuthToken,
			m365Proxy: options.m365Proxy,
			m365ProxyAuthToken: options.m365ProxyAuthToken,
			m365Identity: options.m365Identity,
			bvWebBenchmark: options.bvWebBenchmark,
			bvWebBenchmarkAuthToken: options.bvWebBenchmarkAuthToken,
			// keyHash remains the security principal for ownership/idempotency. The
			// separately verified m365Identity is the only identity contract accepted
			// by the tenant-read proxy.
			keyHash: options.keyHash,
			analyticsKeyHash: options.analyticsKeyHash,
			infraProbe: options.infraProbe,
			brandAuditDb: options.brandAuditDb,
			brandAuditQueue: options.brandAuditQueue,
			asyncBatchQueue: options.asyncBatchQueue,
			asyncBatchKv: options.asyncBatchKv,
			brandReportsR2: options.brandReportsR2,
			publicOrigin: options.publicOrigin,
			browserRenderer: options.browserRenderer,
			discoveryModeDefault: options.discoveryModeDefault,
			principalId: options.principalId,
			tier0Lookup: options.tier0Lookup,
			tier1Lookup: options.tier1Lookup,
			tier2Lookup: options.tier2Lookup,
		})
			.then((dispatchResult) => {
				if (dispatchResult.kind === 'early-error') {
					return dispatchResult.payload;
				}

				logEvent({
					timestamp: new Date().toISOString(),
					correlationId: options.correlationId,
					requestId: typeof id === 'string' ? id : undefined,
					ipHash: options.ipHash,
					tool: dispatchResult.logTool,
					category: dispatchResult.logCategory,
					result: dispatchResult.logResult,
					details: dispatchResult.logDetails,
					durationMs: Date.now() - options.startTime,
					userAgent: options.userAgent,
					severity: dispatchResult.logCategory === 'error' ? 'error' : 'info',
					domain: getDomainFromParams(params),
				});

				const hasJsonRpcError =
					typeof dispatchResult.payload === 'object' && dispatchResult.payload !== null && 'error' in dispatchResult.payload;
				const errPayload = hasJsonRpcError ? (dispatchResult.payload as { error?: { code?: number; message?: string } }).error : undefined;
				emitRequestAnalytics(options, method, hasJsonRpcError ? 'error' : 'ok', hasJsonRpcError, errPayload?.code, errPayload?.message);
				recordMcpToolErrorIfUnknownTool(options, method, dispatchResult.payload);
				if (accessLogInput) {
					recordMcpAccessLog(options, { ...accessLogInput, rateLimited: false, status: hasJsonRpcError ? 'error' : 'pass' });
				}
				return dispatchResult.payload;
			})
			.finally(() => {
				if (concurrencyPrincipalId) releaseConcurrencySlot(concurrencyPrincipalId);
			});

		return {
			kind: 'response',
			payload: null,
			headers: {
				...rateHeaders,
			},
			httpStatus: 200,
			useErrorEnvelope: false,
			eventId,
			streamOperation: dispatchPromise,
		};
	}

	try {
		const dispatchResult = await dispatchMcpMethod({
			id,
			method,
			params,
			ip: options.ip,
			isAuthenticated: options.isAuthenticated,
			rateHeaders,
			serverVersion: options.serverVersion,
			rateLimitKv: options.rateLimitKv,
			quotaCoordinator: options.quotaCoordinator,
			quotaShardRouting: options.quotaShardRouting,
			sessionRateLimitPrincipal:
				options.tierAuthResult?.authenticated && options.tierAuthResult.keyHash
					? `key:${options.tierAuthResult.keyHash.slice(0, 40)}`
					: options.ip,
			sessionStore: options.sessionStore,
			sessionId: options.sessionId,
			scanCache: options.scanCache,
			providerSignaturesUrl: options.providerSignaturesUrl,
			providerSignaturesAllowedHosts: options.providerSignaturesAllowedHosts,
			providerSignaturesSha256: options.providerSignaturesSha256,
			analytics: options.analytics,
			profileAccumulator: options.profileAccumulator,
			profileAccumulatorShardMode: options.profileAccumulatorShardMode,
			waitUntil: options.waitUntil,
			createSessionOnInitialize: options.createSessionOnInitialize,
			existingSessionId: options.existingSessionId,
			scoringConfig: options.scoringConfig,
			cacheTtlSeconds: options.cacheTtlSeconds,
			scanTimeoutMs: options.scanTimeoutMs,
			perCheckTimeoutMs: options.perCheckTimeoutMs,
			webPostureEnabled: options.webPostureEnabled,
			secondaryDohEndpoint: options.secondaryDohEndpoint,
			secondaryDohToken: options.secondaryDohToken,
			country: options.country,
			clientType: options.clientType,
			protocolVersionHeader: options.protocolVersionHeader,
			authTier: options.authTier,
			colo: options.colo,
			region: options.region,
			// PII-gate the AE city blob so ANALYTICS_PII_LEVEL governs Analytics Engine the
			// same way it governs the D1 log: city only at standard+. region/asn stay (coarse).
			city: piiAllows(options.analyticsPiiLevel ?? 'coarse', 'city') ? options.city : undefined,
			asn: options.asn,
			certstream: options.certstream,
			certstreamAuthToken: options.certstreamAuthToken,
			whoisBinding: options.whoisBinding,
			reconBinding: options.reconBinding,
			reconAuthToken: options.reconAuthToken,
			tlsProbeBinding: options.tlsProbeBinding,
			tlsProbeAuthToken: options.tlsProbeAuthToken,
			m365Proxy: options.m365Proxy,
			m365ProxyAuthToken: options.m365ProxyAuthToken,
			m365Identity: options.m365Identity,
			bvWebBenchmark: options.bvWebBenchmark,
			bvWebBenchmarkAuthToken: options.bvWebBenchmarkAuthToken,
			// keyHash remains the security principal for ownership/idempotency. The
			// separately verified m365Identity is the only identity contract accepted
			// by the tenant-read proxy.
			keyHash: options.keyHash,
			analyticsKeyHash: options.analyticsKeyHash,
			infraProbe: options.infraProbe,
			brandAuditDb: options.brandAuditDb,
			brandAuditQueue: options.brandAuditQueue,
			asyncBatchQueue: options.asyncBatchQueue,
			asyncBatchKv: options.asyncBatchKv,
			brandReportsR2: options.brandReportsR2,
			publicOrigin: options.publicOrigin,
			browserRenderer: options.browserRenderer,
			discoveryModeDefault: options.discoveryModeDefault,
			principalId: options.principalId,
			tier0Lookup: options.tier0Lookup,
			tier1Lookup: options.tier1Lookup,
			tier2Lookup: options.tier2Lookup,
		});

		if (dispatchResult.kind === 'early-error') {
			return {
				kind: 'response',
				payload: dispatchResult.payload,
				headers: dispatchResult.headers,
				httpStatus: dispatchResult.status,
				useErrorEnvelope: true,
				eventId,
			};
		}

		const headers: Record<string, string> = {};
		if (dispatchResult.newSessionId) {
			headers['mcp-session-id'] = dispatchResult.newSessionId;
		}
		Object.assign(headers, rateHeaders);

		logEvent({
			timestamp: new Date().toISOString(),
			correlationId: options.correlationId,
			requestId: typeof id === 'string' ? id : undefined,
			ipHash: options.ipHash,
			tool: dispatchResult.logTool,
			category: dispatchResult.logCategory,
			result: dispatchResult.logResult,
			details: dispatchResult.logDetails,
			durationMs: Date.now() - options.startTime,
			userAgent: options.userAgent,
			severity: dispatchResult.logCategory === 'error' ? 'error' : 'info',
			domain: getDomainFromParams(params),
		});

		const hasJsonRpcError =
			typeof dispatchResult.payload === 'object' && dispatchResult.payload !== null && 'error' in dispatchResult.payload;
		const errPayload = hasJsonRpcError ? (dispatchResult.payload as { error?: { code?: number; message?: string } }).error : undefined;
		emitRequestAnalytics(options, method, hasJsonRpcError ? 'error' : 'ok', hasJsonRpcError, errPayload?.code, errPayload?.message);
		recordMcpToolErrorIfUnknownTool(options, method, dispatchResult.payload);
		if (accessLogInput) {
			recordMcpAccessLog(options, { ...accessLogInput, rateLimited: false, status: hasJsonRpcError ? 'error' : 'pass' });
		}

		return {
			kind: 'response',
			payload: dispatchResult.payload,
			headers,
			httpStatus: 200,
			useErrorEnvelope: false,
			eventId,
		};
	} catch (err) {
		if (err instanceof JsonRpcClientError) {
			emitRequestAnalytics(options, method, 'error', true, err.code, err.message);
			return {
				kind: 'response',
				payload: jsonRpcError(id, err.code, sanitizeErrorMessage(err, 'Invalid params')),
				headers: {},
				httpStatus: 400,
				useErrorEnvelope: true,
				eventId,
			};
		}
		emitRequestAnalytics(options, method, 'error', true);
		logError(err instanceof Error ? err : String(err), {
			severity: 'error',
			correlationId: options.correlationId,
			ipHash: options.ipHash,
			requestId: typeof options.body?.id === 'string' ? options.body.id : undefined,
			tool: typeof options.body?.method === 'string' ? options.body.method : undefined,
			details: {
				params:
					options.body?.params && typeof options.body.params === 'object'
						? { keys: Object.keys(options.body.params).sort().slice(0, 25) }
						: undefined,
			},
			durationMs: Date.now() - options.startTime,
			userAgent: options.userAgent,
		});
		return {
			kind: 'response',
			payload: jsonRpcError(id, JSON_RPC_ERRORS.INTERNAL_ERROR, sanitizeErrorMessage(err, 'Internal server error')),
			headers: {},
			httpStatus: 500,
			useErrorEnvelope: true,
			eventId,
		};
	} finally {
		if (concurrencyPrincipalId) releaseConcurrencySlot(concurrencyPrincipalId);
	}
}
