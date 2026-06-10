// SPDX-License-Identifier: BUSL-1.1

import {
	checkRateLimit,
	checkToolDailyRateLimit,
	checkGlobalDailyLimit,
	checkIpDailyLimit,
	checkDistinctDomainDailyLimit,
	acquireConcurrencySlot,
	releaseConcurrencySlot,
} from '../lib/rate-limiter';
import { fireAndForget, getLogger, logEvent, logError } from '../lib/log';
import { jsonRpcError, JSON_RPC_ERRORS, isJsonRpcNotification, sanitizeErrorMessage } from '../lib/json-rpc';
import { buildControlPlaneRateLimitResponse, validateSessionRequest } from './route-gates';
import {
	FREE_TOOL_DAILY_LIMITS,
	FREE_IP_DAILY_LIMIT,
	FREE_DISTINCT_DOMAIN_DAILY_LIMIT,
	FORCE_REFRESH_DAILY_LIMIT,
	GLOBAL_DAILY_TOOL_LIMIT,
	TIER_DAILY_LIMITS,
	TIER_TOOL_DAILY_LIMITS,
	TIER_CONCURRENT_LIMITS,
	isGatedPaidOnlyTool,
	isAuthRequiredTool,
	UPGRADE_URL,
} from '../lib/config';
import { normalizeToolName } from '../handlers/tool-args';
import { acceptsSSE } from '../lib/sse';
import { dispatchMcpMethod } from './dispatch';
import { validateJsonRpcRequest } from './request';
import { checkSessionCreateRateLimit, reviveSession } from '../lib/session';
import type { JsonRpcRequest } from '../lib/json-rpc';
import type { AnalyticsClient } from '../lib/analytics';
import { hashDomain } from '../lib/analytics';
import { classifyError as classifyFuzzError } from '../lib/fuzzing-detector';
import { recordEvent as recordFuzzCounter } from '../lib/fuzzing-counter';

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
	ip: string;
	isAuthenticated: boolean;
	tierAuthResult?: import('../lib/tier-auth').TierAuthResult;
	userAgent?: string;
	sessionId?: string;
	validateSession: boolean;
	sessionErrorMessage?: string;
	createSessionOnInitialize?: boolean;
	existingSessionId?: string;
	serverVersion: string;
	rateLimitKv?: KVNamespace;
	quotaCoordinator?: DurableObjectNamespace;
	sessionStore?: KVNamespace;
	scanCache?: KVNamespace;
	providerSignaturesUrl?: string;
	providerSignaturesAllowedHosts?: string;
	providerSignaturesSha256?: string;
	analytics?: AnalyticsClient;
	profileAccumulator?: DurableObjectNamespace;
	waitUntil?: (promise: Promise<unknown>) => void;
	scoringConfig?: import('@blackveil/dns-checks/scoring').ScoringConfig;
	cacheTtlSeconds?: number;
	scanTimeoutMs?: number;
	perCheckTimeoutMs?: number;
	/** Custom secondary DoH endpoint URL (bv-dns). */
	secondaryDohEndpoint?: string;
	/** Auth token for custom secondary DoH. */
	secondaryDohToken?: string;
	country?: string;
	clientType?: string;
	/** Raw `MCP-Protocol-Version` request header (threaded to dispatch for STRUCTURED_RESULT comment trimming). */
	protocolVersionHeader?: string;
	authTier?: string;
	sessionHash?: string;
	/** Truncated key hash for analytics (first 16 chars of SHA-256). */
	keyHash?: string;
	/** FNV-1a hash of cf-connecting-ip (`i_` prefix) for per-IP analytics filtering. */
	ipHash?: string;
	/** D1 binding for privacy-preserving MCP access logs. */
	intelligenceDb?: D1Database;
	/** Base64-encoded AES-GCM key for encrypted abuse-investigation IP evidence. */
	ipEncryptionKey?: string;
	ipEncryptionKeyVersion?: string;
	certstream?: { fetch: typeof fetch };
	certstreamAuthToken?: string;
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
	/** Bearer token (BV_WEB_INTERNAL_KEY) forwarded to bv-web's internal M365 endpoints. */
	m365ProxyAuthToken?: string;
	infraProbe?: { fetch: typeof fetch };
	/** D1 binding for the brand-audit DB. v2.21.2+. */
	brandAuditDb?: D1Database;
	/** Cloudflare Queue producer for brand-audit batch path. v2.21.2+. */
	brandAuditQueue?: { send(message: unknown, options?: { contentType?: 'json' }): Promise<void> };
	/** R2 bucket binding for brand-audit PDF reports. v2.21.2+. */
	brandReportsR2?: R2Bucket;
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
}

function getDomainFromParams(params: Record<string, unknown> | undefined): string | undefined {
	return typeof params === 'object' && params && 'domain' in params ? String(params.domain) : undefined;
}

function maskIp(ip: string): string {
	const parts = ip.split('.');
	if (parts.length === 4 && parts.every((part) => /^\d{1,3}$/.test(part))) {
		return `${parts[0]}.${parts[1]}.${parts[2]}.xxx`;
	}
	if (ip === 'unknown') return 'unknown';
	return 'masked';
}

function extractAccessLogDomain(args: Record<string, unknown> | undefined): string | undefined {
	if (!args) return undefined;
	if (typeof args.domain === 'string' && args.domain.length > 0) return args.domain;
	if (Array.isArray(args.domains)) {
		return args.domains.find((value): value is string => typeof value === 'string' && value.length > 0);
	}
	return undefined;
}

function getToolCallLogInput(
	method: string,
	params: Record<string, unknown> | undefined,
): { toolName: string; domain: string } | undefined {
	if (method !== 'tools/call') return undefined;
	const toolNameRaw = params && typeof params === 'object' && 'name' in params ? params.name : undefined;
	const argsRaw = params && typeof params === 'object' && 'arguments' in params ? params.arguments : undefined;
	const args = argsRaw && typeof argsRaw === 'object' && !Array.isArray(argsRaw) ? (argsRaw as Record<string, unknown>) : undefined;
	const domain = extractAccessLogDomain(args);
	if (typeof toolNameRaw !== 'string' || !domain) return undefined;
	return { toolName: normalizeToolName(toolNameRaw), domain };
}

function base64ToBytes(value: string): Uint8Array {
	const binary = atob(value);
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i += 1) {
		bytes[i] = binary.charCodeAt(i);
	}
	return bytes;
}

function bytesToBase64(bytes: Uint8Array): string {
	let binary = '';
	for (const byte of bytes) {
		binary += String.fromCharCode(byte);
	}
	return btoa(binary);
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
	return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

// Module-scoped cache so a mis-configured key logs once, then skips silently
// instead of throwing on every request. Map key = the base64 env value, so a
// later config fix (rotated key) gets re-evaluated automatically.
const encryptionKeyValidationCache = new Map<string, { valid: boolean }>();

function validateEncryptionKeyOnce(keyBase64: string): boolean {
	const cached = encryptionKeyValidationCache.get(keyBase64);
	if (cached) return cached.valid;
	let valid = false;
	try {
		valid = base64ToBytes(keyBase64).byteLength === 32;
	} catch {
		valid = false;
	}
	encryptionKeyValidationCache.set(keyBase64, { valid });
	if (!valid) {
		// Surface once at error level — operators need to see this in alerting.
		// Subsequent requests hit the cache and skip without re-logging.
		logError(
			'Invalid MCP_ACCESS_LOG_IP_ENCRYPTION_KEY: must be 32 bytes (base64-decoded). Access-log IP ciphertext disabled until fixed.',
			{
				category: 'config',
				details: {
					keyBytes: (() => {
						try {
							return base64ToBytes(keyBase64).byteLength;
						} catch {
							return 'unparseable_base64';
						}
					})(),
				},
			},
		);
	}
	return valid;
}

async function encryptIpEvidence(ip: string, keyBase64: string | undefined): Promise<string | null> {
	if (!keyBase64 || ip === 'unknown') return null;
	if (!validateEncryptionKeyOnce(keyBase64)) return null;
	const rawKey = base64ToBytes(keyBase64);
	const key = await crypto.subtle.importKey('raw', toArrayBuffer(rawKey), { name: 'AES-GCM' }, false, ['encrypt']);
	const iv = crypto.getRandomValues(new Uint8Array(12));
	const plaintext = new TextEncoder().encode(ip);
	const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: toArrayBuffer(iv) }, key, toArrayBuffer(plaintext)));
	return `v1:${bytesToBase64(iv)}:${bytesToBase64(ciphertext)}`;
}

function recordMcpAccessLog(options: ExecuteMcpRequestOptions, input: { toolName: string; domain: string; rateLimited: boolean }): void {
	if (!options.intelligenceDb) return;
	const logger = getLogger();
	const work = async () => {
		const ipCiphertext = await encryptIpEvidence(options.ip, options.ipEncryptionKey);
		await options
			.intelligenceDb!.prepare(
				`INSERT INTO mcp_access_log
				 (ip_hash, ip_masked, tool_name, domain, country, user_agent, response_ms, rate_limited, ip_ciphertext, ip_key_version)
				 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			)
			.bind(
				options.ipHash ?? 'unknown',
				maskIp(options.ip),
				input.toolName,
				input.domain,
				options.country ?? null,
				options.userAgent ?? null,
				Math.max(0, Date.now() - options.startTime),
				input.rateLimited ? 1 : 0,
				ipCiphertext,
				ipCiphertext ? (options.ipEncryptionKeyVersion ?? 'v1') : null,
			)
			.run();
	};
	const loggedWork = fireAndForget(work, logger, 'mcp_access_log_insert');
	options.waitUntil?.(loggedWork);
}

function extractHeaders(response: Response): Record<string, string> {
	const headers: Record<string, string> = {};
	response.headers.forEach((value, key) => {
		const lower = key.toLowerCase();
		if (lower === 'content-type' || lower === 'cache-control' || lower === 'content-length') return;
		headers[key] = value;
	});
	return headers;
}

async function readJsonRpcPayload(response: Response): Promise<ReturnType<typeof jsonRpcError>> {
	const contentType = response.headers.get('content-type')?.toLowerCase() ?? '';
	if (contentType.includes('text/event-stream')) {
		const text = await response.text();
		const dataLine = text.split('\n').find((line) => line.startsWith('data: '));
		if (!dataLine) {
			return jsonRpcError(null, JSON_RPC_ERRORS.INTERNAL_ERROR, 'Internal server error');
		}
		return JSON.parse(dataLine.slice('data: '.length)) as ReturnType<typeof jsonRpcError>;
	}

	return (await response.json()) as ReturnType<typeof jsonRpcError>;
}

function emitRequestAnalytics(
	options: ExecuteMcpRequestOptions,
	method: string,
	status: 'ok' | 'error',
	hasJsonRpcError: boolean,
	jsonRpcErrorCode?: number,
	jsonRpcErrorDescription?: string,
): void {
	options.analytics?.emitRequestEvent({
		method,
		status,
		durationMs: Date.now() - options.startTime,
		isAuthenticated: options.isAuthenticated,
		hasJsonRpcError,
		jsonRpcErrorCode,
		transport: options.responseTransport,
		country: options.country,
		clientType: options.clientType as import('../lib/client-detection').McpClientType,
		authTier: options.authTier,
		sessionHash: options.sessionHash,
		keyHash: options.keyHash,
		ipHash: options.ipHash,
	});

	// Fuzzing-detection: record an event if the error matches a known fuzz pattern.
	// Best-effort and non-blocking — see docs/plans/2026-05-07-fuzzing-detection-tdd-plan.md.
	if (status === 'error' && options.rateLimitKv && jsonRpcErrorCode !== undefined) {
		void recordFuzzEvent(options, method, jsonRpcErrorCode, jsonRpcErrorDescription);
	}
}

async function recordFuzzEvent(
	options: ExecuteMcpRequestOptions,
	method: string,
	jsonRpcErrorCode: number,
	jsonRpcErrorDescription: string | undefined,
): Promise<void> {
	const dispatchPath = method === 'tools/call' ? 'tools/call' : 'dispatch';
	const kind = classifyFuzzError({
		jsonRpcCode: jsonRpcErrorCode,
		dispatchPath,
		description: jsonRpcErrorDescription,
	});
	if (!kind) return;
	// Principal selection: keyHash for authenticated, ipHash for anonymous.
	const principalId = options.keyHash ?? options.ipHash;
	if (!principalId) return;
	const recordPromise = recordFuzzCounter(options.rateLimitKv!, principalId, kind, Math.floor(Date.now() / 1000));
	if (options.waitUntil) options.waitUntil(recordPromise);
	else await recordPromise.catch(() => undefined);
}

/**
 * MCP `tools/call` errors come back as `{ result: { isError: true, content: [...] } }`,
 * not as JSON-RPC `-32601`. We detect the unknown-tool flavour by inspecting the
 * content text and feed it into the same fuzz counter as JSON-RPC -32601s.
 */
function recordMcpToolErrorIfUnknownTool(options: ExecuteMcpRequestOptions, method: string, payload: unknown): void {
	if (method !== 'tools/call') return;
	if (!options.rateLimitKv) return;
	const principalId = options.keyHash ?? options.ipHash;
	if (!principalId) return;
	const result = (payload as { result?: { isError?: boolean; content?: { text?: string }[] } })?.result;
	if (!result?.isError) return;
	const text = result.content?.[0]?.text ?? '';
	if (!text.includes('Unknown tool:')) return;
	const recordPromise = recordFuzzCounter(options.rateLimitKv, principalId, 'unknown_tool', Math.floor(Date.now() / 1000));
	if (options.waitUntil) options.waitUntil(recordPromise);
	else void recordPromise.catch(() => undefined);
}

/**
 * Reject an UNAUTHENTICATED tools/call for an auth-required tool (identity_secops
 * M365 reads) before dispatch. Returns HTTP 401 with the JSON-RPC UNAUTHORIZED
 * code and an allowlisted ("Invalid") message prefix so sanitizeErrorMessage
 * passes it through unchanged. Prevents an anon → bv-web-internal trust-boundary
 * breach (the proxy would otherwise carry the trusted internal bearer).
 */
function buildAuthRequiredResponse(
	id: JsonRpcRequest['id'],
	toolName: string,
	method: string,
	options: ExecuteMcpRequestOptions,
	eventId: string | undefined,
	accessLogInput: { toolName: string; domain: string } | undefined,
): Extract<ProcessedRequestResult, { kind: 'response' }> {
	options.analytics?.emitRateLimitEvent({
		limitType: 'gated_tool',
		toolName,
		limit: 0,
		remaining: 0,
		country: options.country,
		authTier: options.authTier ?? 'anon',
	});
	emitRequestAnalytics(options, method, 'error', true);
	if (accessLogInput) {
		recordMcpAccessLog(options, { ...accessLogInput, rateLimited: true });
	}
	return {
		kind: 'response',
		payload: jsonRpcError(
			id,
			JSON_RPC_ERRORS.UNAUTHORIZED,
			`Invalid request: ${toolName} requires authentication. Provide a valid API key (Authorization: Bearer …).`,
		),
		headers: {},
		httpStatus: 401,
		useErrorEnvelope: true,
		eventId,
	};
}

function buildGatedToolResponse(
	id: JsonRpcRequest['id'],
	toolName: string,
	method: string,
	options: ExecuteMcpRequestOptions,
	eventId: string | undefined,
	accessLogInput: { toolName: string; domain: string } | undefined,
): Extract<ProcessedRequestResult, { kind: 'response' }> {
	options.analytics?.emitRateLimitEvent({
		limitType: 'gated_tool',
		toolName,
		limit: 0,
		remaining: 0,
		country: options.country,
		authTier: options.authTier ?? 'anon',
	});
	emitRequestAnalytics(options, method, 'error', true);
	if (accessLogInput) {
		recordMcpAccessLog(options, { ...accessLogInput, rateLimited: true });
	}
	return {
		kind: 'response',
		payload: jsonRpcError(
			id,
			JSON_RPC_ERRORS.UPGRADE_REQUIRED,
			`Upgrade required: ${toolName} requires a paid plan (developer tier or higher). See ${UPGRADE_URL}`,
		),
		headers: {},
		httpStatus: 403,
		useErrorEnvelope: true,
		eventId,
	};
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

	let rateHeaders: Record<string, string> = {};
	if (!options.isAuthenticated && method === 'tools/call') {
		const globalResult = await checkGlobalDailyLimit(GLOBAL_DAILY_TOOL_LIMIT, options.rateLimitKv, options.quotaCoordinator);
		if (!globalResult.allowed) {
			const globalHeaders: Record<string, string> = {};
			if (globalResult.retryAfterMs !== undefined) {
				globalHeaders['retry-after'] = String(Math.ceil(globalResult.retryAfterMs / 1000));
			}
			options.analytics?.emitRateLimitEvent({
				limitType: 'daily_global',
				toolName: 'n/a',
				limit: GLOBAL_DAILY_TOOL_LIMIT,
				remaining: 0,
				country: options.country,
				authTier: options.authTier,
			});
			emitRequestAnalytics(options, method, 'error', true);
			if (accessLogInput) {
				recordMcpAccessLog(options, { ...accessLogInput, rateLimited: true });
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
				recordMcpAccessLog(options, { ...accessLogInput, rateLimited: true });
			}
			return {
				kind: 'response',
				payload: jsonRpcError(
					id,
					JSON_RPC_ERRORS.RATE_LIMITED,
					'Rate limit exceeded. Daily request limit reached for this IP. Please try again tomorrow.',
				),
				headers: ipDailyHeaders,
				httpStatus: 429,
				useErrorEnvelope: true,
				eventId,
			};
		}

		const rateResult = await checkRateLimit(options.ip, options.rateLimitKv, options.quotaCoordinator);
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
				recordMcpAccessLog(options, { ...accessLogInput, rateLimited: true });
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

		const toolNameRaw =
			typeof params === 'object' && params !== null && 'name' in params ? (params as Record<string, unknown>).name : undefined;
		const toolName = typeof toolNameRaw === 'string' ? normalizeToolName(toolNameRaw) : '';
		const toolDailyLimit = toolName ? FREE_TOOL_DAILY_LIMITS[toolName] : undefined;
		// Auth-required tools (identity_secops M365 reads) must NEVER be reached by an
		// unauthenticated caller: dispatch would forward to bv-web's internal M365 proxy
		// carrying the trusted internal bearer with keyHash:undefined. Reject before
		// dispatch with HTTP 401 + an allowlisted ("Invalid") message prefix.
		if (toolName && isAuthRequiredTool(toolName)) {
			return buildAuthRequiredResponse(id, toolName, method, options, eventId, accessLogInput);
		}
		if (toolName && isGatedPaidOnlyTool(toolName)) {
			return buildGatedToolResponse(id, toolName, method, options, eventId, accessLogInput);
		}
		if (toolDailyLimit !== undefined) {
			const toolQuotaResult = await checkToolDailyRateLimit(
				options.ip,
				toolName,
				toolDailyLimit,
				options.rateLimitKv,
				options.quotaCoordinator,
			);
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
					recordMcpAccessLog(options, { ...accessLogInput, rateLimited: true });
				}
				return {
					kind: 'response',
					payload: jsonRpcError(
						id,
						JSON_RPC_ERRORS.RATE_LIMITED,
						`Rate limit exceeded. ${toolName} is limited to ${toolDailyLimit} requests per day for free tier users.`,
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
			typeof params === 'object' && params !== null && 'arguments' in params
				? (params as Record<string, unknown>).arguments
				: undefined;
		const forceRefresh =
			argsRaw !== null &&
			typeof argsRaw === 'object' &&
			!Array.isArray(argsRaw) &&
			(argsRaw as Record<string, unknown>).force_refresh === true;

		if (forceRefresh) {
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
					recordMcpAccessLog(options, { ...accessLogInput, rateLimited: true });
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
		const args =
			argsRaw && typeof argsRaw === 'object' && !Array.isArray(argsRaw) ? (argsRaw as Record<string, unknown>) : undefined;
		const ddcDomain = extractAccessLogDomain(args);
		if (ddcDomain) {
			// The domain slot is recorded before dispatch/validation intentionally: the cap throttles
			// distinct-domain enumeration, not just successful scans, so invalid calls still consume a slot.
			const ddcResult = await checkDistinctDomainDailyLimit(
				options.ip,
				hashDomain(ddcDomain),
				FREE_DISTINCT_DOMAIN_DAILY_LIMIT,
				options.rateLimitKv,
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
					recordMcpAccessLog(options, { ...accessLogInput, rateLimited: true });
				}
				return {
					kind: 'response',
					payload: jsonRpcError(
						id,
						JSON_RPC_ERRORS.RATE_LIMITED,
						`Rate limit exceeded. Free tier is limited to ${FREE_DISTINCT_DOMAIN_DAILY_LIMIT} distinct domains per day. Authenticate for a higher limit.`,
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
		const dailyLimit = TIER_TOOL_DAILY_LIMITS[tier]?.[toolName] ?? TIER_DAILY_LIMITS[tier];

		if (dailyLimit === 0 && isGatedPaidOnlyTool(toolName)) {
			return buildGatedToolResponse(id, toolName, method, options, eventId, accessLogInput);
		}

		const tierQuotaResult = await checkToolDailyRateLimit(principalId, toolName, dailyLimit, options.rateLimitKv, options.quotaCoordinator);
		const tierDailyResetEpoch = Math.ceil(Date.now() / 86_400_000) * 86_400;
		rateHeaders['x-quota-limit'] = String(tierQuotaResult.limit);
		rateHeaders['x-quota-remaining'] = String(tierQuotaResult.remaining);
		rateHeaders['x-quota-reset'] = String(tierDailyResetEpoch);
		rateHeaders['x-quota-tier'] = tier;
		if (!tierQuotaResult.allowed) {
			if (tierQuotaResult.retryAfterMs !== undefined) {
				rateHeaders['retry-after'] = String(Math.ceil(tierQuotaResult.retryAfterMs / 1000));
			}
			options.analytics?.emitRateLimitEvent({
				limitType: 'daily_tool',
				toolName,
				limit: dailyLimit,
				remaining: 0,
				country: options.country,
				authTier: tier,
			});
			emitRequestAnalytics(options, method, 'error', true);
			if (accessLogInput) {
				recordMcpAccessLog(options, { ...accessLogInput, rateLimited: true });
			}
			return {
				kind: 'response',
				payload: jsonRpcError(
					id,
					JSON_RPC_ERRORS.RATE_LIMITED,
					`Rate limit exceeded. ${tier} tier is limited to ${dailyLimit} requests per day.`,
				),
				headers: rateHeaders,
				httpStatus: 429,
				useErrorEnvelope: true,
				eventId,
			};
		}
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
		);
		if (controlPlaneLimited) {
			emitRequestAnalytics(options, method, 'error', true);
			return {
				kind: 'response',
				payload: await readJsonRpcPayload(controlPlaneLimited),
				headers: extractHeaders(controlPlaneLimited),
				httpStatus: controlPlaneLimited.status,
				useErrorEnvelope: true,
				eventId,
			};
		}
	}

	let sessionRevived = false;

	// Authenticated users can call read-only protocol methods without a session (e.g. Smithery
	// proxy-style clients that discover tools via ?api_key= before establishing a session).
	const isSessionlessProtocolMethod =
		options.isAuthenticated &&
		(method === 'tools/list' || method === 'resources/list' || method === 'prompts/list' || method === 'prompts/get' || method === 'ping');

	if (options.validateSession && method !== 'initialize' && !method.startsWith('notifications/') && !isSessionlessProtocolMethod) {
		const sessionError = await validateSessionRequest(
			options.sessionId,
			options.sessionStore,
			id,
			options.sessionErrorMessage ?? 'Bad Request: missing session. Send an initialize request first to create a session.',
		);
		if (sessionError) {
			const canRecoverExpiredSession = sessionError.status === 404 && typeof options.sessionId === 'string' && options.sessionId.length > 0;

			if (canRecoverExpiredSession) {
				let recoveryAllowed = true;
				if (!options.isAuthenticated) {
					const createGate = await checkSessionCreateRateLimit(options.ip, options.rateLimitKv, options.quotaCoordinator);
					recoveryAllowed = createGate.allowed;
				}

				if (recoveryAllowed) {
					sessionRevived = await reviveSession(options.sessionId!, options.sessionStore);
					if (sessionRevived) {
						options.analytics?.emitSessionEvent({
							action: 'revived',
							method,
							country: options.country,
							clientType: options.clientType as import('../lib/client-detection').McpClientType,
							authTier: options.authTier,
							keyHash: options.keyHash,
						});
						logEvent({
							timestamp: new Date().toISOString(),
							category: 'session',
							result: 'recovered',
							ipHash: options.ipHash,
							details: { method, clientType: options.clientType },
						});
					}
				}
			}

			if (sessionRevived) {
				// Continue request execution with the revived session to prevent stale-session
				// loops in clients (e.g. mcp-remote) that do not learn new session IDs from
				// response headers and cannot auto-reinitialize after a 404.
			} else {
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
					recordMcpAccessLog(options, { ...accessLogInput, rateLimited: true });
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
			sessionStore: options.sessionStore,
			scanCache: options.scanCache,
			providerSignaturesUrl: options.providerSignaturesUrl,
			providerSignaturesAllowedHosts: options.providerSignaturesAllowedHosts,
			providerSignaturesSha256: options.providerSignaturesSha256,
			analytics: options.analytics,
			profileAccumulator: options.profileAccumulator,
			waitUntil: options.waitUntil,
			createSessionOnInitialize: options.createSessionOnInitialize,
			existingSessionId: options.existingSessionId,
			scoringConfig: options.scoringConfig,
			cacheTtlSeconds: options.cacheTtlSeconds,
			scanTimeoutMs: options.scanTimeoutMs,
			perCheckTimeoutMs: options.perCheckTimeoutMs,
			secondaryDohEndpoint: options.secondaryDohEndpoint,
			secondaryDohToken: options.secondaryDohToken,
			country: options.country,
			clientType: options.clientType,
			protocolVersionHeader: options.protocolVersionHeader,
			authTier: options.authTier,
			certstream: options.certstream,
			certstreamAuthToken: options.certstreamAuthToken,
			whoisBinding: options.whoisBinding,
			reconBinding: options.reconBinding,
			reconAuthToken: options.reconAuthToken,
			tlsProbeBinding: options.tlsProbeBinding,
			tlsProbeAuthToken: options.tlsProbeAuthToken,
			m365Proxy: options.m365Proxy,
			m365ProxyAuthToken: options.m365ProxyAuthToken,
			infraProbe: options.infraProbe,
			brandAuditDb: options.brandAuditDb,
			brandAuditQueue: options.brandAuditQueue,
			brandReportsR2: options.brandReportsR2,
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
					recordMcpAccessLog(options, { ...accessLogInput, rateLimited: false });
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
			sessionStore: options.sessionStore,
			scanCache: options.scanCache,
			providerSignaturesUrl: options.providerSignaturesUrl,
			providerSignaturesAllowedHosts: options.providerSignaturesAllowedHosts,
			providerSignaturesSha256: options.providerSignaturesSha256,
			analytics: options.analytics,
			profileAccumulator: options.profileAccumulator,
			waitUntil: options.waitUntil,
			createSessionOnInitialize: options.createSessionOnInitialize,
			existingSessionId: options.existingSessionId,
			scoringConfig: options.scoringConfig,
			cacheTtlSeconds: options.cacheTtlSeconds,
			scanTimeoutMs: options.scanTimeoutMs,
			perCheckTimeoutMs: options.perCheckTimeoutMs,
			secondaryDohEndpoint: options.secondaryDohEndpoint,
			secondaryDohToken: options.secondaryDohToken,
			country: options.country,
			clientType: options.clientType,
			protocolVersionHeader: options.protocolVersionHeader,
			authTier: options.authTier,
			certstream: options.certstream,
			certstreamAuthToken: options.certstreamAuthToken,
			whoisBinding: options.whoisBinding,
			reconBinding: options.reconBinding,
			reconAuthToken: options.reconAuthToken,
			tlsProbeBinding: options.tlsProbeBinding,
			tlsProbeAuthToken: options.tlsProbeAuthToken,
			m365Proxy: options.m365Proxy,
			m365ProxyAuthToken: options.m365ProxyAuthToken,
			infraProbe: options.infraProbe,
			brandAuditDb: options.brandAuditDb,
			brandAuditQueue: options.brandAuditQueue,
			brandReportsR2: options.brandReportsR2,
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
			recordMcpAccessLog(options, { ...accessLogInput, rateLimited: false });
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
		emitRequestAnalytics(options, method, 'error', true);
		logError(err instanceof Error ? err : String(err), {
			severity: 'error',
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
