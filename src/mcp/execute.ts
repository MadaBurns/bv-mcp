// SPDX-License-Identifier: BUSL-1.1

import {
	checkToolDailyRateLimit,
	checkGlobalDailyLimit,
	checkIpScopedQuotaBatch,
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
	isInternalOnlyTool,
	UPGRADE_URL,
} from '../lib/config';
import { jsonRpcSuccess } from '../lib/json-rpc';
import { mcpError } from '../handlers/tool-formatters';
import { normalizeToolName } from '../handlers/tool-args';
import { shardIndexForKey, isQuotaShardSaltMissing } from '../lib/quota-coordinator';
import { acceptsSSE } from '../lib/sse';
import { dispatchMcpMethod } from './dispatch';
import { validateJsonRpcRequest } from './request';
import { checkSessionCreateRateLimit, reviveSession } from '../lib/session';
import type { JsonRpcRequest } from '../lib/json-rpc';
import type { AnalyticsClient } from '../lib/analytics';
import { hashDomain } from '../lib/analytics';
import { classifyError as classifyFuzzError } from '../lib/fuzzing-detector';
import { recordEvent as recordFuzzCounter } from '../lib/fuzzing-counter';
import { piiAllows } from '../lib/analytics-pii';
import { buildAccessLogEvent, type AccessLogEvent } from '../lib/access-log-event';

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
	userAgent?: string;
	sessionId?: string;
	validateSession: boolean;
	sessionErrorMessage?: string;
	createSessionOnInitialize?: boolean;
	existingSessionId?: string;
	serverVersion: string;
	rateLimitKv?: KVNamespace;
	quotaCoordinator?: DurableObjectNamespace;
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
	/** Truncated key hash for analytics (first 16 chars of SHA-256). */
	keyHash?: string;
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
	/** Service binding to bv-web (BV_WEB) used by get_domain_rank to call the C1 benchmark endpoint. Fail-soft; absent on BSL self-hosts. */
	bvWebBenchmark?: { fetch: typeof fetch };
	/** Bearer token (BV_WEB_INTERNAL_KEY) forwarded to the C1 benchmark endpoint. */
	bvWebBenchmarkAuthToken?: string;
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

export function extractAccessLogDomain(args: Record<string, unknown> | undefined): string | undefined {
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
): { toolName: string; domain: string; method: string } | undefined {
	if (method !== 'tools/call') return undefined;
	const toolNameRaw = params && typeof params === 'object' && 'name' in params ? params.name : undefined;
	const argsRaw = params && typeof params === 'object' && 'arguments' in params ? params.arguments : undefined;
	const args = argsRaw && typeof argsRaw === 'object' && !Array.isArray(argsRaw) ? (argsRaw as Record<string, unknown>) : undefined;
	const domain = extractAccessLogDomain(args);
	if (typeof toolNameRaw !== 'string' || !domain) return undefined;
	return { toolName: normalizeToolName(toolNameRaw), domain, method };
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

export async function encryptIpEvidence(ip: string, keyBase64: string | undefined): Promise<string | null> {
	if (!keyBase64 || ip === 'unknown') return null;
	if (!validateEncryptionKeyOnce(keyBase64)) return null;
	const rawKey = base64ToBytes(keyBase64);
	const key = await crypto.subtle.importKey('raw', toArrayBuffer(rawKey), { name: 'AES-GCM' }, false, ['encrypt']);
	const iv = crypto.getRandomValues(new Uint8Array(12));
	const plaintext = new TextEncoder().encode(ip);
	const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: toArrayBuffer(iv) }, key, toArrayBuffer(plaintext)));
	return `v1:${bytesToBase64(iv)}:${bytesToBase64(ciphertext)}`;
}

/**
 * Inverse of {@link encryptIpEvidence}: parses the `v1:iv:ct` wire format and
 * AES-GCM-decrypts the raw IP. Returns `null` on any failure (missing key,
 * malformed wire, wrong key length, decrypt error) — callers fall back to the
 * masked IP. Operator-only re-identification surface (forensics endpoint).
 */
export async function decryptIpEvidence(wire: string, keyBase64: string | undefined): Promise<string | null> {
	if (!keyBase64 || !wire) return null;
	const parts = wire.split(':');
	if (parts.length !== 3) return null; // expected v1:iv:ct
	try {
		const rawKey = base64ToBytes(keyBase64);
		if (rawKey.byteLength !== 32) return null;
		const iv = base64ToBytes(parts[1]);
		const ct = base64ToBytes(parts[2]);
		const key = await crypto.subtle.importKey('raw', toArrayBuffer(rawKey), { name: 'AES-GCM' }, false, ['decrypt']);
		const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: toArrayBuffer(iv) }, key, toArrayBuffer(ct));
		return new TextDecoder().decode(pt);
	} catch {
		return null;
	}
}

function recordMcpAccessLog(
	options: ExecuteMcpRequestOptions,
	input: { toolName: string; domain: string; rateLimited: boolean; method?: string; status?: string },
): void {
	if (!options.intelligenceDb && !options.analyticsQueue) return;
	const logger = getLogger();
	const level = options.analyticsPiiLevel ?? 'coarse';
	const event = buildAccessLogEvent(
		{
			ip: options.ip,
			ipHash: options.ipHash ?? 'unknown',
			ipMasked: maskIp(options.ip),
			toolName: input.toolName,
			domain: input.domain,
			source: options.source ?? 'public',
			country: options.country ?? null,
			region: options.region ?? null,
			city: options.city ?? null,
			latitude: options.latitude ?? null,
			longitude: options.longitude ?? null,
			asn: options.asn ?? null,
			asOrg: options.asOrg ?? null,
			keyHash: options.keyHash ?? null,
			clientType: options.clientType ?? null,
			colo: options.colo ?? null,
			sessionHash: options.sessionHash ?? null,
			userAgent: options.userAgent ?? null,
			method: input.method ?? null,
			transport: options.responseTransport ?? null,
			status: input.status ?? null,
			responseMs: Math.max(0, Date.now() - options.startTime),
			rateLimited: input.rateLimited,
		},
		level,
	);

	// Phase 1, decision #2: internal-source traffic (automated rescans — null
	// key_hash, ip_hash='unknown') has near-zero forensic value at near-total
	// volume. When the rollup flag is on, increment a low-cardinality counter
	// INSTEAD of writing a per-event row/queue message. External/authenticated
	// traffic is untouched and keeps its faithful per-event rows. Best-effort,
	// fail-soft; requires the D1 binding to land the counter.
	if (options.rollupInternal && (options.source ?? 'public') === 'internal' && options.intelligenceDb) {
		// Capture the day bucket from the REQUEST start time, not `Date.now()` inside
		// the deferred DB write: this recorder runs after dispatch (and the increment
		// settles in the waitUntil tail), so a long request that crosses UTC midnight
		// (e.g. a 15s scan starting at 23:59:5x) would otherwise mis-bucket into the
		// next day. `options.startTime` pins the count to the day the request began.
		const bucketDay = unixDayBucket(options.startTime);
		options.waitUntil?.(fireAndForget(incrementAccessRollup(options.intelligenceDb, event, bucketDay), logger, 'mcp_access_rollup_increment'));
		return;
	}

	// Preferred path: enqueue for the batch consumer (PTR + encrypt + batch insert).
	if (options.analyticsQueue) {
		// Surface-minimization: the consumer needs the raw IP only for PTR (full) or
		// encryption (standard+). At coarse, neither applies — strip it so the raw IP
		// never transits the queue at-rest. ipHash/ipMasked are already on the event.
		const queueEvent = piiAllows(level, 'ptr') || piiAllows(level, 'ciphertext') ? event : { ...event, ip: 'unknown' };
		const send = options.analyticsQueue.send(queueEvent, { contentType: 'json' });
		options.waitUntil?.(fireAndForget(send, logger, 'mcp_access_log_enqueue'));
		return;
	}

	// Fallback (self-host, no queue): inline encrypted insert, no PTR.
	const work = async () => {
		const ipCiphertext = piiAllows(level, 'ciphertext') ? await encryptIpEvidence(event.ip, options.ipEncryptionKey) : null;
		await insertAccessLogRow(options.intelligenceDb!, event, ipCiphertext, ipCiphertext ? (options.ipEncryptionKeyVersion ?? 'v1') : null);
	};
	options.waitUntil?.(fireAndForget(work(), logger, 'mcp_access_log_insert'));
}

/** Test-only handle to exercise the recorder without booting a request. */
export const __recordMcpAccessLogForTest = recordMcpAccessLog;

/** Inputs for the internal-path access-log recorder (B1). */
export interface RecordInternalAccessLogInput {
	toolName: string;
	domain: string;
	/** Tool outcome — `'pass'` | `'error'` (mirrors the public path's status mapping). */
	status: string;
	/** x-bv-caller header value, stored in the `client_type` column. */
	clientType?: string | null;
	intelligenceDb?: D1Database;
	analyticsQueue?: { send(message: unknown, options?: { contentType?: 'json' }): Promise<void> };
	analyticsPiiLevel?: import('../lib/analytics-pii').AnalyticsPiiLevel;
	ipEncryptionKey?: string;
	ipEncryptionKeyVersion?: string;
	startTime: number;
	waitUntil?: (promise: Promise<unknown>) => void;
	/**
	 * Phase 1, decision #2 — when on, internal rows route to the `mcp_access_rollup`
	 * counter instead of a per-event insert. Default-off (per-event, unchanged).
	 */
	rollupInternal?: boolean;
}

/**
 * B1 — record an mcp_access_log row from the internal service-binding path
 * (`/internal/tools/{call,batch}`). Tagged `source: 'internal'` with sentinel
 * `ip`/`ipHash = 'unknown'` (IP encryption + PTR short-circuit) and `keyHash =
 * null` (bv-web owns customer attribution). Delegates to {@link recordMcpAccessLog}
 * so the column/bind logic stays single-sourced. Early-returns (no row) when
 * neither `intelligenceDb` nor `analyticsQueue` is bound.
 */
export function recordInternalAccessLog(input: RecordInternalAccessLogInput): void {
	const options: ExecuteMcpRequestOptions = {
		// Minimal shape — recordMcpAccessLog only reads the fields below.
		body: { jsonrpc: '2.0', id: null, method: 'tools/call' } as JsonRpcRequest,
		allowStreaming: false,
		batchMode: false,
		batchSize: 1,
		// The `transport` column distinguishes the internal door from public json/sse.
		// Cast: the recorder only reads this for the column value; the 'json' | 'sse'
		// union governs the public dispatch path, which this synthetic options never enters.
		responseTransport: 'internal' as ExecuteMcpRequestOptions['responseTransport'],
		startTime: input.startTime,
		ip: 'unknown',
		ipHash: 'unknown',
		isAuthenticated: false,
		validateSession: false,
		serverVersion: '',
		keyHash: undefined,
		clientType: input.clientType ?? undefined,
		country: undefined,
		source: 'internal',
		intelligenceDb: input.intelligenceDb,
		analyticsQueue: input.analyticsQueue,
		analyticsPiiLevel: input.analyticsPiiLevel,
		ipEncryptionKey: input.ipEncryptionKey,
		ipEncryptionKeyVersion: input.ipEncryptionKeyVersion,
		waitUntil: input.waitUntil,
		rollupInternal: input.rollupInternal,
	};
	recordMcpAccessLog(options, {
		toolName: input.toolName,
		domain: input.domain,
		rateLimited: false,
		method: 'tools/call',
		status: input.status,
	});
}

const ACCESS_LOG_COLUMNS = [
	'ip_hash',
	'ip_masked',
	'tool_name',
	'domain',
	'country',
	'user_agent',
	'response_ms',
	'rate_limited',
	'ip_ciphertext',
	'ip_key_version',
	'city',
	'region',
	'latitude',
	'longitude',
	'asn',
	'as_org',
	'ptr_hostname',
	'key_hash',
	'client_type',
	'colo',
	'session_hash',
	'method',
	'transport',
	'status',
	'source',
] as const;

export function accessLogInsertSql(): string {
	return `INSERT INTO mcp_access_log (${ACCESS_LOG_COLUMNS.join(', ')}) VALUES (${ACCESS_LOG_COLUMNS.map(() => '?').join(', ')})`;
}

export function accessLogBindings(event: AccessLogEvent, ipCiphertext: string | null, ipKeyVersion: string | null): unknown[] {
	return [
		event.ipHash,
		event.ipMasked,
		event.toolName,
		event.domain,
		event.country,
		event.userAgent,
		event.responseMs,
		event.rateLimited ? 1 : 0,
		ipCiphertext,
		ipKeyVersion,
		event.city,
		event.region,
		event.latitude,
		event.longitude,
		event.asn,
		event.asOrg,
		event.ptrHostname,
		event.keyHash,
		event.clientType,
		event.colo,
		event.sessionHash,
		event.method,
		event.transport,
		event.status,
		event.source,
	];
}

async function insertAccessLogRow(
	db: D1Database,
	event: AccessLogEvent,
	ipCiphertext: string | null,
	ipKeyVersion: string | null,
): Promise<void> {
	await db
		.prepare(accessLogInsertSql())
		.bind(...accessLogBindings(event, ipCiphertext, ipKeyVersion))
		.run();
}

/** Unix-day bucket (UTC) used as the leading dimension of the rollup primary key. */
function unixDayBucket(nowMs: number): number {
	return Math.floor(nowMs / 86_400_000);
}

/** SQLite UPSERT for the rollup counter — single-sourced so the migration doc and code agree. */
const ACCESS_ROLLUP_UPSERT_SQL = `INSERT INTO mcp_access_rollup (bucket_day, tool_name, source, status, auth_tier, client_type, country, count) VALUES (?, ?, ?, ?, ?, ?, ?, 1) ON CONFLICT (bucket_day, tool_name, source, status, auth_tier, client_type, country) DO UPDATE SET count = count + 1`;

/**
 * Phase 1, decision #2 — increment the low-cardinality `mcp_access_rollup`
 * counter for an internal-source access-log event in place of a per-event row.
 * NULL dimensions are coalesced to `'unknown'` so the composite primary key
 * actually collapses duplicates (SQLite treats NULLs as distinct in a unique
 * index). Internal traffic carries no per-key tier — bv-web owns customer
 * attribution — so `auth_tier` is recorded as `'unknown'`. Best-effort.
 *
 * `bucketDay` is computed by the caller from the request start time (NOT
 * `Date.now()` here) so a request crossing UTC midnight before this deferred
 * write settles still counts against the day it began.
 */
async function incrementAccessRollup(db: D1Database, event: AccessLogEvent, bucketDay: number): Promise<void> {
	await db
		.prepare(ACCESS_ROLLUP_UPSERT_SQL)
		.bind(
			bucketDay,
			event.toolName,
			event.source ?? 'unknown',
			event.status ?? 'unknown',
			'unknown',
			event.clientType ?? 'unknown',
			event.country ?? 'unknown',
		)
		.run();
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
		colo: options.colo,
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
	accessLogInput: { toolName: string; domain: string; method: string } | undefined,
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
		recordMcpAccessLog(options, { ...accessLogInput, rateLimited: true, status: 'unknown' });
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
	accessLogInput: { toolName: string; domain: string; method: string } | undefined,
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
		recordMcpAccessLog(options, { ...accessLogInput, rateLimited: true, status: 'unknown' });
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

/**
 * Reject a PUBLIC `/mcp` tools/call for an INTERNAL-ONLY tool (e.g. map_csc_products).
 *
 * Returns the SAME unknown-tool result a nonexistent tool name produces via the
 * dispatch path (handlers/tools.ts `default` case) — a JSON-RPC success wrapping a
 * countless tool-error result (no tool count that would hint a hidden tool) — so the
 * tool's existence is NOT leaked on the public surface and no 403/UPGRADE_REQUIRED is
 * emitted. executeMcpRequest is the public path only; the internal path
 * (src/internal.ts → handleToolsCall) bypasses this and remains fully callable,
 * as does the direct FUNCTION call from prioritize_csc_leads.
 */
function buildInternalOnlyToolResponse(
	id: JsonRpcRequest['id'],
	toolName: string,
	method: string,
	options: ExecuteMcpRequestOptions,
	eventId: string | undefined,
	accessLogInput: { toolName: string; domain: string; method: string } | undefined,
): Extract<ProcessedRequestResult, { kind: 'response' }> {
	// Byte-identical to the genuine unknown-tool wire payload (same countless message
	// as handlers/tools.ts), so an internal-only tool is indistinguishable from a
	// nonexistent one — and neither response reveals a tool count that would hint a
	// hidden tool exists (public tools/list = TOOLS.length − INTERNAL_ONLY_TOOLS.size).
	const payload = jsonRpcSuccess(id, {
		content: [mcpError(`Unknown tool: ${toolName}. Call tools/list to see the available tools.`)],
		isError: true,
	});
	// Mirror the dispatch unknown-tool bookkeeping: not a JSON-RPC error (result.isError),
	// so request analytics logs 'ok' and the fuzz counter records an unknown_tool hit.
	emitRequestAnalytics(options, method, 'ok', false);
	recordMcpToolErrorIfUnknownTool(options, method, payload);
	if (accessLogInput) {
		recordMcpAccessLog(options, { ...accessLogInput, rateLimited: false, status: 'pass' });
	}
	return {
		kind: 'response',
		payload,
		headers: {},
		httpStatus: 200,
		useErrorEnvelope: false,
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

	// PUBLIC-PATH-ONLY internal-only gate. map_csc_products (INTERNAL_ONLY_TOOLS) is
	// removed from the public /mcp surface: reject BEFORE any tier branching so it
	// applies to ALL callers (unauthenticated, free, developer, owner) with the same
	// unknown-tool result — no existence leak, no 403. The internal path
	// (src/internal.ts → handleToolsCall) never reaches executeMcpRequest, so the
	// tool stays callable there and via the direct prioritize_csc_leads function call.
	if (method === 'tools/call') {
		const internalOnlyNameRaw =
			typeof params === 'object' && params !== null && 'name' in params ? (params as Record<string, unknown>).name : undefined;
		const internalOnlyName = typeof internalOnlyNameRaw === 'string' ? normalizeToolName(internalOnlyNameRaw) : '';
		if (internalOnlyName && isInternalOnlyTool(internalOnlyName)) {
			return buildInternalOnlyToolResponse(id, internalOnlyName, method, options, eventId, accessLogInput);
		}
	}

	let rateHeaders: Record<string, string> = {};
	if (!options.isAuthenticated && method === 'tools/call') {
		const globalResult = await checkGlobalDailyLimit(
			GLOBAL_DAILY_TOOL_LIMIT,
			options.rateLimitKv,
			options.quotaCoordinator,
			options.analytics,
		);
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
		const toolGated = !!toolName && (isAuthRequiredTool(toolName) || isGatedPaidOnlyTool(toolName));
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
		if (toolName && isAuthRequiredTool(toolName)) {
			return buildAuthRequiredResponse(id, toolName, method, options, eventId, accessLogInput);
		}
		if (toolName && isGatedPaidOnlyTool(toolName)) {
			return buildGatedToolResponse(id, toolName, method, options, eventId, accessLogInput);
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
				recordMcpAccessLog(options, { ...accessLogInput, rateLimited: true, status: 'unknown' });
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
							correlationId: options.correlationId,
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
			bvWebBenchmark: options.bvWebBenchmark,
			bvWebBenchmarkAuthToken: options.bvWebBenchmarkAuthToken,
			// keyHash MUST be forwarded: handleToolsCall's Layer-2 guard
			// (isAuthRequiredTool && m365Proxy && !keyHash) rejects every
			// authenticated identity_secops caller without it, and bv-web's
			// M365 proxy needs the principal hash. Set only for authed callers.
			keyHash: options.keyHash,
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
			bvWebBenchmark: options.bvWebBenchmark,
			bvWebBenchmarkAuthToken: options.bvWebBenchmarkAuthToken,
			// keyHash MUST be forwarded: handleToolsCall's Layer-2 guard
			// (isAuthRequiredTool && m365Proxy && !keyHash) rejects every
			// authenticated identity_secops caller without it, and bv-web's
			// M365 proxy needs the principal hash. Set only for authed callers.
			keyHash: options.keyHash,
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
