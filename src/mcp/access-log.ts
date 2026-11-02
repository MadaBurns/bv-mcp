// SPDX-License-Identifier: BUSL-1.1

/** MCP access-log recording and roll-up, split out of execute.ts (no behaviour change). */

import { fireAndForget, getLogger } from '../lib/log';
import { declaredToolArgKeys, normalizeToolName } from '../handlers/tool-args';
import type { JsonRpcRequest } from '../lib/json-rpc';
import { piiAllows, type AnalyticsPiiLevel } from '../lib/analytics-pii';
import { buildAccessLogEvent, resolveAccessLogAttribution, type AccessLogEvent } from '../lib/access-log-event';
import { encryptIpEvidence } from './ip-evidence';
import type { ExecuteMcpRequestOptions } from './execute';

export function getDomainFromParams(params: Record<string, unknown> | undefined): string | undefined {
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

/**
 * Whether a raw (pre-validation) tools/call asks for a metered force_refresh.
 * Only tools whose strict schema DECLARES force_refresh are metered: on any other
 * tool the key is rejected as an unknown argument, so the call never runs and
 * must not burn a force-refresh quota unit.
 */
export function isMeteredForceRefresh(toolName: string, argsRaw: unknown): boolean {
	if (!declaredToolArgKeys(toolName).has('force_refresh')) return false;
	return (
		typeof argsRaw === 'object' &&
		argsRaw !== null &&
		!Array.isArray(argsRaw) &&
		(argsRaw as Record<string, unknown>).force_refresh === true
	);
}

export function getToolCallLogInput(
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

type AccessLogInput = { toolName: string; domain: string; rateLimited: boolean; method?: string; status?: string };
type AccessLogLogger = ReturnType<typeof getLogger>;

/** Copy `keys` from `src`, defaulting each absent (undefined/null) value to `null`; key order follows `keys`. */
function nullableFields<T extends object, K extends keyof T>(src: T, keys: readonly K[]): { [P in K]-?: NonNullable<T[P]> | null } {
	const out = {} as { [P in K]-?: NonNullable<T[P]> | null };
	for (const key of keys) out[key] = (src[key] ?? null) as NonNullable<T[typeof key]> | null;
	return out;
}

/** Request-origin and caller-identity columns (source, geo, key hash, client). */
function accessLogCallerFields(options: ExecuteMcpRequestOptions) {
	return {
		source: options.source ?? 'public',
		...nullableFields(options, ['country', 'region', 'city', 'latitude', 'longitude', 'asn', 'asOrg']),
		keyHash: options.analyticsKeyHash ?? null,
		...nullableFields(options, ['clientType', 'colo', 'sessionHash', 'userAgent']),
	};
}

/** Per-call outcome columns (method, transport, status, latency, rate-limit flag). */
function accessLogOutcomeFields(options: ExecuteMcpRequestOptions, input: AccessLogInput) {
	return {
		method: input.method ?? null,
		transport: options.responseTransport ?? null,
		status: input.status ?? null,
		responseMs: Math.max(0, Date.now() - options.startTime),
		rateLimited: input.rateLimited,
	};
}

function buildMcpAccessLogEvent(options: ExecuteMcpRequestOptions, input: AccessLogInput, level: AnalyticsPiiLevel) {
	// #876 — header present → real `i_` hash; header absent but request.cf present →
	// `n_` network-locality key + ip_masked='no-cf-header'; neither → bare 'unknown'.
	// The internal door passes ipHash='unknown' explicitly and is untouched.
	const attribution = resolveAccessLogAttribution({
		ipHash: options.ipHash,
		ipMasked: maskIp(options.ip),
		asn: options.asn,
		colo: options.colo,
		country: options.country,
	});
	return buildAccessLogEvent(
		{
			ip: options.ip,
			ipHash: attribution.ipHash,
			ipMasked: attribution.ipMasked,
			toolName: input.toolName,
			domain: input.domain,
			...accessLogCallerFields(options),
			...accessLogOutcomeFields(options, input),
		},
		level,
	);
}

/**
 * Phase 1, decision #2: internal-source traffic (automated rescans — null
 * key_hash, ip_hash='unknown') has near-zero forensic value at near-total
 * volume. When the rollup flag is on, increment a low-cardinality counter
 * INSTEAD of writing a per-event row/queue message. External/authenticated
 * traffic is untouched and keeps its faithful per-event rows. Best-effort,
 * fail-soft; requires the D1 binding to land the counter. Returns true when it handled the event.
 */
function recordAccessRollup(options: ExecuteMcpRequestOptions, event: AccessLogEvent, logger: AccessLogLogger): boolean {
	if (!options.rollupInternal || (options.source ?? 'public') !== 'internal' || !options.intelligenceDb) return false;
	// Capture the day bucket from the REQUEST start time, not `Date.now()` inside
	// the deferred DB write: this recorder runs after dispatch (and the increment
	// settles in the waitUntil tail), so a long request that crosses UTC midnight
	// (e.g. a 15s scan starting at 23:59:5x) would otherwise mis-bucket into the
	// next day. `options.startTime` pins the count to the day the request began.
	const bucketDay = unixDayBucket(options.startTime);
	options.waitUntil?.(
		fireAndForget(incrementAccessRollup(options.intelligenceDb, event, bucketDay), logger, 'mcp_access_rollup_increment'),
	);
	return true;
}

/** Preferred path: enqueue for the batch consumer (PTR + encrypt + batch insert). Returns true when it handled the event. */
function enqueueAccessLog(
	options: ExecuteMcpRequestOptions,
	event: AccessLogEvent,
	level: AnalyticsPiiLevel,
	logger: AccessLogLogger,
): boolean {
	if (!options.analyticsQueue) return false;
	// Surface-minimization: the consumer needs the raw IP only for PTR (full) or
	// encryption (standard+). At coarse, neither applies — strip it so the raw IP
	// never transits the queue at-rest. ipHash/ipMasked are already on the event.
	const queueEvent = piiAllows(level, 'ptr') || piiAllows(level, 'ciphertext') ? event : { ...event, ip: 'unknown' };
	const send = options.analyticsQueue.send(queueEvent, { contentType: 'json' });
	options.waitUntil?.(fireAndForget(send, logger, 'mcp_access_log_enqueue'));
	return true;
}

/** Fallback (self-host, no queue): inline encrypted insert, no PTR. */
async function insertAccessLogInline(options: ExecuteMcpRequestOptions, event: AccessLogEvent, level: AnalyticsPiiLevel): Promise<void> {
	const ipCiphertext = piiAllows(level, 'ciphertext') ? await encryptIpEvidence(event.ip, options.ipEncryptionKey) : null;
	await insertAccessLogRow(options.intelligenceDb!, event, ipCiphertext, ipCiphertext ? (options.ipEncryptionKeyVersion ?? 'v1') : null);
}

/** An access-log row can only land when the D1 binding or the analytics queue is bound. */
function hasAccessLogSink(options: ExecuteMcpRequestOptions): boolean {
	return !!(options.intelligenceDb || options.analyticsQueue);
}

export function recordMcpAccessLog(options: ExecuteMcpRequestOptions, input: AccessLogInput): void {
	if (!hasAccessLogSink(options)) return;
	const logger = getLogger();
	const level = options.analyticsPiiLevel ?? 'coarse';
	const event = buildMcpAccessLogEvent(options, input, level);
	if (recordAccessRollup(options, event, logger)) return;
	if (enqueueAccessLog(options, event, level, logger)) return;
	options.waitUntil?.(fireAndForget(insertAccessLogInline(options, event, level), logger, 'mcp_access_log_insert'));
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
