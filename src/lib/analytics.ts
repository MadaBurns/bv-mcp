// SPDX-License-Identifier: BUSL-1.1

/**
 * Cloudflare Analytics Engine helpers.
 *
 * All emits are fail-open: write errors are logged and ignored so MCP flows
 * are never blocked by telemetry issues.
 *
 * Schema: Each event type uses a distinct index1 value. See the analytics
 * observability plan for the full blob/double positional schema.
 */

import { logError } from './log';
import type { McpClientType } from './client-detection';

/** Minimal shape used by Cloudflare Analytics Engine dataset bindings. */
interface AnalyticsDatasetLike {
	writeDataPoint: (point: { indexes?: string[]; blobs?: string[]; doubles?: number[] }) => void;
}

/** Enriched context dimensions threaded from the request handler. */
export interface AnalyticsContext {
	country?: string;
	clientType?: McpClientType;
	authTier?: string;
	sessionHash?: string;
	/** Truncated SHA-256 hash of the API key (first 16 chars). Enables per-customer analytics. */
	keyHash?: string;
	/**
	 * FNV-1a hash of the cf-connecting-ip (`i_` prefix). Lossy by design — groups equal IPs
	 * for analytics queries but is trivially reversible if the IP is already known. We
	 * deliberately accept this property because the alternative (raw IP in telemetry) is
	 * what we want to avoid; a defender investigating a known suspect IP can hash it
	 * client-side and filter, while a leak of the analytics dataset doesn't directly
	 * expose addresses.
	 */
	ipHash?: string;
	/**
	 * Cloudflare edge colo (`request.cf.colo`, e.g. `AKL`, `SYD`) the request landed
	 * on. Captured at the Worker entry point so per-datacenter p95/error-rate can be
	 * isolated — a single-colo regression otherwise averages out across the global
	 * aggregate and never trips ALERT_P95_THRESHOLD. Undefined in tests/local →
	 * stored as `'unknown'`. Appended as the trailing blob on `mcp_request` and
	 * `tool_call` (append-only — never reorder existing positions).
	 */
	colo?: string;
	/** Geo enrichment for AE aggregate dashboards (append-only blobs on tool_call). */
	region?: string;
	city?: string;
	asn?: number;
}

export interface AnalyticsClient {
	enabled: boolean;
	emitRequestEvent(
		event: {
			method: string;
			status: 'ok' | 'error';
			durationMs: number;
			isAuthenticated: boolean;
			hasJsonRpcError: boolean;
			/** JSON-RPC error code (negative per spec); stored as abs() in double2, 0 when absent. */
			jsonRpcErrorCode?: number;
			transport: 'json' | 'sse';
		} & AnalyticsContext,
	): void;
	emitToolEvent(
		event: {
			toolName: string;
			status: 'pass' | 'fail' | 'error' | 'unknown';
			durationMs: number;
			domain?: string;
			isError: boolean;
			score?: number;
			cacheStatus?: 'hit' | 'miss' | 'n/a';
			/**
			 * blob12 — canonical name of the tool called immediately before this one
			 * in the same MCP session. 'none' = first call; 'unknown' = continuity
			 * unavailable (cross-isolate, no session, etc.). Best-effort; never blocks.
			 */
			priorTool?: string;
		} & AnalyticsContext,
	): void;
	emitRateLimitEvent(
		event: {
			limitType: 'minute' | 'hour' | 'daily_tool' | 'daily_global' | 'daily_ip' | 'distinct_domain' | 'gated_tool';
			toolName: string;
			limit: number;
			remaining: number;
		} & AnalyticsContext,
	): void;
	emitSessionEvent(
		event: {
			action: 'created' | 'terminated' | 'revived';
			method?: string;
		} & AnalyticsContext,
	): void;
	emitDegradationEvent(
		event: {
			/**
			 * Degradation members:
			 *  - `kv_fallback` — a KV write threw (emitted from session.ts).
			 *  - `binding_unavailable` / `binding_5xx` / `binding_timeout` — a PRESENT
			 *    operator-only service binding (BV_RECON / BV_TLS_PROBE) failed at call
			 *    time. Absent-on-self-host and the benign recon 404 are deliberately NOT
			 *    emitted (those are expected, not alertable). `component` carries which
			 *    binding (`recon` | `tls_probe`).
			 *  - `quota_coordinator_fallback` — the batched per-IP QuotaCoordinator
			 *    evaluation was bypassed (breaker open, malformed-but-non-empty response,
			 *    or the DO errored) and the request fell back to the serial / fail-soft
			 *    path. Lets an operator see the quota guardrail is degraded (ADAM #6).
			 *    `component` carries the reason (`breaker_open` | `malformed_response`
			 *    | `evaluate_error`).
			 *  - `shard_below_benchmark_floor` — a per-profile ProfileAccumulator shard
			 *    is in its cold-start warm-up window (sampleCount < MIN_BENCHMARK_SCANS)
			 *    while write-sharding is ON. Adaptive uplift is TEMPORARILY degraded
			 *    toward static weights for that profile until the shard re-clears its
			 *    threshold. `component` carries `profile_accumulator:<shardName>`. Only
			 *    emitted in `PROFILE_ACCUMULATOR_SHARDING='profile'` mode — observable so
			 *    an operator can watch the warm-up drain after a flip.
			 *  - `quota_shard_salt_missing` — R8 quota-sharding is ENABLED but
			 *    `QUOTA_SHARD_SALT` is unset, so the shard mapping degrades to the
			 *    precomputable unsalted hash (the salt should be a deploy Secret).
			 *    `component` carries `quota_coordinator`. A config-misconfiguration
			 *    signal, not a runtime failure — `queryBindingDegradation` excludes it
			 *    (like the other quota-guardrail members); query it directly.
			 */
			degradationType:
				| 'kv_fallback'
				| 'binding_unavailable'
				| 'binding_5xx'
				| 'binding_timeout'
				| 'cost_ceiling_degraded'
				| 'quota_coordinator_fallback'
				| 'shard_below_benchmark_floor'
				| 'quota_shard_salt_missing';
			component: string;
			domain?: string;
			// `cost_ceiling_degraded` (component `global_cost_ceiling`) is emitted by
			// rate-limiter.ts when the QuotaCoordinator DO breaker is OPEN and the global
			// cost ceiling falls to KV/in-memory. Intentionally a DISTINCT degradationType
			// (not `kv_fallback`) so queryBindingDegradation's `blob1 != 'kv_fallback'`
			// exclusion does NOT swallow it and it reaches the 15-min cron alert. The alert
			// keys on degradationType (blob1), not component (blob2) -- a new alertable
			// signal must carry a non-excluded degradationType.
		} & AnalyticsContext,
	): void;
	/**
	 * R8 per-shard observability. Emits the resolved QuotaCoordinator shard index
	 * (0 .. QUOTA_SHARD_COUNT-1) for an unauthenticated quota check so an operator can
	 * watch shard-load distribution and detect SKEW (a hot shard) after flipping
	 * `QUOTA_SHARDING_ENABLED`. LOW-CARDINALITY by construction: blob1 is the small
	 * integer shard index. Only emitted when sharding is ON. No new binding — rides the
	 * existing MCP_ANALYTICS dataset under the `quota_shard` index. Fail-open.
	 *
	 * Blob positions (quota_shard): blob1=shardIndex, blob2=country, blob3=tier.
	 */
	emitQuotaShardEvent(
		event: {
			/** Resolved shard index (0-based, < QUOTA_SHARD_COUNT). */
			shardIndex: number;
		} & AnalyticsContext,
	): void;
	/**
	 * Async-path (cron/queue/DO) batch outcome counter. The cron handler, the
	 * queue consumer, and the DOs otherwise log to console only, so a brand-audit
	 * queue batch that throws (or a cron sweep that fails) is structurally outside
	 * `queryRecentAnomalies` (which filters `index1='tool_call'`). This event makes
	 * those failures queryable + alertable.
	 *
	 * `handler` identifies the source (e.g. queue name `brand-audit-queue`,
	 * `tenant-scan-queue`, or a cron route). `outcome` is `ok` when the batch
	 * completed without throwing, `error` when it threw. `messageCount` is the
	 * batch size (0 for cron); `failureCount` is how many messages/sub-tasks
	 * failed (for a whole-batch throw, the consumer reports the batch size).
	 *
	 * Blob positions (queue_batch): blob1=handler, blob2=outcome, blob3=country,
	 *   blob4=authTier. Doubles: double1=durationMs, double2=failureCount,
	 *   double3=messageCount.
	 */
	emitQueueBatchEvent(
		event: {
			handler: string;
			outcome: 'ok' | 'error';
			durationMs: number;
			messageCount: number;
			failureCount: number;
		} & AnalyticsContext,
	): void;
	/**
	 * `tail` event — one aggregated row per (colo, outcome, scriptName) bucket of
	 * a tail-consumer trace batch. Captures invocation outcomes (incl. `exception`)
	 * that never reach the in-band emit path — a durable export of the otherwise
	 * dashboard-only, head-sampled structured logs.
	 *
	 * No AnalyticsContext: tail traces carry no per-request country/client/auth
	 * dimensions (the consumer runs outside the request). `country` is set to the
	 * `colo` so existing colo-grouped queries can pivot on blob (`country` slot).
	 */
	emitTailAggregate(event: {
		/** Cloudflare colo where the traced invocations ran (or `unknown`). */
		colo: string;
		/** Invocation outcome bucket (`ok` | `exception` | `canceled` | …). */
		outcome: string;
		/** Traced Worker script name (or `unknown`). */
		scriptName: string;
		/** Number of traced invocations folded into this bucket. */
		invocations: number;
		/** Number of those invocations that surfaced ≥1 exception. */
		exceptions: number;
	}): void;
}

/**
 * Build an analytics client from the optional dataset binding.
 * If the binding is unavailable, emit functions become no-ops.
 */
export function createAnalyticsClient(dataset?: AnalyticsDatasetLike): AnalyticsClient {
	const noop = () => {
		// no-op when analytics dataset is not configured
	};

	if (!dataset) {
		return {
			enabled: false,
			emitRequestEvent: noop,
			emitToolEvent: noop,
			emitRateLimitEvent: noop,
			emitSessionEvent: noop,
			emitDegradationEvent: noop,
			emitQuotaShardEvent: noop,
			emitQueueBatchEvent: noop,
			emitTailAggregate: noop,
		};
	}

	return {
		enabled: true,
		emitRequestEvent: (event) => {
			safeWrite(dataset, {
				indexes: ['mcp_request'],
				blobs: [
					normalizeIndex(event.method),
					event.transport,
					event.status,
					event.isAuthenticated ? 'auth' : 'anon',
					event.hasJsonRpcError ? 'jsonrpc_error' : 'jsonrpc_ok',
					event.country ?? 'unknown',
					event.clientType ?? 'unknown',
					event.authTier ?? 'anon',
					event.sessionHash ?? 'none',
					event.keyHash ?? 'none',
					event.ipHash ?? 'none',
					// blob12 (append-only trailing) — Cloudflare edge colo. New dimension;
					// must stay LAST so existing position-indexed queries are unaffected.
					event.colo ?? 'unknown',
				],
				// double2: abs(JSON-RPC error code) — codes are negative per spec and
				// sanitizeNumber clamps <0 to 0, so we store the magnitude (0 = no error).
				doubles: [sanitizeNumber(event.durationMs), sanitizeNumber(Math.abs(event.jsonRpcErrorCode ?? 0))],
			});
		},
		emitToolEvent: (event) => {
			safeWrite(dataset, {
				indexes: ['tool_call'],
				blobs: [
					normalizeIndex(event.toolName),
					event.status,
					event.isError ? 'error' : 'ok',
					event.domain ? domainFingerprint(event.domain) : 'none',
					event.country ?? 'unknown',
					event.clientType ?? 'unknown',
					event.authTier ?? 'anon',
					event.cacheStatus ?? 'n/a',
					event.keyHash ?? 'none',
					event.ipHash ?? 'none',
					// blob11 — Cloudflare edge colo (append-only; existing queries unaffected).
					event.colo ?? 'unknown',
					// blob12 — priorTool: canonical name of the immediately-preceding tool in
					// the same MCP session. 'none' = first call; 'unknown' = continuity
					// unavailable. Computed synchronously from in-memory session state
					// (readAndUpdateLastTool) — zero I/O, O(1), never blocks the hot path.
					// Append-only; blobs 1–11 and doubles 1–2 UNCHANGED.
					event.priorTool ?? 'unknown',
					// blob13-15 — geo aggregate dimensions (append-only; positions 1-12 unchanged).
					normalizeIndex(event.region ?? 'unknown'),
					normalizeIndex(event.city ?? 'unknown'),
					event.asn != null ? String(event.asn) : 'unknown',
				],
				doubles: [sanitizeNumber(event.durationMs), sanitizeNumber(event.score ?? 0)],
			});
		},
		emitRateLimitEvent: (event) => {
			safeWrite(dataset, {
				indexes: ['rate_limit'],
				blobs: [event.limitType, normalizeIndex(event.toolName), event.country ?? 'unknown', event.authTier ?? 'anon'],
				doubles: [sanitizeNumber(event.limit), sanitizeNumber(event.remaining)],
			});
		},
		emitSessionEvent: (event) => {
			safeWrite(dataset, {
				indexes: ['session'],
				blobs: [
					event.action,
					event.country ?? 'unknown',
					event.clientType ?? 'unknown',
					event.authTier ?? 'anon',
					event.method ?? 'unknown',
					event.keyHash ?? 'none',
				],
			});
		},
		emitDegradationEvent: (event) => {
			safeWrite(dataset, {
				indexes: ['degradation'],
				blobs: [
					event.degradationType,
					normalizeIndex(event.component),
					event.domain ? domainFingerprint(event.domain) : 'none',
					event.country ?? 'unknown',
					event.clientType ?? 'unknown',
					event.authTier ?? 'anon',
				],
			});
		},
		emitQuotaShardEvent: (event) => {
			safeWrite(dataset, {
				indexes: ['quota_shard'],
				// blob1 = small integer shard index (low cardinality, 0..QUOTA_SHARD_COUNT-1).
				// sanitizeNumber clamps non-finite/negative to 0; Math.trunc drops any fraction.
				blobs: [String(Math.trunc(sanitizeNumber(event.shardIndex))), event.country ?? 'unknown', event.authTier ?? 'anon'],
			});
		},
		emitQueueBatchEvent: (event) => {
			safeWrite(dataset, {
				indexes: ['queue_batch'],
				blobs: [normalizeIndex(event.handler), event.outcome, event.country ?? 'unknown', event.authTier ?? 'anon'],
				doubles: [sanitizeNumber(event.durationMs), sanitizeNumber(event.failureCount), sanitizeNumber(event.messageCount)],
			});
		},
		emitTailAggregate: (event) => {
			safeWrite(dataset, {
				indexes: ['tail'],
				// blob1=colo, blob2=outcome, blob3=scriptName. colo is also mirrored
				// into the `country` blob slot (blob6, 'unknown'-padding the request
				// dimensions absent on a tail trace) so colo-grouped dashboards that
				// pivot on the country column still resolve.
				blobs: [
					normalizeIndex(event.colo),
					normalizeIndex(event.outcome),
					normalizeIndex(event.scriptName),
					'none',
					'unknown',
					normalizeIndex(event.colo),
					'unknown',
					'anon',
				],
				// double1=invocations folded into the bucket, double2=invocations that
				// surfaced ≥1 exception.
				doubles: [sanitizeNumber(event.invocations), sanitizeNumber(event.exceptions)],
			});
		},
	};
}

function safeWrite(
	dataset: AnalyticsDatasetLike,
	point: {
		indexes?: string[];
		blobs?: string[];
		doubles?: number[];
	},
): void {
	try {
		dataset.writeDataPoint(point);
	} catch (err) {
		logError(err instanceof Error ? err : String(err), {
			severity: 'warn',
			category: 'analytics',
			details: {
				event: point.indexes?.[0] ?? 'unknown',
			},
		});
	}
}

function normalizeIndex(value: string): string {
	return value.trim().toLowerCase().slice(0, 64) || 'unknown';
}

function sanitizeNumber(value: number): number {
	return Number.isFinite(value) ? Math.max(0, value) : 0;
}

/**
 * Computes a stable 32-bit fingerprint for aggregate grouping.
 * Not a privacy control — FNV-1a is trivially reversible for known domain sets.
 */
export function hashDomain(domain: string): string {
	return fnv1aHash(domain, 'd_');
}

function domainFingerprint(domain: string): string {
	return hashDomain(domain);
}

/**
 * FNV-1a hash for session ID anonymization.
 * Exported for use in index.ts; prefixed with 's_' to distinguish from domain hashes.
 */
export function hashForAnalytics(value: string): string {
	return fnv1aHash(value, 's_');
}

/**
 * FNV-1a hash for cf-connecting-ip — `i_` prefix to distinguish from session/domain hashes.
 * Lossy aggregation key; not a security control. See AnalyticsContext.ipHash for rationale.
 */
export function hashIpForAnalytics(ip: string): string {
	return fnv1aHash(ip, 'i_');
}

/** Shared FNV-1a hash with configurable prefix. */
function fnv1aHash(value: string, prefix: string): string {
	let hash = 0x811c9dc5;
	const normalized = value.trim().toLowerCase();
	for (let i = 0; i < normalized.length; i += 1) {
		hash ^= normalized.charCodeAt(i);
		hash = Math.imul(hash, 0x01000193);
	}
	return `${prefix}${(hash >>> 0).toString(16)}`;
}
