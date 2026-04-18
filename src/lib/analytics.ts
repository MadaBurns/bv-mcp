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

// ---------------------------------------------------------------------------
// Degradation dedup — isolate-local rolling window (Task 18)
// ---------------------------------------------------------------------------

const DEGRADATION_SEEN = new Map<string, number>(); // key → insertedAtMs
const DEGRADATION_WINDOW_MS = 60_000;

function degradationDedupKey(scanId: string | undefined, type: string, component: string): string {
	return `${scanId ?? ''}|${type}|${component}`;
}

function shouldEmitDegradation(scanId: string | undefined, type: string, component: string): boolean {
	if (!scanId) return true; // no dedup when scanId is missing
	const k = degradationDedupKey(scanId, type, component);
	const now = Date.now();
	for (const [existing, t] of DEGRADATION_SEEN) {
		if (now - t > DEGRADATION_WINDOW_MS) DEGRADATION_SEEN.delete(existing);
	}
	if (DEGRADATION_SEEN.has(k)) return false;
	DEGRADATION_SEEN.set(k, now);
	return true;
}

// ---------------------------------------------------------------------------
// FNV-1a collision probe — opportunistic, zero cost on uncontended paths (Task 19)
// ---------------------------------------------------------------------------

const FNV_HASH_SEEN = new Map<string, string>(); // hash → originalValue
const FNV_HASH_SEEN_MAX = 10_000;
let PENDING_COLLISION_FLAG = false;

function recordHash(value: string, hash: string): void {
	const cached = FNV_HASH_SEEN.get(hash);
	if (cached !== undefined && cached !== value) {
		PENDING_COLLISION_FLAG = true;
	} else if (cached === undefined) {
		FNV_HASH_SEEN.set(hash, value);
		if (FNV_HASH_SEEN.size > FNV_HASH_SEEN_MAX) {
			const firstKey = FNV_HASH_SEEN.keys().next().value;
			if (firstKey !== undefined) FNV_HASH_SEEN.delete(firstKey);
		}
	}
}

/**
 * Test-only helper: simulate a hash collision between existingValue and newValue.
 * Not used in production paths.
 */
export function __forceCollisionForTest(existingValue: string, newValue: string): void {
	for (const [h, v] of FNV_HASH_SEEN) {
		if (v === existingValue) {
			// Simulate a collision: a different value hashes to the same slot.
			recordHash(newValue, h);
			return;
		}
	}
}

/** Minimal shape used by Cloudflare Analytics Engine dataset bindings. */
interface AnalyticsDatasetLike {
	writeDataPoint: (point: {
		indexes?: string[];
		blobs?: string[];
		doubles?: number[];
	}) => void;
}

/** Enriched context dimensions threaded from the request handler. */
export interface AnalyticsContext {
	country?: string;
	clientType?: McpClientType;
	authTier?: string;
	sessionHash?: string;
	/** Truncated SHA-256 hash of the API key (first 16 chars). Enables per-customer analytics. */
	keyHash?: string;
}

export interface AnalyticsClient {
	enabled: boolean;
	emitRequestEvent(event: {
		method: string;
		status: 'ok' | 'error';
		durationMs: number;
		isAuthenticated: boolean;
		hasJsonRpcError: boolean;
		transport: 'json' | 'sse';
	} & AnalyticsContext): void;
	emitToolEvent(event: {
		toolName: string;
		status: 'pass' | 'fail' | 'error' | 'unknown';
		durationMs: number;
		domain?: string;
		isError: boolean;
		score?: number;
		cacheStatus?: 'hit' | 'miss' | 'n/a';
	} & AnalyticsContext): void;
	emitRateLimitEvent(event: {
		limitType: 'minute' | 'hour' | 'daily_tool' | 'daily_global';
		toolName: string;
		limit: number;
		remaining: number;
	} & AnalyticsContext): void;
	emitSessionEvent(event: {
		action: 'created' | 'terminated' | 'revived';
		method?: string;
	} & AnalyticsContext): void;
	emitDegradationEvent(event: {
		degradationType: 'dns_resolver_failure' | 'kv_fallback' | 'provider_detection_failure' | 'partial_result' | 'post_processing_error';
		component: string;
		domain?: string;
		/** Per-scan correlation ID for dedup of parallel check degradations (Task 18). */
		scanId?: string;
		/** Override collision flag directly (probe-only, not a migration). */
		hashCollisionSuspected?: boolean;
	} & AnalyticsContext): void;
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
		return { enabled: false, emitRequestEvent: noop, emitToolEvent: noop, emitRateLimitEvent: noop, emitSessionEvent: noop, emitDegradationEvent: noop };
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
				],
				doubles: [sanitizeNumber(event.durationMs)],
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
				],
				doubles: [sanitizeNumber(event.durationMs), sanitizeNumber(event.score ?? 0)],
			});
		},
		emitRateLimitEvent: (event) => {
			safeWrite(dataset, {
				indexes: ['rate_limit'],
				blobs: [
					event.limitType,
					normalizeIndex(event.toolName),
					event.country ?? 'unknown',
					event.authTier ?? 'anon',
				],
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
			if (!shouldEmitDegradation(event.scanId, event.degradationType, event.component)) return;
			const collision = PENDING_COLLISION_FLAG || Boolean(event.hashCollisionSuspected);
			PENDING_COLLISION_FLAG = false;
			safeWrite(dataset, {
				indexes: ['degradation'],
				blobs: [
					event.degradationType,
					normalizeIndex(event.component),
					event.domain ? domainFingerprint(event.domain) : 'none',
					event.scanId ?? '',
					event.country ?? 'unknown',
					event.clientType ?? 'unknown',
					event.authTier ?? 'anon',
				],
				doubles: [collision ? 1 : 0],
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
 *
 * Also exported as `hashDomain` for opportunistic collision probing (Task 19).
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

/** Shared FNV-1a hash with configurable prefix. Records result for collision probing (Task 19). */
function fnv1aHash(value: string, prefix: string): string {
	let hash = 0x811c9dc5;
	const normalized = value.trim().toLowerCase();
	for (let i = 0; i < normalized.length; i += 1) {
		hash ^= normalized.charCodeAt(i);
		hash = Math.imul(hash, 0x01000193);
	}
	const result = `${prefix}${(hash >>> 0).toString(16)}`;
	recordHash(normalized, result);
	return result;
}
