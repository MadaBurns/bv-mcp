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
		action: 'created' | 'terminated';
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
		return { enabled: false, emitRequestEvent: noop, emitToolEvent: noop, emitRateLimitEvent: noop, emitSessionEvent: noop };
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
				],
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
function domainFingerprint(domain: string): string {
	return fnv1aHash(domain, 'd_');
}

/**
 * FNV-1a hash for session ID anonymization.
 * Exported for use in index.ts; prefixed with 's_' to distinguish from domain hashes.
 */
export function hashForAnalytics(value: string): string {
	return fnv1aHash(value, 's_');
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
