// SPDX-License-Identifier: BUSL-1.1

/**
 * Cloudflare Analytics Engine helpers.
 *
 * All emits are fail-open: write errors are logged and ignored so MCP flows
 * are never blocked by telemetry issues.
 */

import { logError } from './log';

/** Minimal shape used by Cloudflare Analytics Engine dataset bindings. */
interface AnalyticsDatasetLike {
	writeDataPoint: (point: {
		indexes?: string[];
		blobs?: string[];
		doubles?: number[];
	}) => void;
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
	}): void;
	emitToolEvent(event: {
		toolName: string;
		status: 'pass' | 'fail' | 'error' | 'unknown';
		durationMs: number;
		domain?: string;
		isError: boolean;
	}): void;
}

/**
 * Build an analytics client from the optional dataset binding.
 * If the binding is unavailable, emit functions become no-ops.
 */
export function createAnalyticsClient(dataset?: AnalyticsDatasetLike): AnalyticsClient {
	if (!dataset) {
		return {
			enabled: false,
			emitRequestEvent: () => {
				// no-op when analytics dataset is not configured
			},
			emitToolEvent: () => {
				// no-op when analytics dataset is not configured
			},
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
					event.domain ? hashDomain(event.domain) : 'none',
				],
				doubles: [sanitizeNumber(event.durationMs)],
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
 * FNV-1a hash for domain anonymization before analytics emission.
 * Not cryptographic, but stable and adequate for aggregate reporting.
 */
function hashDomain(domain: string): string {
	let hash = 0x811c9dc5;
	const normalized = domain.trim().toLowerCase();
	for (let i = 0; i < normalized.length; i += 1) {
		hash ^= normalized.charCodeAt(i);
		hash = Math.imul(hash, 0x01000193);
	}
	return `d_${(hash >>> 0).toString(16)}`;
}
