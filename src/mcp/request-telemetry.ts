// SPDX-License-Identifier: BUSL-1.1

/** Request analytics and fuzz-event telemetry, split out of execute.ts (no behaviour change). */

import { classifyError as classifyFuzzError } from '../lib/fuzzing-detector';
import { recordEvent as recordFuzzCounter } from '../lib/fuzzing-counter';
import type { ExecuteMcpRequestOptions } from './execute';

export function emitRequestAnalytics(
	options: ExecuteMcpRequestOptions,
	method: string,
	status: 'ok' | 'error',
	hasJsonRpcError: boolean,
	jsonRpcErrorCode?: number,
	jsonRpcErrorDescription?: string,
	httpStatus?: number,
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
		keyHash: options.analyticsKeyHash,
		ipHash: options.ipHash,
		colo: options.colo,
	});

	// Fuzzing-detection: record an event if the error matches a known fuzz pattern.
	// Best-effort and non-blocking — see docs/plans/2026-05-07-fuzzing-detection-tdd-plan.md.
	if (status === 'error' && options.rateLimitKv && (jsonRpcErrorCode !== undefined || httpStatus !== undefined)) {
		void recordFuzzEvent(options, method, jsonRpcErrorCode, jsonRpcErrorDescription, httpStatus);
	}
}

export async function recordFuzzEvent(
	options: ExecuteMcpRequestOptions,
	method: string,
	jsonRpcErrorCode: number | undefined,
	jsonRpcErrorDescription: string | undefined,
	httpStatus: number | undefined,
): Promise<void> {
	const dispatchPath = method === 'tools/call' ? 'tools/call' : 'dispatch';
	const kind = classifyFuzzError({
		jsonRpcCode: jsonRpcErrorCode,
		dispatchPath,
		description: jsonRpcErrorDescription,
		// auth_fail is classified from the HTTP status alone (auth fails outside JSON-RPC framing).
		httpStatus,
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
export function recordMcpToolErrorIfUnknownTool(options: ExecuteMcpRequestOptions, method: string, payload: unknown): void {
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
