// SPDX-License-Identifier: BUSL-1.1

/** Gate / quota denial response builders, split out of execute.ts (no behaviour change). */

import type { ToolDailyRateLimitResult } from '../lib/rate-limiter';
import { jsonRpcError, JSON_RPC_ERRORS } from '../lib/json-rpc';
import { buildUpgradeData, type McpApiKeyTier } from '../lib/config';
import { jsonRpcSuccess } from '../lib/json-rpc';
import { mcpError } from '../handlers/tool-formatters';
import type { JsonRpcRequest } from '../lib/json-rpc';
import type { ExecuteMcpRequestOptions, ProcessedRequestResult } from './execute';
import { recordMcpAccessLog } from './access-log';
import { emitRequestAnalytics, recordMcpToolErrorIfUnknownTool } from './request-telemetry';

/**
 * Reject an UNAUTHENTICATED tools/call for an auth-required tool (identity_secops
 * M365 reads) before dispatch. Returns HTTP 401 with the JSON-RPC UNAUTHORIZED
 * code and an allowlisted ("Invalid") message prefix so sanitizeErrorMessage
 * passes it through unchanged. Prevents an anon → bv-web-internal trust-boundary
 * breach (the proxy would otherwise carry the trusted internal bearer).
 */
export function buildAuthRequiredResponse(
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
	// 401: thread the HTTP status so the fuzz counter can classify it as `auth_fail`.
	emitRequestAnalytics(options, method, 'error', true, undefined, undefined, 401);
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

/** An authenticated key's tier daily counter that denied the call. */
export interface TierQuotaDenial {
	tier: McpApiKeyTier;
	/** The tool name for the per-tool counter, or AGGREGATE_QUOTA_COUNTER for the per-key total. */
	counter: string;
	limit: number;
	result: ToolDailyRateLimitResult;
	message: string;
}

/**
 * HTTP 429 for an authenticated key that exhausted a tier daily quota (per-tool or
 * the per-key total across all tools). `headers` already carry the x-quota-*
 * values for the counter that denied.
 */
export function buildTierQuotaExceededResponse(
	id: JsonRpcRequest['id'],
	denial: TierQuotaDenial,
	method: string,
	options: ExecuteMcpRequestOptions,
	headers: Record<string, string>,
	eventId: string | undefined,
	accessLogInput: { toolName: string; domain: string; method: string } | undefined,
): Extract<ProcessedRequestResult, { kind: 'response' }> {
	const responseHeaders = { ...headers };
	if (denial.result.retryAfterMs !== undefined) {
		responseHeaders['retry-after'] = String(Math.ceil(denial.result.retryAfterMs / 1000));
	}
	options.analytics?.emitRateLimitEvent({
		limitType: 'daily_tool',
		toolName: denial.counter,
		limit: denial.limit,
		remaining: 0,
		country: options.country,
		authTier: denial.tier,
	});
	emitRequestAnalytics(options, method, 'error', true);
	if (accessLogInput) {
		recordMcpAccessLog(options, { ...accessLogInput, rateLimited: true, status: 'unknown' });
	}
	return {
		kind: 'response',
		payload: jsonRpcError(id, JSON_RPC_ERRORS.RATE_LIMITED, denial.message),
		headers: responseHeaders,
		httpStatus: 429,
		useErrorEnvelope: true,
		eventId,
	};
}

export function buildGatedToolResponse(
	id: JsonRpcRequest['id'],
	toolName: string,
	method: string,
	options: ExecuteMcpRequestOptions,
	eventId: string | undefined,
	accessLogInput: { toolName: string; domain: string; method: string } | undefined,
	challenge?: string,
): Extract<ProcessedRequestResult, { kind: 'response' }> {
	options.analytics?.emitRateLimitEvent({
		limitType: 'gated_tool',
		toolName,
		limit: 0,
		remaining: 0,
		country: options.country,
		authTier: options.authTier ?? 'anon',
	});
	// An unauthenticated caller with an OAuth challenge gets 401: thread it to analytics so the
	// fuzz counter classifies it as `auth_fail`, as buildAuthRequiredResponse does.
	const httpStatus = challenge ? 401 : 403;
	emitRequestAnalytics(options, method, 'error', true, undefined, undefined, challenge ? 401 : undefined);
	if (accessLogInput) {
		recordMcpAccessLog(options, { ...accessLogInput, rateLimited: true, status: 'unknown' });
	}
	// Price-free human message + a structured `data.upgrade` affordance carrying the
	// channel (self_serve vs vetted sales) and its URL. Enumerating recon/OSINT tools
	// route to SALES so a paid plan alone never silently unlocks the enumeration
	// surface; a small curated set (SELF_SERVE_UPGRADE_TOOLS) routes to self-serve.
	// Keeping price/URL out of the prose and in `data` lets the copy stay stable while
	// the operator owns the destination URLs (PUBLIC-SURFACE).
	const upgradeData = buildUpgradeData(toolName);
	const message =
		upgradeData.upgrade.channel === 'self_serve'
			? `Upgrade required: ${toolName} requires a paid plan.`
			: `Upgrade required: ${toolName} is available on a vetted plan — contact us to enable it.`;
	return {
		kind: 'response',
		payload: jsonRpcError(id, JSON_RPC_ERRORS.UPGRADE_REQUIRED, message, upgradeData),
		headers: challenge ? { 'www-authenticate': challenge } : {},
		httpStatus,
		useErrorEnvelope: true,
		eventId,
	};
}

/**
 * Reject a PUBLIC `/mcp` tools/call for an INTERNAL-ONLY tool (e.g. map_registrar_products).
 *
 * Returns the SAME unknown-tool result a nonexistent tool name produces via the
 * dispatch path (handlers/tools.ts `default` case) — a JSON-RPC success wrapping a
 * countless tool-error result (no tool count that would hint a hidden tool) — so the
 * tool's existence is NOT leaked on the public surface and no 403/UPGRADE_REQUIRED is
 * emitted. executeMcpRequest is the public path only; the internal path
 * (src/internal.ts → handleToolsCall) bypasses this and remains fully callable,
 * as does the direct FUNCTION call from prioritize_portfolio_leads.
 */
export function buildInternalOnlyToolResponse(
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
