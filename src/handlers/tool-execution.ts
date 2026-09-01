// SPDX-License-Identifier: BUSL-1.1

import { logEvent, logError } from '../lib/log';
import type { AnalyticsClient, ToolOutcomeReason } from '../lib/analytics';
import type { McpClientType } from '../lib/client-detection';

/**
 * `'inconclusive'` = the tool ran without erroring but produced no gradeable
 * measurement (an ungraded scan). Analytics-only; labelling it `'fail'` would
 * record every unmeasured scan as a failure — the same fabrication one layer down.
 */
type ToolSuccessStatus = 'pass' | 'fail' | 'inconclusive';
type ToolFailureSeverity = 'warn' | 'error';

function summarizeToolArgs(args: Record<string, unknown>): { argumentCount: number; argumentKeys: string[] } {
	const argumentKeys = Object.keys(args)
		.filter((key) => /^[A-Za-z0-9_-]{1,64}$/.test(key))
		.sort()
		.slice(0, 32);
	return { argumentCount: Object.keys(args).length, argumentKeys };
}

interface ToolExecutionBase {
	toolName: string;
	durationMs: number;
	domain?: string;
	analytics?: AnalyticsClient;
	country?: string;
	clientType?: McpClientType;
	authTier?: string;
	score?: number;
	cacheStatus?: 'hit' | 'miss' | 'n/a';
	keyHash?: string;
	/** Cloudflare edge colo for per-datacenter tool_call analytics grouping. */
	colo?: string;
	/** Geo enrichment (request.cf) for the tool_call AE geo blobs. */
	region?: string;
	city?: string;
	asn?: number;
	/**
	 * blob12 — canonical name of the tool invoked immediately before this one
	 * in the same MCP session. Resolved synchronously by readAndUpdateLastTool
	 * before dispatch; 'none' on first call, 'unknown' when continuity is absent.
	 */
	priorTool?: string;
	/** Privacy-safe terminal classification and bounded work counters for AE. */
	outcomeReason?: ToolOutcomeReason;
	unitsAttempted?: number;
	unitsCompleted?: number;
}

/** Collapse error details to a fixed, privacy-safe analytics vocabulary. */
function classifyToolFailure(error: unknown, domain?: string): ToolOutcomeReason {
	const err = error instanceof Error ? error : undefined;
	const text = `${err?.name ?? ''} ${err?.message ?? String(error)}`.toLowerCase();
	if (!domain && /(invalid|required|validation|argument|schema|parse)/.test(text)) return 'input_error';
	if (/batch[_ -]?budget|budget[_ -]?exceeded/.test(text)) return 'batch_budget_exceeded';
	if (/scan[_ -]?timeout|scan deadline|scan timed out/.test(text)) return 'scan_timeout';
	if (/429|rate[_ -]?limit|too many requests/.test(text)) return 'upstream_rate_limited';
	if (/client.*abort|disconnect|request.*abort/.test(text)) return 'client_aborted';
	if (err?.name === 'AbortError' || /timed? ?out|timeout|deadline/.test(text)) return 'upstream_timeout';
	return !domain ? 'input_error' : 'internal_error';
}

/**
 * Build the common ToolExecutionBase fields from handler-level variables.
 * Eliminates repeating these 8 fields at every logToolSuccess / logToolFailure call site.
 */
export function buildLogContext(
	toolName: string,
	startTime: number,
	domain: string | undefined,
	runtimeOptions?: {
		analytics?: AnalyticsClient;
		country?: string;
		clientType?: string;
		authTier?: string;
		analyticsKeyHash?: string;
		colo?: string;
		region?: string;
		city?: string;
		asn?: number;
		priorTool?: string;
	},
): ToolExecutionBase {
	return {
		toolName,
		durationMs: Date.now() - startTime,
		domain,
		analytics: runtimeOptions?.analytics,
		country: runtimeOptions?.country,
		clientType: runtimeOptions?.clientType as McpClientType,
		authTier: runtimeOptions?.authTier,
		keyHash: runtimeOptions?.analyticsKeyHash,
		colo: runtimeOptions?.colo,
		region: runtimeOptions?.region,
		city: runtimeOptions?.city,
		asn: runtimeOptions?.asn,
		priorTool: runtimeOptions?.priorTool,
	};
}

export function logToolSuccess(
	options: ToolExecutionBase & {
		status: ToolSuccessStatus;
		logResult: string;
		logDetails: unknown;
		severity?: 'info' | 'warn';
	},
): void {
	options.analytics?.emitToolEvent({
		toolName: options.toolName,
		status: options.status,
		durationMs: options.durationMs,
		domain: options.domain,
		isError: false,
		score: options.score,
		cacheStatus: options.cacheStatus,
		country: options.country,
		clientType: options.clientType,
		authTier: options.authTier,
		keyHash: options.keyHash,
		colo: options.colo,
		region: options.region,
		city: options.city,
		asn: options.asn,
		priorTool: options.priorTool,
		outcomeReason: options.outcomeReason ?? 'completed',
		unitsAttempted: options.unitsAttempted,
		unitsCompleted: options.unitsCompleted,
	});

	logEvent({
		timestamp: new Date().toISOString(),
		tool: options.toolName,
		domain: options.domain,
		result: options.logResult,
		details: options.logDetails,
		durationMs: options.durationMs,
		severity: options.severity ?? (options.status === 'pass' ? 'info' : 'warn'),
	});
}

export function logToolFailure(
	options: ToolExecutionBase & {
		error: unknown;
		args: Record<string, unknown>;
		severity?: ToolFailureSeverity;
	},
): void {
	options.analytics?.emitToolEvent({
		toolName: options.toolName,
		status: 'error',
		durationMs: options.durationMs,
		domain: options.domain,
		isError: true,
		score: options.score,
		cacheStatus: options.cacheStatus,
		country: options.country,
		clientType: options.clientType,
		authTier: options.authTier,
		keyHash: options.keyHash,
		colo: options.colo,
		region: options.region,
		city: options.city,
		asn: options.asn,
		priorTool: options.priorTool,
		outcomeReason: classifyToolFailure(options.error, options.domain),
	});

	logError(options.error instanceof Error ? options.error : String(options.error), {
		tool: options.toolName,
		domain: options.domain,
		details: summarizeToolArgs(options.args),
		severity: options.severity ?? 'error',
	});
}
