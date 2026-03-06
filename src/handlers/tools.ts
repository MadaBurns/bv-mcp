/**
 * MCP Tools handler for Blackveil DNS.
 * Dispatches tools/call requests to the appropriate check functions.
 *
 * Handles JSON-RPC methods: tools/list, tools/call
 * Compatible with Cloudflare Workers runtime (no Node.js APIs).
 */

import { validateDomain, sanitizeDomain } from '../lib/sanitize';
import type { CheckResult } from '../lib/scoring';
import { runWithCache } from '../lib/cache';
import { sanitizeErrorMessage } from '../lib/json-rpc';
import { checkSpf } from '../tools/check-spf';
import { checkDmarc } from '../tools/check-dmarc';
import { checkDkim } from '../tools/check-dkim';
import { checkDnssec } from '../tools/check-dnssec';
import { checkSsl } from '../tools/check-ssl';
import { checkMtaSts } from '../tools/check-mta-sts';
import { checkNs } from '../tools/check-ns';
import { checkCaa } from '../tools/check-caa';
import { scanDomain, formatScanReport } from '../tools/scan-domain';
import { explainFinding, formatExplanation, resolveImpactNarrative } from '../tools/explain-finding';
import { logEvent, logError } from '../lib/log';
import type { AnalyticsClient } from '../lib/analytics';
import { TOOLS } from './tool-schemas';
import type { McpTool } from './tool-schemas';

const TOOL_ALIASES: Record<string, string> = {
	scan: 'scan_domain',
};

function normalizeToolName(name: string): string {
	const normalized = name.trim().toLowerCase();
	return TOOL_ALIASES[normalized] ?? normalized;
}

/** Create an MCP-compatible error content response. */
function mcpError(message: string): { type: 'text'; text: string } {
	return { type: 'text' as const, text: `Error: ${message}` };
}

/** Create an MCP-compatible success content response. */
function mcpText(text: string): { type: 'text'; text: string } {
	return { type: 'text' as const, text };
}

/** MCP content item */
interface McpContent {
	type: 'text';
	text: string;
}

/** MCP tools/call result */
interface McpToolResult {
	content: McpContent[];
	isError?: boolean;
}

/**
 * Handle the MCP tools/list method.
 * Returns all available tool definitions.
 */
export function handleToolsList(): { tools: McpTool[] } {
	return { tools: TOOLS };
}

/**
 * Validate a domain parameter from tool arguments.
 * Returns the sanitized domain or throws with an MCP error message.
 */
function extractAndValidateDomain(args: Record<string, unknown>): string {
	const domain = args.domain;
	if (typeof domain !== 'string' || domain.trim().length === 0) {
		throw new Error('Missing required parameter: domain');
	}
	const validation = validateDomain(domain);
	if (!validation.valid) {
		throw new Error(validation.error ?? 'Invalid domain');
	}
	return sanitizeDomain(domain);
}

/**
 * Extract and validate an optional DKIM selector from tool arguments.
 * Returns the validated selector string, or undefined if not provided.
 * Throws if the selector is present but invalid.
 */
function extractDkimSelector(args: Record<string, unknown>): string | undefined {
	if (typeof args.selector !== 'string' || args.selector.trim().length === 0) {
		return undefined;
	}
	const sel = args.selector.trim().toLowerCase();
	// Validate selector as a DNS label: alphanumeric + hyphens, max 63 chars
	if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(sel) || sel.length > 63) {
		throw new Error('Invalid DKIM selector: must be a valid DNS label (alphanumeric and hyphens, max 63 chars)');
	}
	return sel;
}

/** Wrapper for dynamic check_mx import (required for test mock isolation) */
interface ToolRuntimeOptions {
	providerSignaturesUrl?: string;
	analytics?: AnalyticsClient;
}

async function dynamicCheckMx(domain: string, runtimeOptions?: ToolRuntimeOptions): Promise<CheckResult> {
	const { checkMx } = await import('../tools/check-mx');
	return checkMx(domain, { providerSignaturesUrl: runtimeOptions?.providerSignaturesUrl });
}

/**
 * Registry mapping tool names to their cache key and execution function.
 * Replaces repetitive switch cases for individual DNS check tools.
 */
const TOOL_REGISTRY: Record<
	string,
	{
		cacheKey: (args: Record<string, unknown>) => string;
		execute: (domain: string, args: Record<string, unknown>, runtimeOptions?: ToolRuntimeOptions) => Promise<CheckResult>;
	}
> = {
	check_mx: { cacheKey: () => 'mx', execute: (d, _args, runtimeOptions) => dynamicCheckMx(d, runtimeOptions) },
	check_spf: { cacheKey: () => 'spf', execute: (d) => checkSpf(d) },
	check_dmarc: { cacheKey: () => 'dmarc', execute: (d) => checkDmarc(d) },
	check_dkim: {
		cacheKey: (args) => {
			const sel = extractDkimSelector(args);
			return sel ? `dkim:${sel}` : 'dkim';
		},
		execute: (d, args) => checkDkim(d, extractDkimSelector(args)),
	},
	check_dnssec: { cacheKey: () => 'dnssec', execute: (d) => checkDnssec(d) },
	check_ssl: { cacheKey: () => 'ssl', execute: (d) => checkSsl(d) },
	check_mta_sts: { cacheKey: () => 'mta_sts', execute: (d) => checkMtaSts(d) },
	check_ns: { cacheKey: () => 'ns', execute: (d) => checkNs(d) },
	check_caa: { cacheKey: () => 'caa', execute: (d) => checkCaa(d) },
};

/**
 * Format a CheckResult into MCP text content.
 */
function formatCheckResult(result: CheckResult): string {
	const lines: string[] = [];
	lines.push(`## ${result.category.toUpperCase()} Check`);
	lines.push(`**Status:** ${result.passed ? '✅ Passed' : '❌ Failed'}`);
	lines.push(`**Score:** ${result.score}/100`);
	lines.push('');

	if (result.findings.length > 0) {
		lines.push('### Findings');
		for (const finding of result.findings) {
			const icon =
				finding.severity === 'info'
					? 'ℹ️'
					: finding.severity === 'low'
						? '⚠️'
						: finding.severity === 'medium'
							? '🔶'
							: finding.severity === 'high'
								? '🔴'
								: '🚨';
			lines.push(`- ${icon} **[${finding.severity.toUpperCase()}]** ${finding.title}`);
			lines.push(`  ${finding.detail}`);

			if (finding.severity !== 'info') {
				const narrative = resolveImpactNarrative({
					category: finding.category,
					severity: finding.severity,
					title: finding.title,
					detail: finding.detail,
				});
				if (narrative.impact) {
					lines.push(`  Potential Impact: ${narrative.impact}`);
				}
				if (narrative.adverseConsequences) {
					lines.push(`  Adverse Consequences: ${narrative.adverseConsequences}`);
				}
			}
		}
	}

	return lines.join('\n');
}

/**
 * Handle the MCP tools/call method.
 * Dispatches to the appropriate tool function based on the tool name.
 *
 * @param params - Tool call parameters (name and arguments)
 * @param scanCacheKV - Optional KV namespace for scan result caching
 */
export async function handleToolsCall(
	params: {
		name: string;
		arguments?: Record<string, unknown>;
	},
	scanCacheKV?: KVNamespace,
	runtimeOptions?: ToolRuntimeOptions,
): Promise<McpToolResult> {
	const name = normalizeToolName(params.name);
	const args = params.arguments ?? {};
	const startTime = Date.now();
	let domain: string | undefined;
	let logResult: string | undefined;
	let logDetails: unknown;
	try {
		// Extract and validate domain for tools that need it (all except explain_finding)
		if (name !== 'explain_finding') {
			domain = extractAndValidateDomain(args);
		}
		// `validDomain` is guaranteed to be a string for all branches that use it
		const validDomain: string = domain ?? '';

		// Dispatch to the appropriate tool — check registry first, then special cases
		const registeredTool = TOOL_REGISTRY[name];
		if (registeredTool) {
			const checkName = registeredTool.cacheKey(args);
			const cacheKey = `cache:${validDomain}:check:${checkName}`;
			const result = await runWithCache(cacheKey, () => registeredTool.execute(validDomain, args, runtimeOptions), scanCacheKV);
			logResult = result.passed ? 'pass' : 'fail';
			logDetails = result;
			runtimeOptions?.analytics?.emitToolEvent({
				toolName: name,
				status: result.passed ? 'pass' : 'fail',
				durationMs: Date.now() - startTime,
				domain,
				isError: false,
			});
			logEvent({
				timestamp: new Date().toISOString(),
				tool: name,
				domain,
				result: logResult,
				details: logDetails,
				durationMs: Date.now() - startTime,
				severity: result.passed ? 'info' : 'warn',
			});
			return { content: [mcpText(formatCheckResult(result))] };
		}

		switch (name) {
			case 'scan_domain': {
				const result = await scanDomain(validDomain, scanCacheKV, runtimeOptions);
				logResult = result.score.grade;
				logDetails = result;
				runtimeOptions?.analytics?.emitToolEvent({
					toolName: name,
					status: result.score.overall >= 50 ? 'pass' : 'fail',
					durationMs: Date.now() - startTime,
					domain,
					isError: false,
				});
				logEvent({
					timestamp: new Date().toISOString(),
					tool: name,
					domain,
					result: logResult,
					details: logDetails,
					durationMs: Date.now() - startTime,
					severity: 'info',
				});
				return { content: [mcpText(formatScanReport(result))] };
			}
			case 'explain_finding': {
				const checkType = args.checkType;
				const status = args.status;
				if (typeof checkType !== 'string' || typeof status !== 'string') {
					runtimeOptions?.analytics?.emitToolEvent({
						toolName: name,
						status: 'error',
						durationMs: Date.now() - startTime,
						isError: true,
					});
					logError('Missing required parameters: checkType and status', {
						tool: name,
						details: args,
						severity: 'warn',
					});
					return { content: [mcpError('Missing required parameters: checkType and status')], isError: true };
				}
				const details = typeof args.details === 'string' ? args.details : undefined;
				const result = explainFinding(checkType, status, details);
				runtimeOptions?.analytics?.emitToolEvent({
					toolName: name,
					status: 'pass',
					durationMs: Date.now() - startTime,
					isError: false,
				});
				logEvent({
					timestamp: new Date().toISOString(),
					tool: name,
					result: status,
					details: { checkType, details },
					durationMs: Date.now() - startTime,
					severity: 'info',
				});
				return { content: [mcpText(formatExplanation(result))] };
			}
			default:
				runtimeOptions?.analytics?.emitToolEvent({
					toolName: name,
					status: 'error',
					durationMs: Date.now() - startTime,
					domain,
					isError: true,
				});
				logError(`Unknown tool: ${name}`, {
					tool: name,
					details: args,
					severity: 'error',
				});
				return {
					content: [mcpError(`Unknown tool: ${name}`)],
					isError: true,
				};
		}
	} catch (err) {
		const message = sanitizeErrorMessage(err, 'An unexpected error occurred');
		runtimeOptions?.analytics?.emitToolEvent({
			toolName: name,
			status: 'error',
			durationMs: Date.now() - startTime,
			domain,
			isError: true,
		});
		logError(err instanceof Error ? err : String(err), {
			tool: name,
			domain,
			details: args,
			severity: 'error',
		});
		return { content: [mcpError(message)], isError: true };
	}
}
