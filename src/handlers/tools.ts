// SPDX-License-Identifier: BUSL-1.1

import type { CheckResult } from '../lib/scoring';
import type { QueryDnsOptions, SecondaryDohConfig } from '../lib/dns-types';
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
import { checkBimi } from '../tools/check-bimi';
import { checkTlsrpt } from '../tools/check-tlsrpt';
import { checkLookalikes } from '../tools/check-lookalikes';
import { checkShadowDomains } from '../tools/check-shadow-domains';
import { checkTxtHygiene } from '../tools/check-txt-hygiene';
import { checkHttpSecurity } from '../tools/check-http-security';
import { checkDane } from '../tools/check-dane';
import { checkMxReputation } from '../tools/check-mx-reputation';
import { checkSrv } from '../tools/check-srv';
import { checkZoneHygiene } from '../tools/check-zone-hygiene';
import { scanDomain, formatScanReport, buildStructuredScanResult } from '../tools/scan-domain';
import { explainFinding, formatExplanation } from '../tools/explain-finding';
import { compareBaseline, formatBaselineResult } from '../tools/compare-baseline';
import type { PolicyBaseline } from '../tools/compare-baseline';
import type { AnalyticsClient } from '../lib/analytics';
import { extractAndValidateDomain, extractBaseline, extractDkimSelector, extractExplainFindingArgs, extractScanProfile, normalizeToolName } from './tool-args';
import { logToolFailure, logToolSuccess } from './tool-execution';
import { formatCheckResult, mcpError, mcpText } from './tool-formatters';
import type { McpContent } from './tool-formatters';
import { TOOLS } from './tool-schemas';
import type { McpTool } from './tool-schemas';

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

/** Wrapper for dynamic check_mx import (required for test mock isolation) */
interface ToolRuntimeOptions {
	providerSignaturesUrl?: string;
	providerSignaturesAllowedHosts?: string[];
	providerSignaturesSha256?: string;
	analytics?: AnalyticsClient;
	profileAccumulator?: DurableObjectNamespace;
	waitUntil?: (promise: Promise<unknown>) => void;
	scoringConfig?: import('../lib/scoring-config').ScoringConfig;
	/** When provided, receives the raw CheckResult before MCP text formatting. Used by internal structured response mode. */
	resultCapture?: (result: CheckResult) => void;
	/** Override cache TTL in seconds for scan results. Threaded to scanDomain. */
	cacheTtlSeconds?: number;
	/** Custom secondary DoH resolver config (bv-dns). Threaded to dnsOptions for individual checks. */
	secondaryDoh?: SecondaryDohConfig;
	country?: string;
	clientType?: string;
	authTier?: string;
}

/** Build QueryDnsOptions for individual check calls from runtime options. */
function buildDnsOptions(runtimeOptions?: ToolRuntimeOptions): QueryDnsOptions | undefined {
	if (!runtimeOptions?.secondaryDoh) return undefined;
	return { secondaryDoh: runtimeOptions.secondaryDoh };
}

async function dynamicCheckMx(domain: string, runtimeOptions?: ToolRuntimeOptions): Promise<CheckResult> {
	const { checkMx } = await import('../tools/check-mx');
	return checkMx(domain, {
		providerSignaturesUrl: runtimeOptions?.providerSignaturesUrl,
		providerSignaturesAllowedHosts: runtimeOptions?.providerSignaturesAllowedHosts,
		providerSignaturesSha256: runtimeOptions?.providerSignaturesSha256,
	}, buildDnsOptions(runtimeOptions));
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
		cacheTtlSeconds?: number;
	}
> = {
	check_mx: { cacheKey: () => 'mx', execute: (d, _args, ro) => dynamicCheckMx(d, ro) },
	check_spf: { cacheKey: () => 'spf', execute: (d, _args, ro) => checkSpf(d, buildDnsOptions(ro)) },
	check_dmarc: { cacheKey: () => 'dmarc', execute: (d, _args, ro) => checkDmarc(d, buildDnsOptions(ro)) },
	check_dkim: {
		cacheKey: (args) => {
			const sel = extractDkimSelector(args);
			return sel ? `dkim:${sel}` : 'dkim';
		},
		execute: (d, args, ro) => checkDkim(d, extractDkimSelector(args), buildDnsOptions(ro)),
	},
	check_dnssec: { cacheKey: () => 'dnssec', execute: (d, _args, ro) => checkDnssec(d, buildDnsOptions(ro)) },
	check_ssl: { cacheKey: () => 'ssl', execute: (d) => checkSsl(d) },
	check_mta_sts: { cacheKey: () => 'mta_sts', execute: (d, _args, ro) => checkMtaSts(d, buildDnsOptions(ro)) },
	check_ns: { cacheKey: () => 'ns', execute: (d, _args, ro) => checkNs(d, buildDnsOptions(ro)) },
	check_caa: { cacheKey: () => 'caa', execute: (d, _args, ro) => checkCaa(d, buildDnsOptions(ro)) },
	check_bimi: { cacheKey: () => 'bimi', execute: (d, _args, ro) => checkBimi(d, buildDnsOptions(ro)) },
	check_tlsrpt: { cacheKey: () => 'tlsrpt', execute: (d, _args, ro) => checkTlsrpt(d, buildDnsOptions(ro)) },
	check_lookalikes: { cacheKey: () => 'lookalikes', execute: (d) => checkLookalikes(d), cacheTtlSeconds: 3600 },
	check_shadow_domains: { cacheKey: () => 'shadow_domains', execute: (d, _args, ro) => checkShadowDomains(d, buildDnsOptions(ro)), cacheTtlSeconds: 3600 },
	check_txt_hygiene: { cacheKey: () => 'txt_hygiene', execute: (d, _args, ro) => checkTxtHygiene(d, buildDnsOptions(ro)) },
	check_http_security: { cacheKey: () => 'http_security', execute: (d) => checkHttpSecurity(d) },
	check_dane: { cacheKey: () => 'dane', execute: (d, _args, ro) => checkDane(d, buildDnsOptions(ro)) },
	check_mx_reputation: { cacheKey: () => 'mx_reputation', execute: (d, _args, ro) => checkMxReputation(d, buildDnsOptions(ro)), cacheTtlSeconds: 3600 },
	check_srv: { cacheKey: () => 'srv', execute: (d, _args, ro) => checkSrv(d, buildDnsOptions(ro)) },
	check_zone_hygiene: { cacheKey: () => 'zone_hygiene', execute: (d, _args, ro) => checkZoneHygiene(d, buildDnsOptions(ro)) },
};

function buildToolErrorResult(message: string): McpToolResult {
	return { content: [mcpError(message)], isError: true };
}

function handleExplainFindingValidationError(
	args: Record<string, unknown>,
	durationMs: number,
	runtimeOptions?: ToolRuntimeOptions,
): McpToolResult {
	const error = new Error('Missing required parameters: checkType and status');
	logToolFailure({
		toolName: 'explain_finding',
		durationMs,
		analytics: runtimeOptions?.analytics,
		error,
		args,
		severity: 'warn',
		country: runtimeOptions?.country,
		clientType: runtimeOptions?.clientType as import('../lib/client-detection').McpClientType,
		authTier: runtimeOptions?.authTier,
	});
	return buildToolErrorResult(error.message);
}

/**
 * Handle the MCP tools/call method.
 * Dispatches to the appropriate tool function based on the tool name.
 *
 * @param params - Tool call parameters (name and arguments)
 * @param scanCacheKV - Optional KV namespace for scan result caching
 */
/** Maximum wall-clock time for any single tool call (ms). */
const TOOL_CALL_TIMEOUT_MS = 28_000;

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

		const executeDispatch = async (): Promise<McpToolResult> => {
			// Dispatch to the appropriate tool — check registry first, then special cases
			const registeredTool = TOOL_REGISTRY[name];
			if (registeredTool) {
				const checkName = registeredTool.cacheKey(args);
				const cacheKey = `cache:${validDomain}:check:${checkName}`;
				const result = await runWithCache(cacheKey, () => registeredTool.execute(validDomain, args, runtimeOptions), scanCacheKV, registeredTool.cacheTtlSeconds);
				runtimeOptions?.resultCapture?.(result);
				logResult = result.passed ? 'pass' : 'fail';
				logDetails = result;
				logToolSuccess({
					toolName: name,
					durationMs: Date.now() - startTime,
					domain,
					analytics: runtimeOptions?.analytics,
					status: result.passed ? 'pass' : 'fail',
					logResult,
					logDetails,
					country: runtimeOptions?.country,
					clientType: runtimeOptions?.clientType as import('../lib/client-detection').McpClientType,
					authTier: runtimeOptions?.authTier,
				});
				return { content: [mcpText(formatCheckResult(result))] };
			}

			switch (name) {
				case 'scan_domain': {
					const profile = extractScanProfile(args);
					const scanOptions = profile ? { ...runtimeOptions, profile } : runtimeOptions;
					const result = await scanDomain(validDomain, scanCacheKV, scanOptions);
					logResult = result.score.grade;
					logDetails = result;
					logToolSuccess({
						toolName: name,
						durationMs: Date.now() - startTime,
						domain,
						analytics: runtimeOptions?.analytics,
						status: result.score.overall >= 50 ? 'pass' : 'fail',
						logResult,
						logDetails,
						severity: 'info',
						country: runtimeOptions?.country,
						clientType: runtimeOptions?.clientType as import('../lib/client-detection').McpClientType,
						authTier: runtimeOptions?.authTier,
					});
					const structured = buildStructuredScanResult(result);
					return {
						content: [
							mcpText(formatScanReport(result)),
							mcpText(`<!-- STRUCTURED_RESULT\n${JSON.stringify(structured)}\nSTRUCTURED_RESULT -->`),
						],
					};
				}
				case 'compare_baseline': {
					const baseline = extractBaseline(args) as PolicyBaseline;
					const scan = await scanDomain(validDomain, scanCacheKV, runtimeOptions);
					const result = compareBaseline(scan, baseline);
					logResult = result.passed ? 'pass' : 'fail';
					logDetails = result;
					logToolSuccess({
						toolName: name,
						durationMs: Date.now() - startTime,
						domain,
						analytics: runtimeOptions?.analytics,
						status: result.passed ? 'pass' : 'fail',
						logResult,
						logDetails,
						severity: 'info',
						country: runtimeOptions?.country,
						clientType: runtimeOptions?.clientType as import('../lib/client-detection').McpClientType,
						authTier: runtimeOptions?.authTier,
					});
					return { content: [mcpText(formatBaselineResult(result))] };
				}
				case 'explain_finding': {
					let explainArgs: ReturnType<typeof extractExplainFindingArgs>;
					try {
						explainArgs = extractExplainFindingArgs(args);
					} catch {
						return handleExplainFindingValidationError(args, Date.now() - startTime, runtimeOptions);
					}
					const { checkType, status, details } = explainArgs;
					const result = explainFinding(checkType, status, details);
					logToolSuccess({
						toolName: name,
						durationMs: Date.now() - startTime,
						analytics: runtimeOptions?.analytics,
						status: 'pass',
						logResult: status,
						logDetails: { checkType, details },
						severity: 'info',
						country: runtimeOptions?.country,
						clientType: runtimeOptions?.clientType as import('../lib/client-detection').McpClientType,
						authTier: runtimeOptions?.authTier,
					});
					return { content: [mcpText(formatExplanation(result))] };
				}
				default:
					logToolFailure({
						toolName: name,
						durationMs: Date.now() - startTime,
						domain,
						analytics: runtimeOptions?.analytics,
						error: `Unknown tool: ${name}`,
						args,
						country: runtimeOptions?.country,
						clientType: runtimeOptions?.clientType as import('../lib/client-detection').McpClientType,
						authTier: runtimeOptions?.authTier,
					});
					return buildToolErrorResult(`Unknown tool: ${name}`);
			}
		};

		return await Promise.race([
			executeDispatch(),
			new Promise<never>((_, reject) => setTimeout(() => reject(new Error('__tool_timeout__')), TOOL_CALL_TIMEOUT_MS)),
		]);
	} catch (err) {
		if (err instanceof Error && err.message === '__tool_timeout__') {
			logToolFailure({
				toolName: name,
				durationMs: Date.now() - startTime,
				domain,
				analytics: runtimeOptions?.analytics,
				error: 'Tool call timed out',
				args,
				country: runtimeOptions?.country,
				clientType: runtimeOptions?.clientType as import('../lib/client-detection').McpClientType,
				authTier: runtimeOptions?.authTier,
			});
			return {
				content: [mcpError(`${name} timed out after ${TOOL_CALL_TIMEOUT_MS / 1000}s. Try a simpler check or retry — cached partial results make retries faster.`)],
				isError: true,
			};
		}
		const message = sanitizeErrorMessage(err, 'An unexpected error occurred');
		logToolFailure({
			toolName: name,
			durationMs: Date.now() - startTime,
			domain,
			analytics: runtimeOptions?.analytics,
			error: err,
			args,
			country: runtimeOptions?.country,
			clientType: runtimeOptions?.clientType as import('../lib/client-detection').McpClientType,
			authTier: runtimeOptions?.authTier,
		});
		return buildToolErrorResult(message);
	}
}
