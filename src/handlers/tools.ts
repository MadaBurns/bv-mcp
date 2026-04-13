// SPDX-License-Identifier: BUSL-1.1

import type { CheckResult } from '../lib/scoring';
import type { QueryDnsOptions, SecondaryDohConfig } from '../lib/dns-types';
import { runWithCacheTracked, cacheDelete } from '../lib/cache';
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
import { checkDaneHttps } from '../tools/check-dane-https';
import { checkSvcbHttps } from '../tools/check-svcb-https';
import { checkMxReputation } from '../tools/check-mx-reputation';
import { checkSrv } from '../tools/check-srv';
import { checkZoneHygiene } from '../tools/check-zone-hygiene';
import { checkSubdomailing } from '../tools/check-subdomailing';
import { scanDomain, formatScanReport, buildStructuredScanResult } from '../tools/scan-domain';
import { batchScan, formatBatchScan } from '../tools/batch-scan';
import { compareDomains, formatDomainComparison } from '../tools/compare-domains';
import { explainFinding, formatExplanation } from '../tools/explain-finding';
import { compareBaseline, formatBaselineResult } from '../tools/compare-baseline';
import { generateFixPlan, formatFixPlan } from '../tools/generate-fix-plan';
import { generateSpfRecord, generateDmarcRecord, generateDkimConfig, generateMtaStsPolicy, formatGeneratedRecord } from '../tools/generate-records';
import { getBenchmark, getProviderInsights, formatBenchmark, formatProviderInsights } from '../tools/intelligence';
import { assessSpoofability, formatSpoofability } from '../tools/assess-spoofability';
import { checkResolverConsistency, formatResolverConsistency } from '../tools/check-resolver-consistency';
import { validateFix, formatValidateFix } from '../tools/validate-fix';
import { mapSupplyChain, formatSupplyChain } from '../tools/map-supply-chain';
import { generateRolloutPlan, formatRolloutPlan } from '../tools/generate-rollout-plan';
import { computeDrift, formatDriftReport } from '../tools/analyze-drift';
import { resolveSpfChain, formatSpfChain } from '../tools/resolve-spf-chain';
import { discoverSubdomains, formatSubdomainDiscovery } from '../tools/discover-subdomains';
import { mapCompliance, formatCompliance } from '../tools/map-compliance';
import { simulateAttackPaths, formatAttackPaths } from '../tools/simulate-attack-paths';
import { checkDbl } from '../tools/check-dbl';
import { checkRbl } from '../tools/check-rbl';
import { checkCymruAsn } from '../tools/check-cymru-asn';
import type { PolicyBaseline } from '../tools/compare-baseline';
import type { AnalyticsClient } from '../lib/analytics';
import { extractAndValidateDomain, extractBaseline, extractDkimSelector, extractExplainFindingArgs, extractForceRefresh, extractFormat, extractIncludeProviders, extractMxHosts, extractRecordType, extractScanProfile, normalizeToolName, validateToolArgs } from './tool-args';
import type { OutputFormat } from './tool-args';
import { buildLogContext, logToolFailure, logToolSuccess } from './tool-execution';
import { formatCheckResult, mcpError, buildToolContent } from './tool-formatters';
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
	keyHash?: string;
	certstream?: { fetch: typeof fetch };
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
	check_dane_https: { cacheKey: () => 'dane_https', execute: (d, _args, ro) => checkDaneHttps(d, buildDnsOptions(ro)) },
	check_svcb_https: { cacheKey: () => 'svcb_https', execute: (d, _args, ro) => checkSvcbHttps(d, buildDnsOptions(ro)) },
	check_mx_reputation: { cacheKey: () => 'mx_reputation', execute: (d, _args, ro) => checkMxReputation(d, buildDnsOptions(ro)), cacheTtlSeconds: 3600 },
	check_srv: { cacheKey: () => 'srv', execute: (d, _args, ro) => checkSrv(d, buildDnsOptions(ro)) },
	check_zone_hygiene: { cacheKey: () => 'zone_hygiene', execute: (d, _args, ro) => checkZoneHygiene(d, buildDnsOptions(ro)) },
	check_subdomailing: { cacheKey: () => 'subdomailing', execute: (d, _args, ro) => checkSubdomailing(d, buildDnsOptions(ro)) },
	check_dbl: { cacheKey: () => 'dbl', execute: (d, _args, ro) => checkDbl(d, buildDnsOptions(ro)), cacheTtlSeconds: 3600 },
	check_rbl: { cacheKey: () => 'rbl', execute: (d, _args, ro) => checkRbl(d, buildDnsOptions(ro)), cacheTtlSeconds: 3600 },
	cymru_asn: { cacheKey: () => 'asn', execute: (d, _args, ro) => checkCymruAsn(d, buildDnsOptions(ro)), cacheTtlSeconds: 3600 },
};

/** Known interactive LLM client types that benefit from compact output. */
const INTERACTIVE_CLIENTS = new Set(['claude_mobile', 'claude_code', 'cursor', 'vscode', 'claude_desktop', 'windsurf']);

/** Determine if the client type is a known interactive LLM IDE. */
function isInteractiveClient(clientType?: string): boolean {
	return INTERACTIVE_CLIENTS.has(clientType ?? '');
}

/** Resolve the effective output format from explicit parameter and client type. */
function resolveFormat(args: Record<string, unknown>, clientType?: string): OutputFormat {
	const explicit = extractFormat(args);
	if (explicit) return explicit;
	return isInteractiveClient(clientType) ? 'compact' : 'full';
}

function buildToolErrorResult(message: string): McpToolResult {
	return { content: [mcpError(message)], isError: true };
}

function handleExplainFindingValidationError(
	args: Record<string, unknown>,
	startTime: number,
	runtimeOptions?: ToolRuntimeOptions,
): McpToolResult {
	const error = new Error('Missing required parameters: checkType and status');
	logToolFailure({
		...buildLogContext('explain_finding', startTime, undefined, runtimeOptions),
		error,
		args,
		severity: 'warn',
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
	/** Lazy log context builder — evaluates durationMs at call time. */
	const ctx = () => buildLogContext(name, startTime, domain, runtimeOptions);
	let domain: string | undefined;
	let logResult = 'unknown';
	let logDetails: unknown;
	try {
		const validatedArgs = validateToolArgs(name, args);
		// Extract and validate domain for tools that need it
		// (skip for explain_finding, get_benchmark, get_provider_insights which don't require a domain)
		const DOMAIN_OPTIONAL_TOOLS = new Set(['explain_finding', 'get_benchmark', 'get_provider_insights', 'batch_scan', 'compare_domains']);
		if (!DOMAIN_OPTIONAL_TOOLS.has(name)) {
			domain = extractAndValidateDomain(validatedArgs);
		}
		// `validDomain` is guaranteed to be a string for all branches that use it
		const validDomain: string = domain ?? '';

		const effectiveFormat = resolveFormat(validatedArgs, runtimeOptions?.clientType);
		const _interactive = isInteractiveClient(runtimeOptions?.clientType);

		const executeDispatch = async (): Promise<McpToolResult> => {
			// Dispatch to the appropriate tool — check registry first, then special cases
			const registeredTool = TOOL_REGISTRY[name];
			if (registeredTool) {
				const checkName = registeredTool.cacheKey(validatedArgs);
				const cacheKey = `cache:${validDomain}:check:${checkName}`;
				const { data: result, cacheStatus } = await runWithCacheTracked(cacheKey, () => registeredTool.execute(validDomain, validatedArgs, runtimeOptions), scanCacheKV, registeredTool.cacheTtlSeconds);
				// Don't cache partial results (e.g. lookalike timeout) — evict what runWithCacheTracked just stored
				if (result.partial) {
					await cacheDelete(cacheKey, scanCacheKV);
				}
				runtimeOptions?.resultCapture?.(result);
				logResult = result.passed ? 'pass' : 'fail';
				logDetails = result;
				logToolSuccess({
					...ctx(),
					status: result.passed ? 'pass' : 'fail',
					logResult,
					logDetails,
					cacheStatus,
				});
				return { content: buildToolContent(formatCheckResult(result, effectiveFormat), result, effectiveFormat) };
			}

			switch (name) {
				case 'scan_domain': {
					const profile = extractScanProfile(validatedArgs);
					const forceRefresh = extractForceRefresh(validatedArgs);
					const scanOptions = { ...runtimeOptions, ...(profile && { profile }), ...(forceRefresh && { forceRefresh }) };
					const result = await scanDomain(validDomain, scanCacheKV, scanOptions);
					logResult = result.score.grade;
					logDetails = result;
					logToolSuccess({ ...ctx(), status: result.score.overall >= 50 ? 'pass' : 'fail', logResult, logDetails, severity: 'info' });
					const structured = buildStructuredScanResult(result);
					return { content: buildToolContent(formatScanReport(result, effectiveFormat), structured, effectiveFormat) };
				}
				case 'batch_scan': {
					const domains = validatedArgs.domains as string[];
					const forceRefresh = extractForceRefresh(validatedArgs);
					const batchResults = await batchScan(domains, {
						force_refresh: forceRefresh,
						kv: scanCacheKV,
						runtimeOptions: {
							providerSignaturesUrl: runtimeOptions?.providerSignaturesUrl,
							providerSignaturesAllowedHosts: runtimeOptions?.providerSignaturesAllowedHosts,
							providerSignaturesSha256: runtimeOptions?.providerSignaturesSha256,
							scoringConfig: runtimeOptions?.scoringConfig,
							waitUntil: runtimeOptions?.waitUntil,
							profileAccumulator: runtimeOptions?.profileAccumulator,
							secondaryDoh: runtimeOptions?.secondaryDoh,
						},
					});
					const batchText = formatBatchScan(batchResults, effectiveFormat);
					logToolSuccess({ ...ctx(), status: 'pass', logResult: `${batchResults.filter((r) => !r.error).length}/${batchResults.length} domains`, logDetails: { totalDomains: batchResults.length }, severity: 'info' });
					return { content: buildToolContent(batchText, batchResults, effectiveFormat) };
				}
				case 'compare_domains': {
					const domains = validatedArgs.domains as string[];
					const compareResults = await compareDomains(domains, {
						kv: scanCacheKV,
						runtimeOptions: {
							providerSignaturesUrl: runtimeOptions?.providerSignaturesUrl,
							providerSignaturesAllowedHosts: runtimeOptions?.providerSignaturesAllowedHosts,
							providerSignaturesSha256: runtimeOptions?.providerSignaturesSha256,
							scoringConfig: runtimeOptions?.scoringConfig,
							waitUntil: runtimeOptions?.waitUntil,
							profileAccumulator: runtimeOptions?.profileAccumulator,
							secondaryDoh: runtimeOptions?.secondaryDoh,
						},
					});
					const compareText = formatDomainComparison(compareResults, effectiveFormat);
					logToolSuccess({ ...ctx(), status: 'pass', logResult: `${Object.keys(compareResults.scores).length}/${compareResults.domains.length} domains compared`, logDetails: { totalDomains: compareResults.domains.length, winner: compareResults.winner }, severity: 'info' });
					return { content: buildToolContent(compareText, compareResults, effectiveFormat) };
				}
				case 'compare_baseline': {
					const baseline = extractBaseline(validatedArgs) as PolicyBaseline;
					const scan = await scanDomain(validDomain, scanCacheKV, runtimeOptions);
					const result = compareBaseline(scan, baseline);
					logResult = result.passed ? 'pass' : 'fail';
					logDetails = result;
					logToolSuccess({ ...ctx(), status: result.passed ? 'pass' : 'fail', logResult, logDetails, severity: 'info' });
					return { content: buildToolContent(formatBaselineResult(result, effectiveFormat), result, effectiveFormat) };
				}
				case 'generate_fix_plan': {
					const plan = await generateFixPlan(validDomain, scanCacheKV, runtimeOptions);
					logResult = plan.grade;
					logDetails = plan;
					logToolSuccess({ ...ctx(), status: 'pass', logResult, logDetails, severity: 'info' });
					return { content: buildToolContent(formatFixPlan(plan, effectiveFormat), plan, effectiveFormat) };
				}
				case 'generate_spf_record': {
					const includeProviders = extractIncludeProviders(validatedArgs);
					const record = await generateSpfRecord(validDomain, includeProviders, buildDnsOptions(runtimeOptions));
					logToolSuccess({ ...ctx(), status: 'pass', logResult: 'generated', logDetails: record, severity: 'info' });
					return { content: buildToolContent(formatGeneratedRecord(record, effectiveFormat), record, effectiveFormat) };
				}
				case 'generate_dmarc_record': {
					const policy = typeof validatedArgs.policy === 'string' ? validatedArgs.policy as 'none' | 'quarantine' | 'reject' : undefined;
					const ruaEmail = typeof validatedArgs.rua_email === 'string' ? validatedArgs.rua_email : undefined;
					const record = await generateDmarcRecord(validDomain, policy, ruaEmail, buildDnsOptions(runtimeOptions));
					logToolSuccess({ ...ctx(), status: 'pass', logResult: 'generated', logDetails: record, severity: 'info' });
					return { content: buildToolContent(formatGeneratedRecord(record, effectiveFormat), record, effectiveFormat) };
				}
				case 'generate_dkim_config': {
					const provider = typeof validatedArgs.provider === 'string' ? validatedArgs.provider : undefined;
					const record = await generateDkimConfig(validDomain, provider);
					logToolSuccess({ ...ctx(), status: 'pass', logResult: 'generated', logDetails: record, severity: 'info' });
					return { content: buildToolContent(formatGeneratedRecord(record, effectiveFormat), record, effectiveFormat) };
				}
				case 'generate_mta_sts_policy': {
					const mxHosts = extractMxHosts(validatedArgs);
					const record = await generateMtaStsPolicy(validDomain, mxHosts, buildDnsOptions(runtimeOptions));
					logToolSuccess({ ...ctx(), status: 'pass', logResult: 'generated', logDetails: record, severity: 'info' });
					return { content: buildToolContent(formatGeneratedRecord(record, effectiveFormat), record, effectiveFormat) };
				}
				case 'get_benchmark': {
					const profile = typeof validatedArgs.profile === 'string' ? validatedArgs.profile : 'mail_enabled';
					const result = await getBenchmark(runtimeOptions?.profileAccumulator, profile);
					logToolSuccess({ ...ctx(), status: 'pass', logResult: result.status, logDetails: result, severity: 'info' });
					return { content: buildToolContent(formatBenchmark(result, effectiveFormat), result, effectiveFormat) };
				}
				case 'get_provider_insights': {
					const provider = typeof validatedArgs.provider === 'string' ? validatedArgs.provider : '';
					if (!provider) {
						return buildToolErrorResult('Missing required parameter: provider');
					}
					const profile = typeof validatedArgs.profile === 'string' ? validatedArgs.profile : 'mail_enabled';
					const result = await getProviderInsights(runtimeOptions?.profileAccumulator, provider, profile);
					logToolSuccess({ ...ctx(), status: 'pass', logResult: result.status, logDetails: result, severity: 'info' });
					return { content: buildToolContent(formatProviderInsights(result, effectiveFormat), result, effectiveFormat) };
				}
				case 'assess_spoofability': {
					const result = await assessSpoofability(validDomain, buildDnsOptions(runtimeOptions));
					logResult = result.riskLevel;
					logDetails = result;
					logToolSuccess({ ...ctx(), status: result.spoofabilityScore <= 30 ? 'pass' : 'fail', logResult, logDetails, severity: 'info' });
					return { content: buildToolContent(formatSpoofability(result, effectiveFormat), result, effectiveFormat) };
				}
				case 'check_resolver_consistency': {
					const recordType = extractRecordType(validatedArgs);
					const result = await checkResolverConsistency(validDomain, recordType);
					runtimeOptions?.resultCapture?.(result);
					logResult = result.passed ? 'pass' : 'fail';
					logDetails = result;
					logToolSuccess({ ...ctx(), status: result.passed ? 'pass' : 'fail', logResult, logDetails, severity: 'info' });
					return { content: buildToolContent(formatResolverConsistency(result, effectiveFormat), result, effectiveFormat) };
				}
				case 'explain_finding': {
					let explainArgs: ReturnType<typeof extractExplainFindingArgs>;
					try {
						explainArgs = extractExplainFindingArgs(validatedArgs);
					} catch {
						return handleExplainFindingValidationError(args, startTime, runtimeOptions);
					}
					const { checkType, status, details } = explainArgs;
					const result = explainFinding(checkType, status, details);
					logToolSuccess({ ...ctx(), status: 'pass', logResult: status, logDetails: { checkType, details }, severity: 'info' });
					return { content: buildToolContent(formatExplanation(result, effectiveFormat), result, effectiveFormat) };
				}
				case 'validate_fix': {
					const check = typeof validatedArgs.check === 'string' ? validatedArgs.check : '';
					const expected = typeof validatedArgs.expected === 'string' ? validatedArgs.expected : undefined;
					const result = await validateFix(validDomain, check, expected, buildDnsOptions(runtimeOptions));
					logResult = result.verdict;
					logDetails = result;
					logToolSuccess({ ...ctx(), status: result.verdict === 'fixed' ? 'pass' : 'fail', logResult, logDetails, severity: 'info' });
					return { content: buildToolContent(formatValidateFix(result, effectiveFormat), result, effectiveFormat) };
				}
				case 'map_supply_chain': {
						const result = await mapSupplyChain(validDomain, buildDnsOptions(runtimeOptions));
						logResult = `${result.summary.totalProviders} providers`;
						logDetails = result;
						logToolSuccess({ ...ctx(), status: 'pass', logResult, logDetails, severity: 'info' });
						return { content: buildToolContent(formatSupplyChain(result, effectiveFormat), result, effectiveFormat) };
					}
					case 'generate_rollout_plan': {
						const targetPolicy = typeof validatedArgs.target_policy === 'string'
							? validatedArgs.target_policy as 'quarantine' | 'reject'
							: 'reject';
						const timeline = typeof validatedArgs.timeline === 'string'
							? validatedArgs.timeline as 'aggressive' | 'standard' | 'conservative'
							: 'standard';
						const result = await generateRolloutPlan(validDomain, targetPolicy, timeline, buildDnsOptions(runtimeOptions));
						logResult = result.atTarget ? 'at_target' : `${result.phases.length} phases`;
						logDetails = result;
						logToolSuccess({ ...ctx(), status: 'pass', logResult, logDetails, severity: 'info' });
						return { content: buildToolContent(formatRolloutPlan(result, effectiveFormat), result, effectiveFormat) };
					}
					case 'analyze_drift': {
						const baselineStr = typeof validatedArgs.baseline === 'string' ? validatedArgs.baseline : '';

						let baselineScore: import('../lib/scoring-model').ScanScore;
						if (baselineStr === 'cached') {
							const cacheKey = `cache:${validDomain}`;
							const cached = scanCacheKV ? await import('../lib/cache').then((m) => m.cacheGet<import('../tools/scan-domain').ScanDomainResult>(cacheKey, scanCacheKV)) : undefined;
							if (!cached) {
								return buildToolErrorResult(`Invalid baseline: no cached scan found for ${validDomain}. Run scan_domain first or provide a baseline JSON.`);
							}
							baselineScore = cached.score;
						} else {
							try {
								const parsed = JSON.parse(baselineStr);
								if (typeof parsed?.overall !== 'number' || typeof parsed?.grade !== 'string' || !Array.isArray(parsed?.findings)) {
									return buildToolErrorResult('Invalid baseline: JSON must contain overall (number), grade (string), and findings (array).');
								}
								baselineScore = parsed;
							} catch {
								return buildToolErrorResult('Invalid baseline: could not parse JSON. Provide a valid ScanScore JSON or "cached".');
							}
						}

						const scanResult = await scanDomain(validDomain, scanCacheKV, runtimeOptions);
						const drift = computeDrift(validDomain, baselineScore, scanResult.score);
						logResult = drift.classification;
						logDetails = drift;
						logToolSuccess({ ...ctx(), status: 'pass', logResult, logDetails, severity: 'info' });
						return { content: buildToolContent(formatDriftReport(drift, effectiveFormat), drift, effectiveFormat) };
					}
					case 'resolve_spf_chain': {
						const result = await resolveSpfChain(validDomain, buildDnsOptions(runtimeOptions));
						logResult = result.overLimit ? 'over_limit' : 'ok';
						logDetails = { totalLookups: result.totalLookups, maxDepth: result.maxDepth, issues: result.issues.length };
						logToolSuccess({ ...ctx(), status: result.overLimit ? 'fail' : 'pass', logResult, logDetails, severity: 'info' });
						return { content: buildToolContent(formatSpfChain(result, effectiveFormat), result, effectiveFormat) };
					}
					case 'discover_subdomains': {
						const result = await discoverSubdomains(validDomain, runtimeOptions?.certstream);
						logResult = `${result.totalSubdomains} subdomains`;
						logDetails = { totalSubdomains: result.totalSubdomains, issues: result.issues.length };
						logToolSuccess({ ...ctx(), status: 'pass', logResult, logDetails, severity: 'info' });
						return { content: buildToolContent(formatSubdomainDiscovery(result, effectiveFormat), result, effectiveFormat) };
					}
					case 'map_compliance': {
						const result = await mapCompliance(validDomain, scanCacheKV, runtimeOptions);
						logResult = 'mapped';
						logDetails = result;
						logToolSuccess({ ...ctx(), status: 'pass', logResult, logDetails, severity: 'info' });
						return { content: buildToolContent(formatCompliance(result, effectiveFormat), result, effectiveFormat) };
					}
					case 'simulate_attack_paths': {
						const result = await simulateAttackPaths(validDomain, buildDnsOptions(runtimeOptions));
						logResult = `${result.totalPaths} paths, risk: ${result.overallRisk}`;
						logDetails = { totalPaths: result.totalPaths, overallRisk: result.overallRisk };
						logToolSuccess({ ...ctx(), status: result.overallRisk === 'low' ? 'pass' : 'fail', logResult, logDetails, severity: 'info' });
						return { content: buildToolContent(formatAttackPaths(result, effectiveFormat), result, effectiveFormat) };
					}
					default:
					logToolFailure({ ...ctx(), error: `Unknown tool: ${name}`, args });
					return buildToolErrorResult(`Unknown tool: ${name}. Call tools/list to see all 47 available tools.`);
			}
		};

		return await Promise.race([
			executeDispatch(),
			new Promise<never>((_, reject) => setTimeout(() => reject(new Error('__tool_timeout__')), TOOL_CALL_TIMEOUT_MS)),
		]);
	} catch (err) {
		if (err instanceof Error && err.message === '__tool_timeout__') {
			logToolFailure({ ...ctx(), error: 'Tool call timed out', args });
			return {
				content: [mcpError(`${name} timed out after ${TOOL_CALL_TIMEOUT_MS / 1000}s. Try a simpler check or retry — cached partial results make retries faster.`)],
				isError: true,
			};
		}
		const message = sanitizeErrorMessage(err, `An unexpected error occurred while running ${name}. Retry the request — transient DNS failures are common.`);
		logToolFailure({ ...ctx(), error: err, args });
		return buildToolErrorResult(message);
	}
}
