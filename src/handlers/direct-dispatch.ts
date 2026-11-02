// SPDX-License-Identifier: BUSL-1.1

// Direct dispatch: the tools with no TOOL_REGISTRY entry, split out of `handlers/tools.ts`'s handleToolsCall.

import { buildScanCacheKey } from '../lib/cache';
import { scanDomain, formatScanReport, buildStructuredScanResult } from '../tools/scan-domain';
import { computeScoringConfigHash } from '../lib/scoring-version';
import { batchScan, compactBatchScanResults, formatBatchScan } from '../tools/batch-scan';
import { getAsyncBatchJob, startAsyncBatchScan } from '../tools/batch-scan-async';
import { compareDomains, formatDomainComparison, COMPARE_DOMAINS_SYNC_BUDGET_MS } from '../tools/compare-domains';
import { explainFinding, formatExplanation } from '../tools/explain-finding';
import { compareBaseline, formatBaselineResult } from '../tools/compare-baseline';
import { generateFixPlan, formatFixPlan } from '../tools/generate-fix-plan';
import {
	generateSpfRecord,
	generateDmarcRecord,
	generateDkimConfig,
	generateMtaStsPolicy,
	formatGeneratedRecord,
} from '../tools/generate-records';
import { getBenchmark, getProviderInsights, formatBenchmark, formatProviderInsights } from '../tools/intelligence';
import { getDomainRank, formatDomainRank } from '../tools/get-domain-rank';
import { assessSpoofability, formatSpoofability } from '../tools/assess-spoofability';
import { checkResolverConsistency, formatResolverConsistency } from '../tools/check-resolver-consistency';
import { validateFix, formatValidateFix } from '../tools/validate-fix';
import { mapSupplyChain, formatSupplyChain } from '../tools/map-supply-chain';
import { generateRolloutPlan, formatRolloutPlan } from '../tools/generate-rollout-plan';
import { isGraded } from '../lib/scoring';
import { computeDrift, formatDriftReport, isUsableDriftBaseline } from '../tools/analyze-drift';
import { resolveSpfChain, formatSpfChain } from '../tools/resolve-spf-chain';
import { discoverSubdomains, formatSubdomainDiscovery, DISCOVER_SUBDOMAINS_SYNC_BUDGET_MS } from '../tools/discover-subdomains';
import { mapCompliance, formatCompliance } from '../tools/map-compliance';
import { sgeQuickscan, formatSgeQuickscan } from '../tools/sge-quickscan';
import { mapRegistrarProducts, formatRegistrarProducts } from '../tools/map-registrar-products';
import { prioritizePortfolioLeads, formatPortfolioLeads } from '../tools/prioritize-portfolio-leads';
import { simulateAttackPaths, formatAttackPaths } from '../tools/simulate-attack-paths';
import { querySignins } from '../tools/m365/query-signins';
import { queryUal } from '../tools/m365/query-ual';
import { getCaPolicies } from '../tools/m365/get-ca-policies';
import { assessCoverage } from '../tools/m365/assess-coverage';
import type { PolicyBaseline } from '../tools/compare-baseline';
import {
	extractBaseline,
	extractExplainFindingArgs,
	extractForceRefresh,
	extractIncludeProviders,
	extractMxHosts,
	extractRecordType,
	extractScanProfile,
	type OutputFormat,
} from './tool-args';
import { buildLogContext, logToolFailure, logToolSuccess } from './tool-execution';
import { mcpError, buildToolResult } from './tool-formatters';
import { QUERY_UAL_LIFECYCLE, TOOL_STATUS_META_KEY } from '../schemas/tool-definitions';
import type { McpToolResult, ToolRuntimeOptions } from './tool-types';
import { buildDnsOptions } from './tool-registry';

export function buildToolErrorResult(message: string): McpToolResult {
	return { content: [mcpError(message)], isError: true };
}

function summarizeM365LogResult(result: unknown): Record<string, unknown> {
	const r = result && typeof result === 'object' && !Array.isArray(result) ? (result as Record<string, unknown>) : {};
	const data = r.data && typeof r.data === 'object' && !Array.isArray(r.data) ? (r.data as Record<string, unknown>) : undefined;
	const rows = data && Array.isArray(data.rows) ? data.rows : undefined;
	return {
		ok: r.ok === true,
		unprovisioned: r.unprovisioned === true,
		...(typeof r.error === 'string' ? { error: r.error } : {}),
		...(typeof data?.count === 'number' ? { rowCount: data.count } : rows ? { rowCount: rows.length } : {}),
	};
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

/** The handleToolsCall locals the direct-dispatch arms read. */
export interface DirectDispatchContext {
	name: string;
	args: Record<string, unknown>;
	startTime: number;
	validatedArgs: Record<string, unknown>;
	validDomain: string;
	effectiveFormat: OutputFormat;
	scanCacheKV?: KVNamespace;
	runtimeOptions?: ToolRuntimeOptions;
	ctx: () => ReturnType<typeof buildLogContext>;
}

/**
 * Run a tool that has no TOOL_REGISTRY entry. Every arm returns or throws; handleToolsCall's
 * idempotency/dedup wrappers, timeout race and catch still wrap this call.
 */
export async function dispatchDirectTool(c: DirectDispatchContext): Promise<McpToolResult> {
	const { name, args, startTime, validatedArgs, validDomain, effectiveFormat, scanCacheKV, runtimeOptions, ctx } = c;
	let logResult = 'unknown';
	let logDetails: unknown;
	switch (name) {
		case 'scan_domain': {
			const profile = extractScanProfile(validatedArgs);
			const forceRefresh = extractForceRefresh(validatedArgs);
			// `webPosture: true`: scan_domain is the only caller that renders the non-scoring web
			// posture section, so it is the only one that runs it (SQ-487).
			const scanOptions = { ...runtimeOptions, ...(profile && { profile }), ...(forceRefresh && { forceRefresh }), webPosture: true };
			const result = await scanDomain(validDomain, scanCacheKV, scanOptions);
			// Orchestrator counterpart to the TOOL_REGISTRY path's resultCapture.
			// Callers persisting a scan (tenant queue consumer / scan routes) read
			// the full ScanDomainResult from here — resultCapture cannot carry it.
			runtimeOptions?.scanResultCapture?.(result);
			// `grade` is nullable on an ungraded scan; the analytics log label
			// abstains explicitly rather than emitting an empty/`null` result field.
			logResult = result.score.grade ?? 'ungraded';
			// Summary only, not the full result: scan_domain's ~19-category CheckResult[]
			// (with per-category findings + metadata) logged in full on every call was the
			// dominant contributor to "Log size limit exceeded" warnings on the tenant
			// scan-queue path, where a whole MessageBatch's worth of domains accumulate
			// against the Workers 256KB-per-invocation log cap in one queue invocation.
			logDetails = {
				grade: result.score.grade,
				overall: result.score.overall,
				cached: result.cached,
				categoryCount: result.checks.length,
				findingCount: result.checks.reduce((n, c) => n + c.findings.length, 0),
			};
			// scanDomain sets `cached: true` only when the top-level cache:<domain>
			// key returned a hit. Threading that into the analytics emit so
			// `tool_call.blob8` reflects the orchestrator-level cache hit/miss
			// (was 'n/a' for every scan_domain call before — drowned the leaf
			// tools' real hit-rate signal in the .dev/analytics-30d.mjs report).
			const cacheStatus: 'hit' | 'miss' = result.cached ? 'hit' : 'miss';
			logToolSuccess({
				...ctx(),
				status: result.score.overall === null ? 'inconclusive' : result.score.overall >= 50 ? 'pass' : 'fail',
				logResult,
				logDetails,
				severity: 'info',
				cacheStatus,
				outcomeReason: result.checks.some((check) => check.checkStatus === 'timeout') ? 'scan_timeout' : 'completed',
				unitsAttempted: result.checks.length,
				unitsCompleted: result.checks.filter((check) => !check.checkStatus || check.checkStatus === 'completed').length,
			});
			const structured = buildStructuredScanResult(result, {
				scoringConfigHash: computeScoringConfigHash(runtimeOptions?.scoringConfig),
				includeWebPosture: true,
			});
			return buildToolResult(formatScanReport(result, effectiveFormat), structured, effectiveFormat);
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
					scanTimeoutMs: runtimeOptions?.scanTimeoutMs,
					perCheckTimeoutMs: runtimeOptions?.perCheckTimeoutMs,
					secondaryDoh: runtimeOptions?.secondaryDoh,
					infraProbe: runtimeOptions?.infraProbe,
				},
			});
			const batchText = formatBatchScan(batchResults, effectiveFormat);
			const completedDomains = batchResults.filter((result) => result.error !== 'batch_budget_exceeded').length;
			const budgetExceeded = completedDomains < batchResults.length;
			logToolSuccess({
				...ctx(),
				status: 'pass',
				// Same predicate as formatBatchScan's "Scanned N/M domain(s) successfully"
				// footer. `!r.error` counted a domain that resolved but produced no
				// measurement as a success, so the ops stream and the customer's report
				// disagreed about the same run.
				logResult: `${batchResults.filter((r) => r.measured && r.score !== null).length}/${batchResults.length} domains`,
				logDetails: { totalDomains: batchResults.length },
				severity: 'info',
				outcomeReason: budgetExceeded ? 'batch_budget_exceeded' : 'completed',
				unitsAttempted: batchResults.length,
				unitsCompleted: completedDomains,
			});
			return buildToolResult(
				batchText,
				effectiveFormat === 'compact' ? compactBatchScanResults(batchResults) : batchResults,
				effectiveFormat,
			);
		}
		case 'batch_scan_start': {
			const principalId = runtimeOptions?.principalId;
			const kv = runtimeOptions?.asyncBatchKv;
			const queue = runtimeOptions?.asyncBatchQueue;
			if (!principalId || !kv || !queue) return buildToolErrorResult('Async batch scanning is not provisioned');
			const job = await startAsyncBatchScan(
				{
					domains: validatedArgs.domains as string[],
					forceRefresh: extractForceRefresh(validatedArgs),
					idempotencyKey: String(validatedArgs.idempotency_key),
				},
				principalId,
				{ kv, queue, scoringConfig: runtimeOptions.scoringConfig },
			);
			logToolSuccess({ ...ctx(), status: 'pass', logResult: job.status, logDetails: job, severity: 'info' });
			return buildToolResult(JSON.stringify(job, null, 2), job, effectiveFormat);
		}
		case 'batch_scan_status':
		case 'batch_scan_findings': {
			const principalId = runtimeOptions?.principalId;
			const kv = runtimeOptions?.asyncBatchKv;
			if (!principalId || !kv) return buildToolErrorResult('Async batch scanning is not provisioned');
			const job = await getAsyncBatchJob(String(validatedArgs.job_id), principalId, kv);
			if (!job) return buildToolErrorResult('Batch scan job not found');
			const payload =
				name === 'batch_scan_findings'
					? {
							jobId: job.jobId,
							status: job.status,
							expiresAt: job.expiresAt,
							result: job.status === 'completed' ? job.result : undefined,
						}
					: {
							jobId: job.jobId,
							status: job.status,
							createdAt: job.createdAt,
							updatedAt: job.updatedAt,
							expiresAt: job.expiresAt,
							error: job.error,
							// A `completed` job whose budget cut off a tail is NOT a clean completion (SQ-291).
							...(job.incomplete !== undefined && { incomplete: job.incomplete, unscanned: job.unscanned ?? [] }),
						};
			logToolSuccess({ ...ctx(), status: 'pass', logResult: job.status, logDetails: payload, severity: 'info' });
			return buildToolResult(JSON.stringify(payload, null, 2), payload, effectiveFormat);
		}
		case 'compare_domains': {
			const domains = validatedArgs.domains as string[];
			const forceRefresh = extractForceRefresh(validatedArgs);
			const compareResults = await compareDomains(domains, {
				kv: scanCacheKV,
				signal: AbortSignal.timeout(COMPARE_DOMAINS_SYNC_BUDGET_MS),
				deadlineMs: Date.now() + COMPARE_DOMAINS_SYNC_BUDGET_MS,
				runtimeOptions: {
					providerSignaturesUrl: runtimeOptions?.providerSignaturesUrl,
					providerSignaturesAllowedHosts: runtimeOptions?.providerSignaturesAllowedHosts,
					providerSignaturesSha256: runtimeOptions?.providerSignaturesSha256,
					scoringConfig: runtimeOptions?.scoringConfig,
					waitUntil: runtimeOptions?.waitUntil,
					profileAccumulator: runtimeOptions?.profileAccumulator,
					scanTimeoutMs: runtimeOptions?.scanTimeoutMs,
					perCheckTimeoutMs: runtimeOptions?.perCheckTimeoutMs,
					secondaryDoh: runtimeOptions?.secondaryDoh,
					infraProbe: runtimeOptions?.infraProbe,
					...(forceRefresh && { forceRefresh }),
				},
			});
			const compareText = formatDomainComparison(compareResults, effectiveFormat);
			logToolSuccess({
				...ctx(),
				status: 'pass',
				// `Object.keys(scores)` includes the domains whose score is `null` — the
				// formatter prints those as "not measured", so counting them as compared
				// made the ops stream claim a comparison the report never made.
				logResult: `${Object.values(compareResults.scores).filter((s) => s !== null).length}/${compareResults.domains.length} domains compared`,
				logDetails: { totalDomains: compareResults.domains.length, winner: compareResults.winner },
				severity: 'info',
			});
			return buildToolResult(compareText, compareResults, effectiveFormat);
		}
		case 'compare_baseline': {
			const baseline = extractBaseline(validatedArgs) as PolicyBaseline;
			const forceRefresh = extractForceRefresh(validatedArgs);
			const scanOptions = { ...runtimeOptions, ...(forceRefresh && { forceRefresh }) };
			const scan = await scanDomain(validDomain, scanCacheKV, scanOptions);
			const result = compareBaseline(scan, baseline);
			// `passed === null` is the third state (a rule the scan could not measure).
			// Collapsing it to 'fail' via a boolean test would misreport an unmeasured
			// domain as a policy breach in the analytics/log stream.
			const baselineStatus = result.passed === null ? 'inconclusive' : result.passed ? 'pass' : 'fail';
			logResult = baselineStatus;
			logDetails = result;
			logToolSuccess({ ...ctx(), status: baselineStatus, logResult, logDetails, severity: 'info' });
			return buildToolResult(formatBaselineResult(result, effectiveFormat), result, effectiveFormat);
		}
		case 'generate': {
			// Consolidated remediation generator; `artifact` selects the output.
			// Zod has already validated `artifact` against the enum, so the
			// default branch is a defensive backstop only.
			const artifact = typeof validatedArgs.artifact === 'string' ? validatedArgs.artifact : '';
			switch (artifact) {
				case 'fix_plan': {
					const forceRefresh = extractForceRefresh(validatedArgs);
					const scanOptions = { ...runtimeOptions, ...(forceRefresh && { forceRefresh }) };
					const plan = await generateFixPlan(validDomain, scanCacheKV, scanOptions);
					logResult = plan.grade ?? 'ungraded';
					logDetails = plan;
					logToolSuccess({ ...ctx(), status: 'pass', logResult, logDetails, severity: 'info' });
					return buildToolResult(formatFixPlan(plan, effectiveFormat), plan, effectiveFormat);
				}
				case 'spf_record': {
					const includeProviders = extractIncludeProviders(validatedArgs);
					const record = await generateSpfRecord(validDomain, includeProviders, buildDnsOptions(runtimeOptions));
					logToolSuccess({ ...ctx(), status: 'pass', logResult: 'generated', logDetails: record, severity: 'info' });
					return buildToolResult(formatGeneratedRecord(record, effectiveFormat), record, effectiveFormat);
				}
				case 'dmarc_record': {
					const policy = typeof validatedArgs.policy === 'string' ? (validatedArgs.policy as 'none' | 'quarantine' | 'reject') : undefined;
					const ruaEmail = typeof validatedArgs.rua_email === 'string' ? validatedArgs.rua_email : undefined;
					const record = await generateDmarcRecord(validDomain, policy, ruaEmail, buildDnsOptions(runtimeOptions));
					logToolSuccess({ ...ctx(), status: 'pass', logResult: 'generated', logDetails: record, severity: 'info' });
					return buildToolResult(formatGeneratedRecord(record, effectiveFormat), record, effectiveFormat);
				}
				case 'dkim_config': {
					const provider = typeof validatedArgs.provider === 'string' ? validatedArgs.provider : undefined;
					const record = await generateDkimConfig(validDomain, provider);
					logToolSuccess({ ...ctx(), status: 'pass', logResult: 'generated', logDetails: record, severity: 'info' });
					return buildToolResult(formatGeneratedRecord(record, effectiveFormat), record, effectiveFormat);
				}
				case 'mta_sts_policy': {
					const mxHosts = extractMxHosts(validatedArgs);
					const record = await generateMtaStsPolicy(validDomain, mxHosts, buildDnsOptions(runtimeOptions));
					logToolSuccess({ ...ctx(), status: 'pass', logResult: 'generated', logDetails: record, severity: 'info' });
					return buildToolResult(formatGeneratedRecord(record, effectiveFormat), record, effectiveFormat);
				}
				case 'rollout_plan': {
					const targetPolicy =
						typeof validatedArgs.target_policy === 'string' ? (validatedArgs.target_policy as 'quarantine' | 'reject') : 'reject';
					const timeline =
						typeof validatedArgs.timeline === 'string'
							? (validatedArgs.timeline as 'aggressive' | 'standard' | 'conservative')
							: 'standard';
					const result = await generateRolloutPlan(validDomain, targetPolicy, timeline, buildDnsOptions(runtimeOptions));
					logResult = result.atTarget ? 'at_target' : `${result.phases.length} phases`;
					logDetails = result;
					logToolSuccess({ ...ctx(), status: 'pass', logResult, logDetails, severity: 'info' });
					return buildToolResult(formatRolloutPlan(result, effectiveFormat), result, effectiveFormat);
				}
				default:
					return buildToolErrorResult(`Invalid artifact: ${artifact}`);
			}
		}
		case 'get_domain_rank': {
			if (!validDomain) {
				return buildToolErrorResult('Missing required parameter: domain');
			}
			const rawScore = validatedArgs.score;
			const score = typeof rawScore === 'number' && isFinite(rawScore) ? Math.max(0, Math.min(100, rawScore)) : null;
			if (score === null) {
				return buildToolErrorResult('Invalid parameter: score must be a finite number between 0 and 100');
			}
			const rankCountry = typeof validatedArgs.country === 'string' ? validatedArgs.country : undefined;
			const rankSector = typeof validatedArgs.sector === 'string' ? validatedArgs.sector : undefined;
			const result = await getDomainRank(validDomain, score, { country: rankCountry, sector: rankSector }, runtimeOptions?.bvWebBenchmark, {
				authToken: runtimeOptions?.bvWebBenchmarkAuthToken,
			});
			logDetails = result;
			logToolSuccess({
				...ctx(),
				status: result.representative ? 'pass' : 'pass',
				logResult: result.status,
				logDetails,
				severity: 'info',
			});
			return buildToolResult(formatDomainRank(result, effectiveFormat), result, effectiveFormat);
		}
		case 'get_benchmark': {
			const profile = typeof validatedArgs.profile === 'string' ? validatedArgs.profile : 'mail_enabled';
			const result = await getBenchmark(runtimeOptions?.profileAccumulator, profile, runtimeOptions?.profileAccumulatorShardMode);
			logToolSuccess({ ...ctx(), status: 'pass', logResult: result.status, logDetails: result, severity: 'info' });
			return buildToolResult(formatBenchmark(result, effectiveFormat), result, effectiveFormat);
		}
		case 'get_provider_insights': {
			const provider = typeof validatedArgs.provider === 'string' ? validatedArgs.provider : '';
			if (!provider) {
				return buildToolErrorResult('Missing required parameter: provider');
			}
			const profile = typeof validatedArgs.profile === 'string' ? validatedArgs.profile : 'mail_enabled';
			const result = await getProviderInsights(
				runtimeOptions?.profileAccumulator,
				provider,
				profile,
				runtimeOptions?.profileAccumulatorShardMode,
			);
			logToolSuccess({ ...ctx(), status: 'pass', logResult: result.status, logDetails: result, severity: 'info' });
			return buildToolResult(formatProviderInsights(result, effectiveFormat), result, effectiveFormat);
		}
		case 'assess_spoofability': {
			const result = await assessSpoofability(validDomain, buildDnsOptions(runtimeOptions));
			// riskLevel/spoofabilityScore are null when NO control could be measured
			// (total resolver outage). That is neither a pass nor a measured failure —
			// log it as its own state rather than letting `null <= 30` read as a pass.
			logResult = result.riskLevel ?? 'unmeasured';
			logDetails = result;
			logToolSuccess({
				...ctx(),
				status: result.spoofabilityScore !== null && result.spoofabilityScore <= 30 ? 'pass' : 'fail',
				logResult,
				logDetails,
				severity: 'info',
			});
			return buildToolResult(formatSpoofability(result, effectiveFormat), result, effectiveFormat);
		}
		case 'check_resolver_consistency': {
			const recordType = extractRecordType(validatedArgs);
			const result = await checkResolverConsistency(validDomain, recordType);
			runtimeOptions?.resultCapture?.(result);
			logResult = result.passed ? 'pass' : 'fail';
			logDetails = result;
			logToolSuccess({ ...ctx(), status: result.passed ? 'pass' : 'fail', logResult, logDetails, severity: 'info' });
			return buildToolResult(formatResolverConsistency(result, effectiveFormat), result, effectiveFormat);
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
			return buildToolResult(formatExplanation(result, effectiveFormat), result, effectiveFormat);
		}
		case 'validate_fix': {
			const check = typeof validatedArgs.check === 'string' ? validatedArgs.check : '';
			const expected = typeof validatedArgs.expected === 'string' ? validatedArgs.expected : undefined;
			const result = await validateFix(validDomain, check, expected, buildDnsOptions(runtimeOptions));
			logResult = result.verdict;
			logDetails = result;
			logToolSuccess({ ...ctx(), status: result.verdict === 'fixed' ? 'pass' : 'fail', logResult, logDetails, severity: 'info' });
			return buildToolResult(formatValidateFix(result, effectiveFormat), result, effectiveFormat);
		}
		case 'map_supply_chain': {
			const result = await mapSupplyChain(validDomain, { dnsOptions: buildDnsOptions(runtimeOptions) });
			logResult = `${result.summary.totalProviders} providers`;
			logDetails = result;
			logToolSuccess({ ...ctx(), status: 'pass', logResult, logDetails, severity: 'info' });
			return buildToolResult(formatSupplyChain(result, effectiveFormat), result, effectiveFormat);
		}
		case 'analyze_drift': {
			const baselineStr = typeof validatedArgs.baseline === 'string' ? validatedArgs.baseline : '';

			let baselineScore: import('@blackveil/dns-checks/scoring').ScanScore;
			if (baselineStr === 'cached') {
				// MUST match scanDomain's default-profile top-level key (buildScanCacheKey)
				// so the versioned cache written by scan_domain is readable here.
				const cacheKey = buildScanCacheKey(validDomain);
				const cached = scanCacheKV
					? await import('../lib/cache').then((m) => m.cacheGet<import('../tools/scan-domain').ScanDomainResult>(cacheKey, scanCacheKV))
					: undefined;
				if (!cached) {
					return buildToolErrorResult(
						`Invalid baseline: no cached scan found for ${validDomain}. Run scan_domain first or provide a baseline JSON.`,
					);
				}
				baselineScore = cached.score;
				// A CACHED scan can legitimately be ungraded (NXDOMAIN, unresolvable zone).
				// There is nothing to measure drift against, so abstain rather than diff
				// against it and report a fabricated delta — e.g. a domain that NXDOMAINed
				// and was later configured properly would otherwise render
				// "Score: +73 pts (… -> B), improving" against a baseline never measured.
				if (!isUsableDriftBaseline(baselineScore)) {
					return buildToolErrorResult(
						`Invalid baseline: the cached scan for ${validDomain} was never graded, so there is nothing to measure drift against. Re-run scan_domain.`,
					);
				}
			} else {
				try {
					const parsed = JSON.parse(baselineStr);
					// Same gate as the cached path: a caller-supplied baseline whose grade is
					// a placeholder rather than a real letter fabricates the identical delta.
					if (!isUsableDriftBaseline(parsed)) {
						return buildToolErrorResult(
							'Invalid baseline: JSON must contain overall (a finite number), grade (a real grade letter), and findings (array). An ungraded scan cannot be used as a drift baseline.',
						);
					}
					baselineScore = parsed;
				} catch {
					return buildToolErrorResult('Invalid baseline: could not parse JSON. Provide a valid ScanScore JSON or "cached".');
				}
			}

			const forceRefresh = extractForceRefresh(validatedArgs);
			const scanOptions = { ...runtimeOptions, ...(forceRefresh && { forceRefresh }) };
			const scanResult = await scanDomain(validDomain, scanCacheKV, scanOptions);
			// The CURRENT side needs the same abstain as the baseline side, and for a
			// sharper reason: computeDrift diffs finding SETS, so an unmeasured current
			// scan makes every baseline finding "disappear" and reports them as RESOLVED.
			// A monitored client domain that lapses (NXDOMAIN) rendered "STABLE" with a
			// HIGH and a MEDIUM finding ticked off as fixed — nothing was fixed, the
			// domain stopped existing. categoryDeltas' `?? 0` likewise turned an empty
			// categoryScores map into a confident `spf: 80 -> 0 (-80)`. Abstaining BEFORE
			// computeDrift is what makes both unconstructible; computeDrift's own
			// `'inconclusive'` classification is a verdict change layered on top of this
			// guard for the callers that do reach it, not a substitute for it.
			if (!isGraded(scanResult.score)) {
				return buildToolErrorResult(
					`Domain ${validDomain} could not be scored on this run (it does not resolve, or its zone is unresolvable), so there is nothing to compare against the baseline. Drift cannot be measured.`,
				);
			}
			const drift = computeDrift(validDomain, baselineScore, scanResult.score);
			logResult = drift.classification;
			logDetails = drift;
			logToolSuccess({ ...ctx(), status: 'pass', logResult, logDetails, severity: 'info' });
			return buildToolResult(formatDriftReport(drift, effectiveFormat), drift, effectiveFormat);
		}
		case 'resolve_spf_chain': {
			const result = await resolveSpfChain(validDomain, buildDnsOptions(runtimeOptions));
			logResult = result.overLimit ? 'over_limit' : 'ok';
			logDetails = { totalLookups: result.totalLookups, maxDepth: result.maxDepth, issues: result.issues.length };
			logToolSuccess({ ...ctx(), status: result.overLimit ? 'fail' : 'pass', logResult, logDetails, severity: 'info' });
			return buildToolResult(formatSpfChain(result, effectiveFormat), result, effectiveFormat);
		}
		case 'discover_subdomains': {
			const forceRefresh = extractForceRefresh(validatedArgs);
			const result = await discoverSubdomains(validDomain, runtimeOptions?.certstream, runtimeOptions?.certstreamAuthToken, {
				signal: AbortSignal.timeout(DISCOVER_SUBDOMAINS_SYNC_BUDGET_MS),
				deadlineMs: Date.now() + DISCOVER_SUBDOMAINS_SYNC_BUDGET_MS,
				...(forceRefresh && { forceRefresh }),
				...(runtimeOptions?.certspotterToken && { certspotterToken: runtimeOptions.certspotterToken }),
				// Subdomain cache, doing two jobs off one entry: inside the fresh
				// window it answers the call outright (marked `cached`, no upstream
				// query — this is what keeps us inside CertSpotter's 10/hr
				// full-domain quota); past it, it is the last-known-good net
				// re-served (marked `stale`) when every live CT source is down.
				...(scanCacheKV && { cacheKv: scanCacheKV }),
				...(runtimeOptions?.waitUntil && { waitUntil: runtimeOptions.waitUntil }),
			});
			logResult = `${result.countBasis === 'floor' ? '>=' : ''}${result.totalSubdomains} subdomains`;
			logDetails = {
				totalSubdomains: result.totalSubdomains,
				// #866: a floor must read as a floor in tail too — a rising floor
				// rate is the alarm for a CT source that has started failing.
				countBasis: result.countBasis ?? 'sample',
				concreteSubdomains: result.concreteSubdomains ?? result.totalSubdomains - result.wildcardCerts,
				issues: result.issues.length,
				sourceUnavailable: result.sourceUnavailable ?? false,
				stale: result.stale ?? false,
				// Cache-hit rate is the metric this quota fix is judged on — without
				// it in tail there is no way to tell a working fresh-read cache from
				// one that silently never hits.
				cached: result.cached ?? false,
				// #573: an under-reported enumeration must be visible in tail, not
				// just in the payload — a rising truncated-rate is the alarm for a
				// CT source that has quietly started capping us.
				truncated: result.truncated ?? false,
				returned: result.returned ?? result.subdomains.length,
				// Renamed from `enumerationComplete`, which asserted estate-level
				// completeness a single CT source can never support. The narrow
				// per-source truth is unchanged; only the (misreadable) name is.
				sourceIndexExhausted: result.sourceIndexExhausted ?? true,
				// Degraded recall — a source was asked and failed, or was never
				// consulted — is now visible in tail, not just in the payload.
				coverageDegraded: result.coverage?.degraded ?? false,
				...(result.sources ? { sources: result.sources.join(',') } : {}),
				...(result.stale || result.cached ? { cacheAgeMinutes: result.cacheAgeMinutes ?? 0 } : {}),
			};
			// A CT-source outage (sourceUnavailable) is NOT a clean "0 subdomains found" — for a
			// security tool the two are dangerously indistinguishable. Surface it as a failed/
			// inconclusive tool call (isError) so a machine consumer cannot read "source down" as
			// "genuinely no subdomains". The formatted text already explains the outage + suggests
			// a retry; the structured payload carries sourceUnavailable:true for programmatic checks.
			if (result.sourceUnavailable) {
				const sourceOutcomes = result.coverage?.perSource.map((source) => source.outcome) ?? [];
				logToolSuccess({
					...ctx(),
					status: 'fail',
					logResult: 'CT source unavailable',
					logDetails,
					severity: 'warn',
					outcomeReason: sourceOutcomes.includes('rate_limited')
						? 'upstream_rate_limited'
						: sourceOutcomes.includes('timeout')
							? 'upstream_timeout'
							: 'internal_error',
					unitsAttempted: result.coverage?.perSource.length,
					unitsCompleted: result.coverage?.contributing.length,
				});
				return { ...buildToolResult(formatSubdomainDiscovery(result, effectiveFormat), result, effectiveFormat), isError: true };
			}
			// A stale (last-known-good) result carries real data, so it is NOT an error —
			// but log it warn-level so a live-source outage is still visible in tail.
			if (result.stale) {
				logToolSuccess({
					...ctx(),
					status: 'pass',
					logResult: `${logResult} (stale)`,
					logDetails,
					severity: 'warn',
					outcomeReason: result.coverage?.perSource.some((source) => source.outcome === 'rate_limited')
						? 'upstream_rate_limited'
						: result.coverage?.perSource.some((source) => source.outcome === 'timeout')
							? 'upstream_timeout'
							: 'completed',
					unitsAttempted: result.coverage?.perSource.length,
					unitsCompleted: result.coverage?.contributing.length,
				});
				return buildToolResult(formatSubdomainDiscovery(result, effectiveFormat), result, effectiveFormat);
			}
			logToolSuccess({ ...ctx(), status: 'pass', logResult, logDetails, severity: 'info' });
			return buildToolResult(formatSubdomainDiscovery(result, effectiveFormat), result, effectiveFormat);
		}
		case 'map_compliance': {
			const forceRefresh = extractForceRefresh(validatedArgs);
			const scanOptions = { ...runtimeOptions, ...(forceRefresh && { forceRefresh }) };
			const result = await mapCompliance(validDomain, scanCacheKV, scanOptions);
			logResult = 'mapped';
			logDetails = result;
			logToolSuccess({ ...ctx(), status: 'pass', logResult, logDetails, severity: 'info' });
			return buildToolResult(formatCompliance(result, effectiveFormat), result, effectiveFormat);
		}
		case 'sge_quickscan': {
			const forceRefresh = extractForceRefresh(validatedArgs);
			const scanOptions = { ...runtimeOptions, ...(forceRefresh && { forceRefresh }) };
			const result = await sgeQuickscan(validDomain, scanCacheKV, scanOptions);
			// The log line carries the VERDICT, never a count of ticks: "5 satisfied"
			// in a log is the same misreading the rendered output is built to prevent.
			logResult = result.verdict;
			logDetails = result;
			logToolSuccess({ ...ctx(), status: 'pass', logResult, logDetails, severity: 'info' });
			return buildToolResult(formatSgeQuickscan(result, effectiveFormat), result, effectiveFormat);
		}
		case 'map_registrar_products': {
			const forceRefresh = extractForceRefresh(validatedArgs);
			const scanOptions = { ...runtimeOptions, ...(forceRefresh && { forceRefresh }) };
			const result = await mapRegistrarProducts(validDomain, scanCacheKV, scanOptions);
			logResult = `${result.recommendedCount} recommended`;
			logDetails = result;
			logToolSuccess({ ...ctx(), status: 'pass', logResult, logDetails, severity: 'info' });
			return buildToolResult(formatRegistrarProducts(result, effectiveFormat), result, effectiveFormat);
		}
		case 'prioritize_portfolio_leads': {
			const forceRefresh = extractForceRefresh(validatedArgs);
			const scanOptions = { ...runtimeOptions, ...(forceRefresh && { forceRefresh }) };
			const result = await prioritizePortfolioLeads(
				{
					domains: validatedArgs.domains as string[] | undefined,
					brand: validatedArgs.brand as string | undefined,
					force_refresh: forceRefresh,
				},
				scanCacheKV,
				scanOptions,
			);
			logResult = `${result.rankedLeads.length} leads, ${result.summary.hotLeads} hot`;
			logDetails = { totalDomains: result.totalDomains, hotLeads: result.summary.hotLeads };
			logToolSuccess({ ...ctx(), status: 'pass', logResult, logDetails, severity: 'info' });
			return buildToolResult(formatPortfolioLeads(result, effectiveFormat), result, effectiveFormat);
		}
		case 'simulate_attack_paths': {
			const result = await simulateAttackPaths(validDomain, buildDnsOptions(runtimeOptions));
			logResult = result.overallRisk === null ? 'not assessed' : `${result.totalPaths} paths, risk: ${result.overallRisk}`;
			logDetails = { totalPaths: result.totalPaths, overallRisk: result.overallRisk };
			logToolSuccess({
				...ctx(),
				status: result.overallRisk === null ? 'inconclusive' : result.overallRisk === 'low' ? 'pass' : 'fail',
				logResult,
				logDetails,
				severity: 'info',
			});
			return buildToolResult(formatAttackPaths(result, effectiveFormat), result, effectiveFormat);
		}
		case 'query_signins': {
			const result = await querySignins(
				{
					ms_tenant_id: String(validatedArgs.ms_tenant_id),
					user_principal_name: validatedArgs.user_principal_name as string | undefined,
					failures_only: validatedArgs.failures_only as boolean | undefined,
					since_hours: validatedArgs.since_hours as number | undefined,
				},
				runtimeOptions?.m365Proxy,
				{ authToken: runtimeOptions?.m365ProxyAuthToken, identity: runtimeOptions?.m365Identity },
			);
			logResult = result.ok ? 'ok' : 'error';
			logDetails = summarizeM365LogResult(result);
			logToolSuccess({ ...ctx(), status: result.ok ? 'pass' : 'fail', logResult, logDetails, severity: 'info' });
			const text = JSON.stringify(result, null, effectiveFormat === 'compact' ? 0 : 2);
			return buildToolResult(text, result, effectiveFormat);
		}
		case 'query_ual': {
			const result = await queryUal(
				{
					ms_tenant_id: String(validatedArgs.ms_tenant_id),
					operation: validatedArgs.operation as string | undefined,
					user_principal_name: validatedArgs.user_principal_name as string | undefined,
					since_hours: validatedArgs.since_hours as number | undefined,
				},
				runtimeOptions?.m365Proxy,
				{ authToken: runtimeOptions?.m365ProxyAuthToken, identity: runtimeOptions?.m365Identity },
			);
			logResult = result.ok ? 'ok' : 'error';
			logDetails = summarizeM365LogResult(result);
			logToolSuccess({ ...ctx(), status: result.ok ? 'pass' : 'fail', logResult, logDetails, severity: 'info' });
			const text = JSON.stringify(result, null, effectiveFormat === 'compact' ? 0 : 2);
			return {
				...buildToolResult(text, result, effectiveFormat),
				isError: true,
				_meta: { [TOOL_STATUS_META_KEY]: QUERY_UAL_LIFECYCLE },
			};
		}
		case 'get_ca_policies': {
			const result = await getCaPolicies({ ms_tenant_id: String(validatedArgs.ms_tenant_id) }, runtimeOptions?.m365Proxy, {
				authToken: runtimeOptions?.m365ProxyAuthToken,
				identity: runtimeOptions?.m365Identity,
			});
			logResult = result.ok ? 'ok' : 'error';
			logDetails = summarizeM365LogResult(result);
			logToolSuccess({ ...ctx(), status: result.ok ? 'pass' : 'fail', logResult, logDetails, severity: 'info' });
			const text = JSON.stringify(result, null, effectiveFormat === 'compact' ? 0 : 2);
			return buildToolResult(text, result, effectiveFormat);
		}
		case 'assess_coverage': {
			const result = await assessCoverage({ ms_tenant_id: String(validatedArgs.ms_tenant_id) }, runtimeOptions?.m365Proxy, {
				authToken: runtimeOptions?.m365ProxyAuthToken,
				identity: runtimeOptions?.m365Identity,
			});
			logResult = result.ok ? 'ok' : 'error';
			logDetails = summarizeM365LogResult(result);
			logToolSuccess({ ...ctx(), status: result.ok ? 'pass' : 'fail', logResult, logDetails, severity: 'info' });
			const text = JSON.stringify(result, null, effectiveFormat === 'compact' ? 0 : 2);
			return buildToolResult(text, result, effectiveFormat);
		}
		default:
			logToolFailure({ ...ctx(), error: `Unknown tool: ${name}`, args });
			return buildToolErrorResult(`Unknown tool: ${name}. Call tools/list to see the available tools.`);
	}
}
