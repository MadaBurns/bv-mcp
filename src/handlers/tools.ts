// SPDX-License-Identifier: BUSL-1.1

import type { CheckResult } from '../lib/scoring';
import { buildNonResolvingCheckResult, isNonResolvingApex } from '../lib/apex-resolution';
import { buildCheckCacheKey, buildScanCacheKey, runWithCacheTracked } from '../lib/cache';
import { withRequestDedup, withStrongRequestIdempotency } from '../lib/request-dedup';
import { isAuthRequiredTool, isInternalOnlyTool } from '../lib/config';
import { sanitizeErrorMessage } from '../lib/json-rpc';
import { compactLookalikesResult, formatLookalikeCompactSummary } from '../tools/lookalike-compact';
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
import { getRejectedRequest } from '../tools/async-start-error-result';
import { querySignins } from '../tools/m365/query-signins';
import { queryUal } from '../tools/m365/query-ual';
import { getCaPolicies } from '../tools/m365/get-ca-policies';
import { assessCoverage } from '../tools/m365/assess-coverage';
import type { PolicyBaseline } from '../tools/compare-baseline';
import {
	extractAndValidateDomain,
	extractBaseline,
	extractExplainFindingArgs,
	extractForceRefresh,
	extractIncludeProviders,
	extractMxHosts,
	extractRecordType,
	extractScanProfile,
	resolveToolAlias,
	validateToolArgs,
	type OutputFormat,
} from './tool-args';
import { resolveToolOutputFormat } from './tool-output';
import { buildLogContext, logToolFailure, logToolSuccess } from './tool-execution';
import { readAndUpdateLastTool } from '../lib/session-memory';
import { formatCheckResult, formatAccessRefusal, mcpError, buildToolResult, withReportCitation } from './tool-formatters';
import { markUnmeasured, isAccessRefusal } from '../lib/unmeasured-result';
import { isCompletedCheck } from '../lib/ungraded-display';
import { QUERY_UAL_LIFECYCLE, TOOL_STATUS_META_KEY, TOOLS } from '../schemas/tool-definitions';
import type { McpToolResult, ToolRuntimeOptions, WireTool } from './tool-types';
import { MUTATING_DEDUP_TOOLS, nxdomainGateCategory, toolRequiresDomain } from './tool-sets';
import { TOOL_REGISTRY, buildDnsOptions } from './tool-registry';

// The registry, tool sets and runtime types live in sibling modules; every name this file exported before is re-exported here.
export {
	DIRECT_DISPATCH_TOOLS,
	INTERNAL_BATCH_SAFE_TOOLS,
	MUTATING_DEDUP_TOOLS,
	NXDOMAIN_GATED_TOOLS,
	toolRequiresDomain,
} from './tool-sets';
export { TOOL_REGISTRY } from './tool-registry';

/**
 * Handle the MCP tools/list method.
 * Returns all available tool definitions in MCP-spec shape.
 */
export function handleToolsList(): { tools: WireTool[] } {
	return {
		// Internal-only tools (INTERNAL_ONLY_TOOLS, e.g. map_registrar_products) stay in
		// TOOLS for internal-path callability but are hidden from the PUBLIC surface.
		tools: TOOLS.filter((tool) => !isInternalOnlyTool(tool.name)).map((tool) => ({
			name: tool.name,
			description: tool.description,
			inputSchema: tool.inputSchema,
			...(tool.outputSchema !== undefined && { outputSchema: tool.outputSchema }),
			annotations: tool.annotations,
			_meta: {
				group: tool.group,
				...(tool.tier !== undefined && { tier: tool.tier }),
				scanIncluded: tool.scanIncluded,
				...(tool.recommended && { recommended: true }),
			},
		})),
	};
}

function buildToolErrorResult(message: string): McpToolResult {
	return { content: [mcpError(message)], isError: true };
}

/**
 * A result that is not a security verdict, rendered as a failed tool call: an access refusal
 * (tier denied / not owned) or a rejected request (invalid input, unknown id, quota, persistence
 * or enqueue failure). A rejection carries its machine-readable `kind` in `structuredContent` and
 * NO `score`/`passed`. `undefined` for an ordinary result.
 */
function refusalToolResult(result: CheckResult, format: OutputFormat): McpToolResult | undefined {
	const rejected = getRejectedRequest(result);
	if (rejected) return { content: [mcpError(rejected.text)], structuredContent: rejected.structured, isError: true };
	if (isAccessRefusal(result)) return { ...buildToolResult(formatAccessRefusal(result), result, format), isError: true };
	return undefined;
}

/**
 * Hand the CheckResult to the caller's `resultCapture` (the /internal `?format=structured` door),
 * except for a rejected request: that door would otherwise return the raw scored CheckResult.
 */
function captureResult(runtimeOptions: ToolRuntimeOptions | undefined, result: CheckResult): void {
	if (!getRejectedRequest(result)) runtimeOptions?.resultCapture?.(result);
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

/**
 * Handle the MCP tools/call method.
 * Dispatches to the appropriate tool function based on the tool name.
 *
 * @param params - Tool call parameters (name and arguments)
 * @param scanCacheKV - Optional KV namespace for scan result caching
 */
/** Maximum wall-clock time for any single tool call (ms). */
const TOOL_CALL_TIMEOUT_MS = 28_000;

/**
 * Tool dispatch. This function applies NO per-tool policy of its own beyond the
 * identity_secops no-principal hard reject below — the four policy gates
 * (internal-only, auth-required, paid-only, contract-flag) live in
 * `evaluateToolPolicy` (src/lib/config.ts) and are the CALLER's responsibility.
 *
 * Every externally-reachable entry point must consult that chokepoint before it
 * gets here. `src/mcp/execute.ts` (public `/mcp`) and `src/internal.ts`
 * (`/internal/tools/{call,batch}`) both do; the remaining callers are trusted
 * server-side orchestration (queue consumers, tenant scan pipeline) that select
 * the tool themselves rather than taking it from a request. That census is
 * pinned by `test/tool-policy-chokepoint.audit.test.ts`, which fails when a new
 * caller appears without declaring which of the two it is.
 */
export async function handleToolsCall(
	params: {
		name: string;
		arguments?: Record<string, unknown>;
	},
	scanCacheKV?: KVNamespace,
	runtimeOptions?: ToolRuntimeOptions,
): Promise<McpToolResult> {
	const { name, args } = resolveToolAlias(params.name, params.arguments ?? {});
	const startTime = Date.now();
	// Resolve priorTool synchronously (O(1) in-memory Map read+write) before the
	// tool executes so the "immediately before this call" semantic is exact.
	// readAndUpdateLastTool returns 'none' on the first call, 'unknown' when the
	// session is absent (cross-isolate, sessionless path, etc.) — never blocks.
	const priorTool = readAndUpdateLastTool(runtimeOptions?.sessionId, name);
	const runtimeOptionsWithPrior = runtimeOptions ? { ...runtimeOptions, priorTool } : { priorTool };
	/** Lazy log context builder — evaluates durationMs at call time. */
	const ctx = () => buildLogContext(name, startTime, domain, runtimeOptionsWithPrior);
	let domain: string | undefined;
	let logResult = 'unknown';
	let logDetails: unknown;
	try {
		const validatedArgs = validateToolArgs(name, args);
		if (toolRequiresDomain(name)) {
			domain = extractAndValidateDomain(validatedArgs);
		}
		// `validDomain` is guaranteed to be a string for all branches that use it
		const validDomain: string = domain ?? '';

		const effectiveFormat = resolveToolOutputFormat(validatedArgs, runtimeOptions?.clientType);

		const executeDispatch = async (): Promise<McpToolResult> => {
			// Defense-in-depth (P1): the identity_secops M365 tools forward to bv-web's
			// internal proxy carrying the trusted internal bearer. If the dangerous
			// forward is actually possible (m365Proxy bound) but there is no verified,
			// discriminated principal identity, never forward an untrusted or absent
			// identity alongside that bearer — hard-reject even if an upstream gate were bypassed. Gated on
			// m365Proxy presence so the `/internal/*` path (which wires neither m365Proxy
			// nor identity) keeps its fail-soft `unprovisioned` behavior unchanged. The
			// public /mcp gate (execute.ts) is the primary control; this is the backstop.
			if (isAuthRequiredTool(name) && runtimeOptions?.m365Proxy && !runtimeOptions?.m365Identity) {
				logToolFailure({ ...ctx(), error: 'm365_proxy_unauthenticated', args });
				return buildToolErrorResult('Invalid request: m365_proxy_unauthenticated (authentication required).');
			}

			// Tier gate: registrar_complement view requires enterprise or owner tier.
			if (name === 'brand_audit_single' || name === 'brand_audit_batch_start') {
				const requestedView = (validatedArgs as { view?: string }).view;
				if (requestedView === 'registrar_complement') {
					const tier = runtimeOptions?.authTier;
					if (tier !== 'enterprise' && tier !== 'owner') {
						return buildToolErrorResult("Invalid view: 'registrar_complement' requires enterprise tier");
					}
				}
			}

			// Tier gate: discovery_mode='tiered' activates the Tier-0/1/2 lookups
			// against private BV_INFRA_GRAPH, BV_INTEL_GATEWAY, and BV_ENTERPRISE
			// service bindings (operator-deploy only). Restricted to enterprise tier
			// or higher (enterprise, partner, owner). Developer was removed because
			// the prior self-asserted ownership_verified attestation was not
			// cryptographically verifiable, opening a cost/abuse vector against
			// third-party domains. On BSL self-hosts the bindings are unprovisioned
			// and the pipeline degrades to classic regardless, so this gate is a
			// no-op there.
			if (
				name === 'discover_brand_domains' ||
				name === 'discover_brand_domains_start' ||
				name === 'brand_audit_single' ||
				name === 'brand_audit_batch_start'
			) {
				const requestedMode = (validatedArgs as { discovery_mode?: string }).discovery_mode;
				if (requestedMode === 'tiered') {
					const tier = runtimeOptions?.authTier;
					if (tier !== 'partner' && tier !== 'enterprise' && tier !== 'owner') {
						return buildToolErrorResult("Invalid discovery_mode: 'tiered' requires enterprise tier or higher");
					}
				}
			}

			// Tier gate: depth='deep' expands candidate seeding + enrichment fanout
			// (roughly 3× the per-call compute cost of 'standard'). Restricted to
			// enterprise tier or higher — same threshold as discovery_mode='tiered'.
			// Defensive for brand_audit_* (free/agent already get 0 quota there)
			// and for discover_brand_domains on free (now 0/day too); still
			// meaningful for agent callers, who get discover_brand_domains at the
			// tier default and could otherwise burn it on deep.
			if (
				name === 'discover_brand_domains' ||
				name === 'discover_brand_domains_start' ||
				name === 'brand_audit_single' ||
				name === 'brand_audit_batch_start'
			) {
				const requestedDepth = (validatedArgs as { depth?: string }).depth;
				if (requestedDepth === 'deep') {
					const tier = runtimeOptions?.authTier;
					if (tier !== 'partner' && tier !== 'enterprise' && tier !== 'owner') {
						return buildToolErrorResult("Invalid depth: 'deep' requires enterprise tier or higher");
					}
				}
			}

			// Dispatch to the appropriate tool — check registry first, then special cases
			const registeredTool = TOOL_REGISTRY[name];
			if (registeredTool) {
				const checkName = await registeredTool.cacheKey(validatedArgs, runtimeOptions);
				// Versioned (cache:v<version>:...) so a deploy auto-invalidates — see buildCheckCacheKey.
				const cacheKey = buildCheckCacheKey(validDomain, checkName);
				let cacheStatus: 'hit' | 'miss' = 'miss';
				let result: CheckResult;
				// #1128: a non-resolving apex abstains exactly as scan_domain does, instead of
				// scoring every absent record. Probed inside the producer, so a cache hit costs
				// nothing; the abstention is `partial` and therefore never cached (scan_domain
				// does not cache its non-resolving result either). A probe failure or SERVFAIL
				// falls through to the check unchanged (fail-open).
				const nxdomainCategory = nxdomainGateCategory(name, validatedArgs);
				// Registry tools see the scan cache through runtimeOptions (they have no other
				// handle on this function's `scanCacheKV` parameter).
				const registryOptions: ToolRuntimeOptions = { ...runtimeOptions, ...(scanCacheKV ? { scanCacheKv: scanCacheKV } : {}) };
				const runRegisteredTool = async (): Promise<CheckResult> => {
					if (!nxdomainCategory) return registeredTool.execute(validDomain, validatedArgs, registryOptions);
					// One per-call cache shared by the probe and the check, so check_ns / check_dnssec /
					// check_zone_hygiene reuse the probe's apex NS answer (SQ-268 F3).
					const gatedOptions: ToolRuntimeOptions = { ...registryOptions, dnsQueryCache: new Map() };
					return (await isNonResolvingApex(validDomain, buildDnsOptions(gatedOptions)))
						? buildNonResolvingCheckResult(nxdomainCategory, validDomain)
						: registeredTool.execute(validDomain, validatedArgs, gatedOptions);
				};
				if (registeredTool.cacheable === false) {
					result = await runRegisteredTool();
				} else {
					// Don't cache partial results (e.g. lookalike timeout). The predicate skips the
					// kv.put entirely instead of the old put-then-delete anti-pattern that drove
					// ~13M wasted SCAN_CACHE writes/week (bv-web 2026-05-14 analytics, cluster F5).
					// Never cache a refusal or a rejected request either: cache keys are not
					// principal-scoped, so one caller's quota or tier refusal would be served to
					// every caller for the same arguments until the TTL expired.
					const tracked = await runWithCacheTracked(
						cacheKey,
						runRegisteredTool,
						scanCacheKV,
						registeredTool.cacheTtlSeconds,
						/* skipCache */ extractForceRefresh(validatedArgs),
						(r) => !r.partial && !getRejectedRequest(r) && !isAccessRefusal(r),
					);
					result = tracked.data;
					cacheStatus = tracked.cacheStatus;
				}
				// #695 chokepoint. `buildCheckResult` derives `passed`/`score` from finding
				// severities, so a tool reporting that it measured NOTHING — an absent binding, a
				// silent upstream — still returns `passed: true, score: 100`. Applied here rather
				// than at each builder so one rule covers the osint, bucket, brand-audit and
				// threat-feed families, and so a future unavailable-lane builder inherits it.
				//
				// `markUnmeasured` stamps `checkStatus`/`verdictWithheld`; it never rewrites the scalars. See
				// `src/lib/unmeasured-result.ts` for why inverting them would be worse than
				// leaving them.
				result = markUnmeasured(result);
				// An authorization refusal is not a security verdict either, but it is a different
				// class: the caller was refused, not the capability missing. Surfaced as a failed
				// tool call, mirroring the `sourceUnavailable` branch of `discover_subdomains`
				// below — for a security tool, "refused" and "clean" must never be
				// indistinguishable to a machine consumer. NOT `checkStatus: 'error'`: that is the
				// retryable class, and an agentic caller would loop on a permanent refusal.
				//
				// A rejected or failed REQUEST (bad input, unknown id, quota, persistence/enqueue
				// failure) is the same class of non-verdict: it says nothing about the domain, so
				// it must not surface as a scored HIGH finding with `passed: true`. See
				// `refusalToolResult` / `captureResult`.
				const refusal = refusalToolResult(result, effectiveFormat);
				const measured = isCompletedCheck(result) && !refusal;
				captureResult(runtimeOptions, result);
				logResult = measured && result.passed ? 'pass' : 'fail';
				logDetails = result;
				logToolSuccess({
					...ctx(),
					status: measured && result.passed ? 'pass' : 'fail',
					logResult,
					logDetails,
					cacheStatus,
				});
				if (refusal) return refusal;
				if (name === 'check_lookalikes' && effectiveFormat === 'compact') {
					// #1130: a large brand emits one or two findings per registered candidate
					// (google.com: 76 findings, 69 KB) and overflowed the MCP tool-result cap in
					// "compact". Compact is a presentation transform over the complete, cached
					// result — score/passed/checkStatus are untouched — and it shrinks BOTH
					// channels, since `structuredContent` is emitted in every format.
					const compact = compactLookalikesResult(result);
					return buildToolResult(
						formatCheckResult(result, effectiveFormat, {
							findings: compact.findings,
							trailerLines: formatLookalikeCompactSummary(compact.summary),
						}),
						compact.structured,
						effectiveFormat,
					);
				}
				return buildToolResult(formatCheckResult(result, effectiveFormat), result, effectiveFormat);
			}

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
							const policy =
								typeof validatedArgs.policy === 'string' ? (validatedArgs.policy as 'none' | 'quarantine' | 'reject') : undefined;
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
					const result = await getDomainRank(
						validDomain,
						score,
						{ country: rankCountry, sector: rankSector },
						runtimeOptions?.bvWebBenchmark,
						{ authToken: runtimeOptions?.bvWebBenchmarkAuthToken },
					);
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
		};

		// Mutating *_start/register tools: internal callers with an explicit,
		// validated Idempotency-Key use strong DO state, so concurrent retries cannot
		// both execute and an ambiguous HTTP timeout can replay the stored result.
		// Public clients without a key retain the legacy short KV compatibility
		// window. Both wrappers sit inside the timeout race; the strong execution is
		// also attached to waitUntil so it can persist its result after that timeout.
		const dedupKv = runtimeOptions?.rateLimitKv;
		let dispatch = executeDispatch;
		if (MUTATING_DEDUP_TOOLS.has(name) && runtimeOptions?.idempotencyKey && runtimeOptions.idempotencyPrincipal) {
			dispatch = () =>
				withStrongRequestIdempotency(
					{
						toolName: name,
						principal: runtimeOptions.idempotencyPrincipal as string,
						idempotencyKey: runtimeOptions.idempotencyKey as string,
						args: validatedArgs as Record<string, unknown>,
						coordinator: runtimeOptions.quotaCoordinator,
						waitUntil: runtimeOptions.waitUntil,
					},
					executeDispatch,
				);
		} else if (MUTATING_DEDUP_TOOLS.has(name) && dedupKv) {
			dispatch = () =>
				withRequestDedup(
					{
						toolName: name,
						// keyHash ONLY — it is set solely for AUTHENTICATED callers.
						// principalId = keyHash ?? ipHash (execute.ts), so using it
						// would make an unauth caller's ipHash a truthy principal and
						// defeat withRequestDedup's skip, letting two NAT'd unauth
						// callers share a fingerprint → cross-principal op-ID replay.
						principal: runtimeOptions?.keyHash,
						args: validatedArgs as Record<string, unknown>,
						kv: dedupKv,
						waitUntil: runtimeOptions?.waitUntil,
					},
					executeDispatch,
				);
		}

		const dispatched = await Promise.race([
			dispatch(),
			new Promise<never>((_, reject) => setTimeout(() => reject(new Error('__tool_timeout__')), TOOL_CALL_TIMEOUT_MS)),
		]);
		// Public scanner fallback; a successful check does not prove a scorecard exists.
		// No-op for non-domain tools (`domain` undefined) and error results.
		return withReportCitation(dispatched, domain);
	} catch (err) {
		if (err instanceof Error && err.message === '__tool_timeout__') {
			logToolFailure({ ...ctx(), error: 'Tool call timed out', args });
			return {
				content: [
					mcpError(
						`${name} timed out after ${TOOL_CALL_TIMEOUT_MS / 1000}s. Try a simpler check or retry — cached partial results make retries faster.`,
					),
				],
				isError: true,
			};
		}
		const message = sanitizeErrorMessage(
			err,
			`An unexpected error occurred while running ${name}. Retry the request — transient DNS failures are common.`,
		);
		logToolFailure({ ...ctx(), error: err, args });
		return buildToolErrorResult(message);
	}
}
