// SPDX-License-Identifier: BUSL-1.1

import type { CheckResult } from '../lib/scoring';
import { buildNonResolvingCheckResult, isNonResolvingApex } from '../lib/apex-resolution';
import { buildCheckCacheKey, runWithCacheTracked } from '../lib/cache';
import { withRequestDedup, withStrongRequestIdempotency } from '../lib/request-dedup';
import { isAuthRequiredTool, isInternalOnlyTool } from '../lib/config';
import { sanitizeErrorMessage } from '../lib/json-rpc';
import { compactLookalikesResult, formatLookalikeCompactSummary } from '../tools/lookalike-compact';
import { getRejectedRequest } from '../tools/async-start-error-result';
import { extractAndValidateDomain, extractForceRefresh, resolveToolAlias, validateToolArgs, type OutputFormat } from './tool-args';
import { resolveToolOutputFormat } from './tool-output';
import { buildLogContext, logToolFailure, logToolSuccess } from './tool-execution';
import { readAndUpdateLastTool } from '../lib/session-memory';
import { formatCheckResult, formatAccessRefusal, mcpError, buildToolResult, withReportCitation } from './tool-formatters';
import { markUnmeasured, isAccessRefusal } from '../lib/unmeasured-result';
import { isCompletedCheck } from '../lib/ungraded-display';
import { TOOLS } from '../schemas/tool-definitions';
import type { McpToolResult, ToolRuntimeOptions, WireTool } from './tool-types';
import { MUTATING_DEDUP_TOOLS, nxdomainGateCategory, toolRequiresDomain } from './tool-sets';
import { TOOL_REGISTRY, buildDnsOptions } from './tool-registry';
import { buildToolErrorResult, dispatchDirectTool } from './direct-dispatch';

// The registry, tool sets, runtime types and direct-dispatch arms live in sibling modules; every name this file exported before is re-exported here.
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

			return dispatchDirectTool({ name, args, startTime, validatedArgs, validDomain, effectiveFormat, scanCacheKV, runtimeOptions, ctx });
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
