// SPDX-License-Identifier: BUSL-1.1

import type { CheckResult } from '../lib/scoring';
import type { QueryDnsOptions, SecondaryDohConfig } from '../lib/dns-types';
import { buildCheckCacheKey, buildScanCacheKey, runWithCacheTracked } from '../lib/cache';
import { withRequestDedup } from '../lib/request-dedup';
import { isAuthRequiredTool } from '../lib/config';
import { sanitizeErrorMessage } from '../lib/json-rpc';
import { checkSpf } from '../tools/check-spf';
import { checkSubdomainTakeover } from '../tools/check-subdomain-takeover';
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
import { computeScoringConfigHash } from '../lib/scoring-version';
import { batchScan, formatBatchScan } from '../tools/batch-scan';
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
import { computeDrift, formatDriftReport } from '../tools/analyze-drift';
import { resolveSpfChain, formatSpfChain } from '../tools/resolve-spf-chain';
import { discoverSubdomains, formatSubdomainDiscovery, DISCOVER_SUBDOMAINS_SYNC_BUDGET_MS } from '../tools/discover-subdomains';
import { mapCompliance, formatCompliance } from '../tools/map-compliance';
import { simulateAttackPaths, formatAttackPaths } from '../tools/simulate-attack-paths';
import { checkDbl } from '../tools/check-dbl';
import { checkRbl } from '../tools/check-rbl';
import { checkCymruAsn } from '../tools/check-cymru-asn';
import { checkRdapLookup, RDAP_LOOKUP_SYNC_BUDGET_MS } from '../tools/check-rdap-lookup';
import { checkNsecWalkability } from '../tools/check-nsec-walkability';
import { checkDnssecChain } from '../tools/check-dnssec-chain';
import { checkDnskeyStrength } from '../tools/check-dnskey-strength';
import { checkAgentDiscovery } from '../tools/check-agent-discovery';
import type { AgentProtocol } from '../tools/check-agent-discovery';
import { checkFastFlux } from '../tools/check-fast-flux';
import { checkAuthoritativeDnsInfra } from '../tools/check-authoritative-dns-infra';
import { checkRootServerSet } from '../tools/check-root-server-set';
import { discoverBrandDomains } from '../tools/discover-brand-domains';
import { brandAuditSingle } from '../tools/brand-audit-single';
import { brandAuditBatchStart } from '../tools/brand-audit-batch-start';
import { brandAuditStatus } from '../tools/brand-audit-status';
import { brandAuditGetReport } from '../tools/brand-audit-get-report';
import { discoverBrandDomainsStart, discoverBrandDomainsFindings } from '../tools/discover-brand-domains-start';
import { registerBrandAuditWatch, listBrandAuditWatches, deleteBrandAuditWatch } from '../tools/brand-audit-watch';
import { createD1BrandAuditStepStore } from '../lib/brand-audit-step-store';
import { querySignins } from '../tools/m365/query-signins';
import { queryUal } from '../tools/m365/query-ual';
import { getCaPolicies } from '../tools/m365/get-ca-policies';
import { assessCoverage } from '../tools/m365/assess-coverage';
import type { PolicyBaseline } from '../tools/compare-baseline';
import type { AnalyticsClient } from '../lib/analytics';
import type { BindingDegradationSink } from '../lib/binding-degradation';
import {
	extractAndValidateDomain,
	extractBaseline,
	extractDkimSelector,
	extractExplainFindingArgs,
	extractForceRefresh,
	extractFormat,
	extractIncludeProviders,
	extractMxHosts,
	extractRecordType,
	extractScanProfile,
	resolveToolAlias,
	validateToolArgs,
} from './tool-args';
import type { OutputFormat } from './tool-args';
import { buildLogContext, logToolFailure, logToolSuccess } from './tool-execution';
import { readAndUpdateLastTool } from '../lib/session-memory';
import { formatCheckResult, mcpError, buildToolResult } from './tool-formatters';
import type { McpContent } from './tool-formatters';
import { TOOLS } from '../schemas/tool-definitions';
import type { McpTool } from '../schemas/tool-definitions';

/** MCP tools/call result */
interface McpToolResult {
	content: McpContent[];
	structuredContent?: Record<string, unknown>;
	isError?: boolean;
}

/**
 * MCP-spec-shaped tool descriptor as sent over the wire. Server-specific
 * metadata (functional group, scoring tier, scan inclusion) is nested under
 * `_meta` — the spec-sanctioned extension point — rather than leaked as
 * top-level fields the MCP `Tool` shape does not define.
 */
interface WireTool {
	name: string;
	description: string;
	inputSchema: McpTool['inputSchema'];
	/** Present only for tools whose `structuredContent` is a `CheckResult`. */
	outputSchema?: McpTool['outputSchema'];
	annotations: McpTool['annotations'];
	_meta: {
		group: McpTool['group'];
		tier?: McpTool['tier'];
		scanIncluded: boolean;
		/** Present (true) only for the curated starter set; omitted otherwise (lean, like tier). */
		recommended?: boolean;
	};
}

/**
 * Handle the MCP tools/list method.
 * Returns all available tool definitions in MCP-spec shape.
 */
export function handleToolsList(): { tools: WireTool[] } {
	return {
		tools: TOOLS.map((tool) => ({
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

const DOMAIN_REQUIRED_TOOLS = new Set(
	TOOLS.filter((tool) => Array.isArray(tool.inputSchema.required) && tool.inputSchema.required.includes('domain')).map((tool) => tool.name),
);

/**
 * Tools eligible for the request-dedup window (#363 item 3): mutating
 * (`readOnlyHint === false`) AND non-destructive (`destructiveHint === false`).
 * That's the 8 `*_start` / `register_*` creators — the ones a client retry can
 * DUPLICATE. The naturally-idempotent `delete_brand_audit_watch` (destructive)
 * is excluded. Derived from annotations (the SSOT), so a future mutating tool
 * auto-joins — guarded by an exact-set test so that's a conscious decision.
 */
export const MUTATING_DEDUP_TOOLS = new Set(
	TOOLS.filter((tool) => tool.annotations?.readOnlyHint === false && tool.annotations?.destructiveHint === false).map((tool) => tool.name),
);

export function toolRequiresDomain(name: string): boolean {
	return DOMAIN_REQUIRED_TOOLS.has(name);
}

/** Wrapper for dynamic check_mx import (required for test mock isolation) */
interface ToolRuntimeOptions {
	providerSignaturesUrl?: string;
	providerSignaturesAllowedHosts?: string[];
	providerSignaturesSha256?: string;
	analytics?: AnalyticsClient;
	/**
	 * Sink for operator-binding degradation telemetry (BV_RECON / BV_TLS_PROBE).
	 * Constructed once at the ToolRuntimeOptions seam from `analytics` so each
	 * recon/tls-probe wrapper can emit the analytics `degradation` event when a
	 * PRESENT binding fails. Undefined when analytics is unavailable (BSL
	 * self-hosts, queue path) — the bindings then only warn-log. Fail-open.
	 */
	onBindingDegradation?: BindingDegradationSink;
	profileAccumulator?: DurableObjectNamespace;
	/**
	 * ProfileAccumulator write-sharding mode (R10, default-off). Threaded from
	 * env.PROFILE_ACCUMULATOR_SHARDING via execute.ts then dispatch.ts. Routes the
	 * adaptive-weight /ingest write (scan_domain), the /weights read, and the
	 * intelligence read seams (get_benchmark / get_provider_insights) to the SAME
	 * per-profile shard. 'global'/undefined = legacy single instance (unchanged).
	 */
	profileAccumulatorShardMode?: import('../lib/profile-accumulator').AccumulatorShardMode;
	waitUntil?: (promise: Promise<unknown>) => void;
	scoringConfig?: import('@blackveil/dns-checks/scoring').ScoringConfig;
	/** When provided, receives the raw CheckResult before MCP text formatting. Used by internal structured response mode. */
	resultCapture?: (result: CheckResult) => void;
	/** Override cache TTL in seconds for scan results. Threaded to scanDomain. */
	cacheTtlSeconds?: number;
	/** Scan-level wall-clock budget in milliseconds. Threaded to scanDomain. */
	scanTimeoutMs?: number;
	/** Per-check wall-clock budget in milliseconds. Threaded to scanDomain. */
	perCheckTimeoutMs?: number;
	/** Custom secondary DoH resolver config (bv-dns). Threaded to dnsOptions for individual checks. */
	secondaryDoh?: SecondaryDohConfig;
	country?: string;
	clientType?: string;
	authTier?: string;
	keyHash?: string;
	/** Cloudflare edge colo (`request.cf.colo`) for per-datacenter tool_call analytics grouping. */
	colo?: string;
	/** Geo enrichment (request.cf) for the tool_call AE geo blobs. */
	region?: string;
	city?: string;
	asn?: number;
	/**
	 * MCP session ID from the `mcp-session-id` request header. Used to resolve
	 * the `priorTool` dimension (blob12) on tool_call analytics events via
	 * readAndUpdateLastTool — synchronous, in-memory only, never blocks.
	 * Omitted on sessionless paths (e.g. /internal tools/call) → priorTool='unknown'.
	 */
	sessionId?: string;
	certstream?: { fetch: typeof fetch };
	certstreamAuthToken?: string;
	whoisBinding?: { fetch: typeof fetch };
	/** Operator-only bv-recon service binding. Fail-soft; absent on BSL self-hosts. */
	reconBinding?: { fetch: typeof fetch };
	/** Operator-only bv-tls-probe service binding (negotiated-TLS-version detection). Fail-soft; absent on BSL self-hosts → SSL check gains no TLS-version finding. */
	tlsProbeBinding?: { fetch: typeof fetch };
	/** Bearer token forwarded to bv-tls-probe. */
	tlsProbeAuthToken?: string;
	/** Service binding to bv-web's internal M365 proxy surface. Fail-soft; absent when bv-web is not provisioned. */
	m365Proxy?: { fetch: typeof fetch };
	/** Bearer token (BV_WEB_INTERNAL_KEY) forwarded to bv-web's internal M365 endpoints. */
	m365ProxyAuthToken?: string;
	/**
	 * Service binding to bv-web (BV_WEB) used by get_domain_rank to call C1.
	 * Reuses the same BV_WEB binding as m365Proxy — a separate field so callers
	 * can thread it independently (they are the same binding in practice).
	 * Fail-soft: absent → get_domain_rank returns representative result.
	 */
	bvWebBenchmark?: { fetch: typeof fetch };
	/** Bearer token (BV_WEB_INTERNAL_KEY) forwarded to the C1 benchmark endpoint. */
	bvWebBenchmarkAuthToken?: string;
	/** Bearer admin token forwarded to bv-recon. */
	reconAuthToken?: string;
	infraProbe?: { fetch: typeof fetch };
	/** D1 binding for the brand-audit DB. Used by brand_audit_{batch_start,status,get_report}. Undefined if the operator hasn't provisioned brand-audit-v1 yet (see docs/provisioning/brand-audit-bindings.md). */
	brandAuditDb?: D1Database;
	/** Cloudflare Queue producer for the brand-audit batch path. Undefined if unprovisioned. */
	brandAuditQueue?: { send(message: unknown, options?: { contentType?: 'json' }): Promise<void> };
	/** RATE_LIMIT KV — also used by enforceBrandAuditQuota for the per-tier monthly window. */
	rateLimitKv?: KVNamespace;
	/** principalId of the calling user — required for enforceBrandAuditQuota. Key hash for auth, IP hash for unauth. */
	principalId?: string;
	/** R2 bucket binding for brand-audit PDF reports. v2.20.0+; used by brand_audit_get_report to mint signed URLs. */
	brandReportsR2?: R2Bucket;
	/** Service binding to bv-browser-renderer Worker. v2.20.0+; used by brand_audit_pdf_consumer at queue time, not by request-path tools. */
	browserRenderer?: { fetch: typeof fetch };
	/**
	 * T13 — runtime-default for `discover_brand_domains` discovery_mode.
	 * Sourced from `env.BRAND_AUDIT_DISCOVERY_MODE_DEFAULT` at the index.ts
	 * construction sites. Threaded into `brandAuditSingle`'s pipeline
	 * `options.env`. `'tiered'` flips the default; any other value (including
	 * undefined) leaves the public schema default (`'classic'`) in charge.
	 * BSL self-hosters never set this — they get classic mode out of the box.
	 */
	discoveryModeDefault?: string;
	/**
	 * Tier 0 (tenant-declared portfolio) lookup closure — wraps the
	 * `BV_ENTERPRISE` service binding. Constructed at the production seam in
	 * `src/index.ts` when both the binding and `BV_WEB_INTERNAL_KEY` are
	 * provisioned. Threaded through to `discoverBrandDomains` (direct + via
	 * `brand_audit_single`'s pipeline). Undefined on BSL self-hosts → tiered
	 * mode degrades to classic without ever calling bv-enterprise.
	 */
	tier0Lookup?: (domain: string) => Promise<import('../lib/brand-tier0-enterprise').Tier0Result>;
	/**
	 * Tier 1 (bv-infrastructure-graph) lookup closure — wraps the
	 * `BV_INFRA_GRAPH` service binding. Constructed at the production seam in
	 * `src/index.ts` when both the binding and `BV_WEB_INTERNAL_KEY` are
	 * provisioned. Threaded through to `discoverBrandDomains` (direct + via
	 * `brand_audit_single`'s pipeline). Undefined on BSL self-hosts.
	 */
	tier1Lookup?: (domain: string) => Promise<import('../lib/brand-tier1-graph').Tier1Result>;
	/**
	 * Tier 2 (bv-intel-gateway declared-evidence) lookup closure — wraps the
	 * `BV_INTEL_GATEWAY` RPC service binding. Constructed at the production
	 * seam in `src/index.ts` when the binding is provisioned. Threaded through
	 * to `discoverBrandDomains` (direct + via `brand_audit_single`'s pipeline).
	 * Undefined on BSL self-hosts.
	 */
	tier2Lookup?: (domain: string) => Promise<import('../lib/brand-tier2-evidence').Tier2Result>;
}

/** Build QueryDnsOptions for individual check calls from runtime options. */
function buildDnsOptions(runtimeOptions?: ToolRuntimeOptions): QueryDnsOptions | undefined {
	if (!runtimeOptions?.secondaryDoh) return undefined;
	return { secondaryDoh: runtimeOptions.secondaryDoh };
}

/**
 * Construct a closure that calls `enforceBrandAuditQuota` with the principal +
 * tier bound from `ToolRuntimeOptions`. Returns `undefined` when the required
 * bindings/principal aren't present — the tool then falls back to its own
 * graceful path (no enforcement, equivalent to v2.18.0–v2.20.0 behavior).
 *
 * Wired in v2.21.0 to bring the `BRAND_AUDIT_QUOTAS` monthly window helper
 * (shipped as a Phase-1 building block) online at request time. The daily
 * caps via `TIER_TOOL_DAILY_LIMITS` continue to gate brand_audit_single /
 * brand_audit_batch_start as a first-line check; the monthly enforcement
 * applies on top.
 */
function buildMonthlyEnforceQuota(
	ro?: ToolRuntimeOptions,
): ((count: number) => Promise<{ allowed: boolean; remaining?: number; limit?: number; retryAfterMs?: number }>) | undefined {
	if (!ro?.rateLimitKv || !ro.principalId || !ro.authTier) return undefined;
	const tier = ro.authTier as import('../lib/config').McpApiKeyTier;
	const kv = ro.rateLimitKv;
	const principalId = ro.principalId;
	return async (count: number) => {
		const { enforceBrandAuditQuota } = await import('../lib/brand-audit-quota');
		return enforceBrandAuditQuota({ kv, principalId, tier, count });
	};
}

async function dynamicCheckMx(domain: string, runtimeOptions?: ToolRuntimeOptions): Promise<CheckResult> {
	const { checkMx } = await import('../tools/check-mx');
	return checkMx(
		domain,
		{
			providerSignaturesUrl: runtimeOptions?.providerSignaturesUrl,
			providerSignaturesAllowedHosts: runtimeOptions?.providerSignaturesAllowedHosts,
			providerSignaturesSha256: runtimeOptions?.providerSignaturesSha256,
		},
		buildDnsOptions(runtimeOptions),
	);
}

async function dynamicCheckPtr(domain: string, runtimeOptions?: ToolRuntimeOptions): Promise<CheckResult> {
	const { checkPtr } = await import('../tools/check-ptr');
	return checkPtr(
		domain,
		{
			providerSignaturesUrl: runtimeOptions?.providerSignaturesUrl,
			providerSignaturesAllowedHosts: runtimeOptions?.providerSignaturesAllowedHosts,
			providerSignaturesSha256: runtimeOptions?.providerSignaturesSha256,
		},
		buildDnsOptions(runtimeOptions),
	);
}

/** Shared `unprovisioned` result for the brand-audit watch tools when BRAND_AUDIT_DB is absent. */
async function brandAuditWatchUnprovisioned(): Promise<CheckResult> {
	const { buildCheckResult, createFinding } = await import('../lib/scoring');
	return buildCheckResult('brand_discovery', [
		createFinding('brand_discovery', 'Brand audit watch unavailable', 'high', 'BRAND_AUDIT_DB binding is not provisioned.', {
			unprovisioned: true,
		}),
	]);
}

/**
 * Registry mapping tool names to their cache key and execution function.
 * Replaces repetitive switch cases for individual DNS check tools.
 */
export const TOOL_REGISTRY: Record<
	string,
	{
		/** cacheKey may consult runtimeOptions to bind principal (defense against owner-scoped IDOR via cache). */
		cacheKey: (args: Record<string, unknown>, runtimeOptions?: ToolRuntimeOptions) => string;
		execute: (domain: string, args: Record<string, unknown>, runtimeOptions?: ToolRuntimeOptions) => Promise<CheckResult>;
		cacheable?: boolean;
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
	check_ssl: {
		cacheKey: (_a, ro) => (ro?.tlsProbeBinding ? 'ssl:tls-probe' : 'ssl'),
		execute: (d, _args, ro) =>
			checkSsl(d, {
				tlsProbeBinding: ro?.tlsProbeBinding,
				tlsProbeAuthToken: ro?.tlsProbeAuthToken,
				onBindingDegradation: ro?.onBindingDegradation,
			}),
	},
	check_mta_sts: { cacheKey: () => 'mta_sts', execute: (d, _args, ro) => checkMtaSts(d, buildDnsOptions(ro)) },
	check_ns: { cacheKey: () => 'ns', execute: (d, _args, ro) => checkNs(d, buildDnsOptions(ro)) },
	check_caa: { cacheKey: () => 'caa', execute: (d, _args, ro) => checkCaa(d, buildDnsOptions(ro)) },
	check_bimi: { cacheKey: () => 'bimi', execute: (d, _args, ro) => checkBimi(d, buildDnsOptions(ro)) },
	check_tlsrpt: { cacheKey: () => 'tlsrpt', execute: (d, _args, ro) => checkTlsrpt(d, buildDnsOptions(ro)) },
	check_lookalikes: {
		cacheKey: (_a, ro) => (ro?.reconBinding ? 'lookalikes:recon' : 'lookalikes'),
		execute: (d, _args, ro) =>
			checkLookalikes(d, {
				reconBinding: ro?.reconBinding,
				reconAuthToken: ro?.reconAuthToken,
				onBindingDegradation: ro?.onBindingDegradation,
			}),
		cacheTtlSeconds: 3600,
	},
	check_shadow_domains: {
		cacheKey: () => 'shadow_domains',
		execute: (d, _args, ro) => checkShadowDomains(d, buildDnsOptions(ro)),
		cacheTtlSeconds: 3600,
	},
	check_txt_hygiene: { cacheKey: () => 'txt_hygiene', execute: (d, _args, ro) => checkTxtHygiene(d, buildDnsOptions(ro)) },
	check_http_security: { cacheKey: () => 'http_security', execute: (d) => checkHttpSecurity(d) },
	check_dane: { cacheKey: () => 'dane', execute: (d, _args, ro) => checkDane(d, buildDnsOptions(ro)) },
	check_ptr: { cacheKey: () => 'ptr', execute: (d, _args, ro) => dynamicCheckPtr(d, ro) },
	check_dane_https: { cacheKey: () => 'dane_https', execute: (d, _args, ro) => checkDaneHttps(d, buildDnsOptions(ro)) },
	check_svcb_https: { cacheKey: () => 'svcb_https', execute: (d, _args, ro) => checkSvcbHttps(d, buildDnsOptions(ro)) },
	check_mx_reputation: {
		cacheKey: () => 'mx_reputation',
		execute: (d, _args, ro) => checkMxReputation(d, buildDnsOptions(ro)),
		cacheTtlSeconds: 3600,
	},
	check_srv: { cacheKey: () => 'srv', execute: (d, _args, ro) => checkSrv(d, buildDnsOptions(ro)) },
	check_zone_hygiene: { cacheKey: () => 'zone_hygiene', execute: (d, _args, ro) => checkZoneHygiene(d, buildDnsOptions(ro)) },
	check_subdomailing: { cacheKey: () => 'subdomailing', execute: (d, _args, ro) => checkSubdomailing(d, buildDnsOptions(ro)) },
	check_dbl: { cacheKey: () => 'dbl', execute: (d, _args, ro) => checkDbl(d, buildDnsOptions(ro)), cacheTtlSeconds: 3600 },
	check_rbl: { cacheKey: () => 'rbl', execute: (d, _args, ro) => checkRbl(d, buildDnsOptions(ro)), cacheTtlSeconds: 3600 },
	cymru_asn: {
		cacheKey: (_a, ro) => (ro?.reconBinding ? 'asn:recon' : 'asn'),
		execute: (d, _args, ro) =>
			checkCymruAsn(d, buildDnsOptions(ro), {
				reconBinding: ro?.reconBinding,
				reconAuthToken: ro?.reconAuthToken,
				onBindingDegradation: ro?.onBindingDegradation,
			}),
		cacheTtlSeconds: 3600,
	},
	rdap_lookup: {
		cacheKey: () => 'rdap',
		execute: (d, _args, ro) =>
			checkRdapLookup(d, {
				whoisBinding: ro?.whoisBinding,
				signal: AbortSignal.timeout(RDAP_LOOKUP_SYNC_BUDGET_MS),
				deadlineMs: Date.now() + RDAP_LOOKUP_SYNC_BUDGET_MS,
			}),
		cacheTtlSeconds: 3600,
	},
	check_realtime_threat_feed: {
		cacheKey: () => 'realtime_threat_feed',
		execute: (d, _args, ro) =>
			import('../tools/check-realtime-threat-feed').then((m) =>
				m.checkRealtimeThreatFeed(d, {
					reconBinding: ro?.reconBinding,
					reconAuthToken: ro?.reconAuthToken,
					onBindingDegradation: ro?.onBindingDegradation,
				}),
			),
		cacheTtlSeconds: 3600,
	},
	check_nsec_walkability: {
		cacheKey: () => 'nsec_walkability',
		execute: (d, _args, ro) => checkNsecWalkability(d, buildDnsOptions(ro)),
		cacheTtlSeconds: 3600,
	},
	check_dnssec_chain: { cacheKey: () => 'dnssec_chain', execute: (d, _args, ro) => checkDnssecChain(d, buildDnsOptions(ro)) },
	check_agent_discovery: {
		cacheKey: (args) => {
			const protocol = (args.protocol as string | undefined) ?? 'all';
			const name = (args.name as string | undefined) ?? 'zone';
			return `agent_discovery:${protocol}:${name}:${args.verify_cap === true ? 'v' : 'd'}`;
		},
		execute: (d, args, ro) =>
			checkAgentDiscovery(
				d,
				{
					protocol: args.protocol as AgentProtocol | undefined,
					name: args.name as string | undefined,
					verifyCap: args.verify_cap === true,
				},
				buildDnsOptions(ro),
			),
	},
	check_dnskey_strength: { cacheKey: () => 'dnskey_strength', execute: (d, _args, ro) => checkDnskeyStrength(d, buildDnsOptions(ro)) },
	check_fast_flux: {
		cacheKey: (_a, ro) => (ro?.reconBinding ? 'fast_flux:recon' : 'fast_flux'),
		execute: (d, args, ro) =>
			checkFastFlux(d, (args.rounds as number | undefined) ?? 3, buildDnsOptions(ro), undefined, {
				reconBinding: ro?.reconBinding,
				reconAuthToken: ro?.reconAuthToken,
				onBindingDegradation: ro?.onBindingDegradation,
			}),
	},
	check_subdomain_takeover: {
		cacheKey: (args) => {
			const subs = Array.isArray(args.subdomains) ? (args.subdomains as string[]) : null;
			// Cache key folds caller-supplied list CONTENTS (not just size) so two
			// different same-length lists don't collide on one entry (5-min TTL,
			// global per domain+checkName) — mirrors the discover_brand_domains
			// sibling. Sorted + length-prefixed + bounded to keep keys finite.
			return subs && subs.length > 0
				? `subdomain_takeover:custom:${subs.length}:${subs.slice().sort().join('|').slice(0, 128)}`
				: 'subdomain_takeover:default';
		},
		execute: (d, args, ro) => {
			const subs = Array.isArray(args.subdomains) ? (args.subdomains as string[]) : undefined;
			return checkSubdomainTakeover(d, buildDnsOptions(ro), subs ? { subdomains: subs } : undefined);
		},
	},
	check_authoritative_dns_infra: {
		cacheKey: () => 'authoritative_dns_infra',
		execute: (d, _args, ro) => checkAuthoritativeDnsInfra(d, { infraProbe: ro?.infraProbe }),
	},
	check_root_server_set: {
		cacheKey: () => 'root_server_set',
		execute: (_d, _args, ro) => checkRootServerSet({ infraProbe: ro?.infraProbe }),
		cacheable: false,
	},
	discover_brand_domains: {
		cacheKey: (args) => {
			const signals = (args.signals as string[] | undefined)?.slice().sort().join(',') ?? 'all';
			const minConf = typeof args.min_confidence === 'number' ? args.min_confidence : 0.5;
			const depth = typeof args.depth === 'string' ? args.depth : 'standard';
			const plannerMode = typeof args.planner_mode === 'string' ? args.planner_mode : 'observe';
			// Discovery mode is part of the cache key. `classic` and `tiered`
			// produce different candidate sets (tiered layers Tier 0/1/2 lookups
			// in front of the legacy sweep), so a shared cache entry would let
			// whichever invocation ran first silently win for the next TTL window
			// — exactly the symptom T7 was trying to fix. Schema default is
			// `'classic'`.
			const discoveryMode = typeof args.discovery_mode === 'string' ? args.discovery_mode : 'classic';
			const aliases = (args.brand_aliases as string[] | undefined) ?? [];
			const candDomains = (args.candidate_domains as string[] | undefined) ?? [];
			const aliasHash = aliases.length === 0 ? '0' : `${aliases.length}:${aliases.slice().sort().join('|').slice(0, 64)}`;
			const candHash = candDomains.length === 0 ? '0' : `${candDomains.length}:${candDomains.slice().sort().join('|').slice(0, 64)}`;
			return `discover_brand:${signals}:d${depth}:p${plannerMode}:dm${discoveryMode}:a${aliasHash}:c${candHash}:m${minConf}`;
		},
		execute: (d, args, ro) => {
			// Bound the synchronous discovery against the server's 28s tool-call
			// cap. Without this, a slow/hanging signal (notably the SAN/CT crt.sh
			// lookup, which retries up to 3× at 15s each ≈ 46s) runs past the
			// `Promise.race` deadline below — and because that race only *rejects*
			// (it can't abort in-flight work), the call surfaces `__tool_timeout__`
			// and the other six signals' completed results are discarded.
			//
			// Threading a deadline-derived AbortSignal makes the SAN retries
			// cancellable (correlateSans composes it via AbortSignal.any) and lets
			// the orchestrator return whatever the fast signals gathered, marking
			// the sweep `partial`. `deadlineMs` additionally arms the recursive-SAN
			// headroom guard. Budget mirrors `brand_audit_single`'s sync-handoff
			// margin so we settle before the 28s race fires.
			const deadlineMs = Date.now() + DISCOVER_BRAND_DOMAINS_SYNC_BUDGET_MS;
			return discoverBrandDomains(
				d,
				{
					signals: args.signals as Parameters<typeof discoverBrandDomains>[1] extends infer O
						? O extends { signals?: infer S }
							? S
							: undefined
						: undefined,
					depth: args.depth as 'standard' | 'deep' | undefined,
					planner_mode: args.planner_mode as 'off' | 'observe' | 'enforce' | undefined,
					discovery_mode: args.discovery_mode as 'classic' | 'tiered' | undefined,
					brand_aliases: args.brand_aliases as string[] | undefined,
					candidate_domains: args.candidate_domains as string[] | undefined,
					dkim_selectors: args.dkim_selectors as string[] | undefined,
					min_confidence: args.min_confidence as number | undefined,
					certstream: ro?.certstream,
					certstreamAuthToken: ro?.certstreamAuthToken,
					deadlineMs,
					signal: AbortSignal.timeout(DISCOVER_BRAND_DOMAINS_SYNC_BUDGET_MS),
				},
				// Tier closures forwarded only when present — BSL self-hosts that lack
				// the bindings pass nothing (the discoverer then sees `undefined`
				// closures and falls back to classic-mode behaviour).
				//
				// `DiscoverBrandDomainsDeps` declares its non-tier signal stubs as
				// required; the runtime tolerates partials (it merges over its own
				// `defaultDeps()`). Existing call sites cast — match that pattern.
				{
					...(ro?.tier0Lookup ? { tier0Lookup: ro.tier0Lookup } : {}),
					...(ro?.tier1Lookup ? { tier1Lookup: ro.tier1Lookup } : {}),
					...(ro?.tier2Lookup ? { tier2Lookup: ro.tier2Lookup } : {}),
				} as Parameters<typeof discoverBrandDomains>[2],
			);
		},
		cacheTtlSeconds: 3600,
	},
	discover_brand_domains_start: {
		// Async producer — not cacheable. Random UUID keeps every call a cache-miss.
		cacheKey: () => `__nocache__:discover_brand_domains_start:${crypto.randomUUID()}`,
		execute: async (domain, args, ro) => {
			const db = ro?.brandAuditDb;
			const queue = ro?.brandAuditQueue;
			const principalId = ro?.principalId ?? ro?.keyHash ?? 'anonymous';
			if (!db || !queue) {
				const { buildCheckResult, createFinding } = await import('../lib/scoring');
				return buildCheckResult('brand_discovery', [
					createFinding(
						'brand_discovery',
						'Async brand-domain discovery unavailable',
						'high',
						'BRAND_AUDIT_DB or BRAND_AUDIT_QUEUE binding is not provisioned. See docs/provisioning/brand-audit-bindings.md.',
						{ unprovisioned: true },
					),
				]);
			}
			return discoverBrandDomainsStart(
				domain,
				{
					signals: args.signals as string[] | undefined,
					depth: args.depth as 'standard' | 'deep' | undefined,
					planner_mode: args.planner_mode as 'off' | 'observe' | 'enforce' | undefined,
					brand_aliases: args.brand_aliases as string[] | undefined,
					candidate_domains: args.candidate_domains as string[] | undefined,
					dkim_selectors: args.dkim_selectors as string[] | undefined,
					min_confidence: args.min_confidence as number | undefined,
					discovery_mode: args.discovery_mode as 'classic' | 'tiered' | undefined,
					ownership_verified: args.ownership_verified as boolean | undefined,
				},
				principalId,
				{ db, queue },
			);
		},
		cacheTtlSeconds: 0,
	},
	discover_brand_domains_status: {
		// Mutable polling read — do not cache. Reuses the brand-audit status reader
		// keyed on the operationId (= the brand_audits row id).
		cacheKey: (args, ro) => `discover_brand_domains_status:${ro?.principalId ?? ro?.keyHash ?? 'anon'}:${String(args.operationId ?? '')}`,
		execute: async (_domain, args, ro) => {
			const db = ro?.brandAuditDb;
			const principalId = ro?.principalId ?? ro?.keyHash ?? 'anonymous';
			if (!db) {
				const { buildCheckResult, createFinding } = await import('../lib/scoring');
				return buildCheckResult('brand_discovery', [
					createFinding(
						'brand_discovery',
						'Async brand-domain discovery status unavailable',
						'high',
						'BRAND_AUDIT_DB binding is not provisioned.',
						{
							unprovisioned: true,
						},
					),
				]);
			}
			return brandAuditStatus(String(args.operationId ?? ''), principalId, { db });
		},
		cacheable: false,
	},
	discover_brand_domains_findings: {
		// Mutable read — do not cache. Reuses the brand-audit get-report reader
		// (per-target mode) to surface the discovery CheckResult.
		cacheKey: (args, ro) => `discover_brand_domains_findings:${ro?.principalId ?? ro?.keyHash ?? 'anon'}:${String(args.operationId ?? '')}`,
		execute: async (_domain, args, ro) => {
			const db = ro?.brandAuditDb;
			const principalId = ro?.principalId ?? ro?.keyHash ?? 'anonymous';
			if (!db) {
				const { buildCheckResult, createFinding } = await import('../lib/scoring');
				return buildCheckResult('brand_discovery', [
					createFinding(
						'brand_discovery',
						'Async brand-domain discovery findings unavailable',
						'high',
						'BRAND_AUDIT_DB binding is not provisioned.',
						{
							unprovisioned: true,
						},
					),
				]);
			}
			return discoverBrandDomainsFindings(String(args.operationId ?? ''), principalId, { db });
		},
		cacheable: false,
	},
	brand_audit_single: {
		cacheKey: (args, ro) => {
			const minConf = typeof args.min_confidence === 'number' ? args.min_confidence : 0.5;
			const fmt = typeof args.format === 'string' ? args.format : 'both';
			const depth = typeof args.depth === 'string' ? args.depth : 'standard';
			const plannerMode = typeof args.planner_mode === 'string' ? args.planner_mode : 'observe';
			// Discovery mode is part of the cache key — see the discover_brand_domains
			// cache-key comment above for the poisoning rationale. We hash on the
			// *effective* mode the pipeline will run: explicit arg wins, otherwise
			// the env-default (`BRAND_AUDIT_DISCOVERY_MODE_DEFAULT`) flips classic→tiered
			// on BlackVeil production deploys. Schema default falls back to `classic`.
			const discoveryMode =
				typeof args.discovery_mode === 'string' ? args.discovery_mode : ro?.discoveryModeDefault === 'tiered' ? 'tiered' : 'classic';
			const aliases = (args.brand_aliases as string[] | undefined) ?? [];
			const candDomains = (args.candidate_domains as string[] | undefined) ?? [];
			const aliasHash = aliases.length === 0 ? '0' : `${aliases.length}:${aliases.slice().sort().join('|').slice(0, 64)}`;
			const candHash = candDomains.length === 0 ? '0' : `${candDomains.length}:${candDomains.slice().sort().join('|').slice(0, 64)}`;
			const view = typeof args.view === 'string' ? args.view : 'standard';
			return `brand_audit_single:${fmt}:d${depth}:p${plannerMode}:dm${discoveryMode}:a${aliasHash}:c${candHash}:m${minConf}:vw${view}`;
		},
		execute: (d, args, ro) => {
			const deadlineMs = Date.now() + BRAND_AUDIT_SINGLE_SYNC_HANDOFF_MS;
			return brandAuditSingle(
				d,
				{
					format: args.format as 'json' | 'markdown' | 'both' | undefined,
					min_confidence: args.min_confidence as number | undefined,
					depth: args.depth as 'standard' | 'deep' | undefined,
					planner_mode: args.planner_mode as 'off' | 'observe' | 'enforce' | undefined,
					discovery_mode: args.discovery_mode as 'classic' | 'tiered' | undefined,
					brand_aliases: args.brand_aliases as string[] | undefined,
					candidate_domains: args.candidate_domains as string[] | undefined,
					view: args.view as 'standard' | 'csc_complement' | undefined,
					// T13 — propagate the BlackVeil-production runtime override.
					// Pipeline only honours it when the caller omits `discovery_mode`;
					// undefined on BSL self-hosts (schema default `'classic'` wins).
					...(ro?.discoveryModeDefault ? { env: { BRAND_AUDIT_DISCOVERY_MODE_DEFAULT: ro.discoveryModeDefault } } : {}),
					deadlineMs,
					timeoutBehavior: 'async_handoff',
				},
				{
					certstream: ro?.certstream,
					certstreamAuthToken: ro?.certstreamAuthToken,
					whoisBinding: ro?.whoisBinding,
					enforceQuota: buildMonthlyEnforceQuota(ro),
					// The brand-audit queue binding doubles as the CSC fast→full
					// deep-scan trigger in the pipeline (brand-audit-pipeline.ts:1061).
					// Without it, sync view='csc_complement' audits write only the
					// fast payload and brand_audit_get_report can never surface the
					// full enrichment.
					...(ro?.brandAuditQueue ? { brandAuditQueue: ro.brandAuditQueue } : {}),
					// Tier closures: forwarded through the pipeline → discoverBrandDomains
					// seam. Undefined on BSL self-hosts → pipeline never calls the
					// proprietary lookups.
					...(ro?.tier0Lookup ? { tier0Lookup: ro.tier0Lookup } : {}),
					...(ro?.tier1Lookup ? { tier1Lookup: ro.tier1Lookup } : {}),
					...(ro?.tier2Lookup ? { tier2Lookup: ro.tier2Lookup } : {}),
				},
			);
		},
		cacheTtlSeconds: 3600,
	},
	brand_audit_batch_start: {
		// Async producer — not cacheable. Each invocation enqueues fresh work.
		// Random UUID keeps every call a cache-miss; brief KV write churn is the cost.
		cacheKey: () => `__nocache__:brand_audit_batch_start:${crypto.randomUUID()}`,
		execute: async (_domain, args, ro) => {
			const db = ro?.brandAuditDb;
			const queue = ro?.brandAuditQueue;
			const principalId = ro?.principalId ?? ro?.keyHash ?? 'anonymous';
			if (!db || !queue) {
				const { buildCheckResult, createFinding } = await import('../lib/scoring');
				return buildCheckResult('brand_discovery', [
					createFinding(
						'brand_discovery',
						'Brand audit batch unavailable',
						'high',
						'BRAND_AUDIT_DB or BRAND_AUDIT_QUEUE binding is not provisioned. See docs/provisioning/brand-audit-bindings.md.',
						{ unprovisioned: true },
					),
				]);
			}
			return brandAuditBatchStart(
				args.domains as string[],
				{
					format: args.format as 'json' | 'markdown' | 'both' | undefined,
					min_confidence: args.min_confidence as number | undefined,
					depth: args.depth as 'standard' | 'deep' | undefined,
					planner_mode: args.planner_mode as 'off' | 'observe' | 'enforce' | undefined,
					brand_aliases: args.brand_aliases as string[] | undefined,
					candidate_domains: args.candidate_domains as string[] | undefined,
					discovery_mode: args.discovery_mode as 'classic' | 'tiered' | undefined,
					view: args.view as 'standard' | 'csc_complement' | undefined,
				},
				principalId,
				{ db, queue, enforceQuota: buildMonthlyEnforceQuota(ro) },
			);
		},
		cacheTtlSeconds: 0,
	},
	brand_audit_status: {
		// Mutable polling read — do not cache. A stale queued/notReady state can
		// make report generators time out even after the queue consumer has completed.
		// Keep owner in the key shape for logging/debug consistency only.
		cacheKey: (args, ro) => `brand_audit_status:${ro?.principalId ?? ro?.keyHash ?? 'anon'}:${String(args.auditId ?? '')}`,
		execute: async (_domain, args, ro) => {
			const db = ro?.brandAuditDb;
			const principalId = ro?.principalId ?? ro?.keyHash ?? 'anonymous';
			if (!db) {
				const { buildCheckResult, createFinding } = await import('../lib/scoring');
				return buildCheckResult('brand_discovery', [
					createFinding('brand_discovery', 'Brand audit status unavailable', 'high', 'BRAND_AUDIT_DB binding is not provisioned.', {
						unprovisioned: true,
					}),
				]);
			}
			return brandAuditStatus(String(args.auditId ?? ''), principalId, { db, stepStore: createD1BrandAuditStepStore(db) });
		},
		cacheable: false,
	},
	brand_audit_get_report: {
		// Mutable read — do not cache. Before completion this can return notReady,
		// and after completion the PDF sidecar URL/pending state can change.
		cacheKey: (args, ro) =>
			`brand_audit_report:${ro?.principalId ?? ro?.keyHash ?? 'anon'}:${String(args.auditId ?? '')}:${String(args.target ?? '')}`,
		execute: async (_domain, args, ro) => {
			const db = ro?.brandAuditDb;
			const principalId = ro?.principalId ?? ro?.keyHash ?? 'anonymous';
			if (!db) {
				const { buildCheckResult, createFinding } = await import('../lib/scoring');
				return buildCheckResult('brand_discovery', [
					createFinding('brand_discovery', 'Brand audit get-report unavailable', 'high', 'BRAND_AUDIT_DB binding is not provisioned.', {
						unprovisioned: true,
					}),
				]);
			}
			return brandAuditGetReport({ auditId: String(args.auditId ?? ''), target: args.target as string | undefined }, principalId, {
				db,
				bucket: ro?.brandReportsR2 as
					| { createSignedUrl?: (input: { key: string; expiresInSeconds: number }) => Promise<string> }
					| undefined,
				stepStore: createD1BrandAuditStepStore(db),
			});
		},
		cacheable: false,
	},
	list_brand_audit_watches: {
		// Read-only, but watch state is mutable — never cache.
		cacheKey: () => `__nocache__:list_brand_audit_watches:${crypto.randomUUID()}`,
		execute: async (_domain, _args, ro) => {
			const db = ro?.brandAuditDb;
			const principalId = ro?.principalId ?? ro?.keyHash ?? 'anonymous';
			if (!db) return brandAuditWatchUnprovisioned();
			return listBrandAuditWatches(principalId, { db });
		},
		cacheTtlSeconds: 0,
	},
	register_brand_audit_watch: {
		// Mutating tool — random UUID keeps every call a cache-miss.
		cacheKey: () => `__nocache__:register_brand_audit_watch:${crypto.randomUUID()}`,
		execute: async (domain, args, ro) => {
			const db = ro?.brandAuditDb;
			const principalId = ro?.principalId ?? ro?.keyHash ?? 'anonymous';
			if (!db) return brandAuditWatchUnprovisioned();
			return registerBrandAuditWatch(
				{
					domain,
					interval: args.interval as 'daily' | 'weekly' | 'monthly' | undefined,
					webhook_url: args.webhook_url as string | undefined,
				},
				principalId,
				{ db },
			);
		},
		cacheTtlSeconds: 0,
	},
	delete_brand_audit_watch: {
		// Destructive tool — random UUID keeps every call a cache-miss.
		cacheKey: () => `__nocache__:delete_brand_audit_watch:${crypto.randomUUID()}`,
		execute: async (_domain, args, ro) => {
			const db = ro?.brandAuditDb;
			const principalId = ro?.principalId ?? ro?.keyHash ?? 'anonymous';
			if (!db) return brandAuditWatchUnprovisioned();
			return deleteBrandAuditWatch({ watchId: args.watchId as string | undefined }, principalId, { db });
		},
		cacheTtlSeconds: 0,
	},
	scan_buckets_start: {
		// Async producer — not cacheable. Each invocation enqueues fresh work.
		cacheKey: () => `__nocache__:scan_buckets_start:${crypto.randomUUID()}`,
		execute: (_d, args, ro) =>
			import('../tools/scan-buckets').then((m) =>
				m.scanBucketsStart(
					{ target: String(args.target), providers: Array.isArray(args.providers) ? (args.providers as string[]) : undefined },
					{
						reconBinding: ro?.reconBinding,
						reconAuthToken: ro?.reconAuthToken,
						bucketScanKv: ro?.rateLimitKv,
						onBindingDegradation: ro?.onBindingDegradation,
					},
				),
			),
		cacheTtlSeconds: 0,
	},
	scan_buckets_status: {
		cacheKey: (a) => `bucketstatus:${String(a.scanId)}`,
		execute: (_d, a, ro) =>
			import('../tools/scan-buckets').then((m) =>
				m.scanBucketsStatus(
					{ scanId: String(a.scanId) },
					{
						reconBinding: ro?.reconBinding,
						reconAuthToken: ro?.reconAuthToken,
						bucketScanKv: ro?.rateLimitKv,
						onBindingDegradation: ro?.onBindingDegradation,
					},
				),
			),
		cacheTtlSeconds: 15,
	},
	scan_buckets_findings: {
		cacheKey: (a) => `bucketfindings:${String(a.scanId ?? 'all')}:${String(a.target ?? '')}:${JSON.stringify(a.providers ?? [])}`,
		execute: (_d, a, ro) =>
			import('../tools/scan-buckets').then((m) =>
				m.scanBucketsFindings(
					{
						scanId: a.scanId ? String(a.scanId) : undefined,
						target: a.target ? String(a.target) : undefined,
						providers: Array.isArray(a.providers) ? (a.providers as string[]) : undefined,
					},
					{
						reconBinding: ro?.reconBinding,
						reconAuthToken: ro?.reconAuthToken,
						bucketScanKv: ro?.rateLimitKv,
						onBindingDegradation: ro?.onBindingDegradation,
					},
				),
			),
		cacheTtlSeconds: 30,
	},
	osint_investigate_domain_start: {
		cacheKey: () => `__nocache__:osint_investigate_domain_start:${crypto.randomUUID()}`,
		execute: (_d, a, ro) =>
			import('../tools/osint-investigate').then((m) =>
				m.osintInvestigateDomainStart(String(a.query), {
					reconBinding: ro?.reconBinding,
					reconAuthToken: ro?.reconAuthToken,
					onBindingDegradation: ro?.onBindingDegradation,
				}),
			),
		cacheTtlSeconds: 0,
	},
	osint_investigate_infrastructure_start: {
		cacheKey: () => `__nocache__:osint_investigate_infrastructure_start:${crypto.randomUUID()}`,
		execute: (_d, a, ro) =>
			import('../tools/osint-investigate').then((m) =>
				m.osintInvestigateInfrastructureStart(String(a.query), {
					reconBinding: ro?.reconBinding,
					reconAuthToken: ro?.reconAuthToken,
					onBindingDegradation: ro?.onBindingDegradation,
				}),
			),
		cacheTtlSeconds: 0,
	},
	osint_investigate_supply_chain_start: {
		cacheKey: () => `__nocache__:osint_investigate_supply_chain_start:${crypto.randomUUID()}`,
		execute: (_d, a, ro) =>
			import('../tools/osint-investigate').then((m) =>
				m.osintInvestigateSupplyChainStart(String(a.query), {
					reconBinding: ro?.reconBinding,
					reconAuthToken: ro?.reconAuthToken,
					onBindingDegradation: ro?.onBindingDegradation,
				}),
			),
		cacheTtlSeconds: 0,
	},
	osint_investigate_username_start: {
		cacheKey: () => `__nocache__:osint_investigate_username_start:${crypto.randomUUID()}`,
		execute: (_d, a, ro) =>
			import('../tools/osint-people').then((m) =>
				m.osintInvestigateUsernameStart(String(a.query), {
					reconBinding: ro?.reconBinding,
					reconAuthToken: ro?.reconAuthToken,
					authTier: ro?.authTier,
					onBindingDegradation: ro?.onBindingDegradation,
				}),
			),
		cacheTtlSeconds: 0,
	},
	osint_investigate_email_start: {
		cacheKey: () => `__nocache__:osint_investigate_email_start:${crypto.randomUUID()}`,
		execute: (_d, a, ro) =>
			import('../tools/osint-people').then((m) =>
				m.osintInvestigateEmailStart(String(a.query), {
					reconBinding: ro?.reconBinding,
					reconAuthToken: ro?.reconAuthToken,
					authTier: ro?.authTier,
					onBindingDegradation: ro?.onBindingDegradation,
				}),
			),
		cacheTtlSeconds: 0,
	},
	osint_investigation_status: {
		cacheKey: (a) => `osintstatus:${String(a.investigationId)}`,
		execute: (_d, a, ro) =>
			import('../tools/osint-investigate').then((m) =>
				m.osintInvestigationStatus(String(a.investigationId), {
					reconBinding: ro?.reconBinding,
					reconAuthToken: ro?.reconAuthToken,
					onBindingDegradation: ro?.onBindingDegradation,
				}),
			),
		cacheTtlSeconds: 15,
	},
	osint_investigation_report: {
		cacheKey: (a) => `osintreport:${String(a.investigationId)}`,
		execute: (_d, a, ro) =>
			import('../tools/osint-investigate').then((m) =>
				m.osintInvestigationReport(String(a.investigationId), {
					reconBinding: ro?.reconBinding,
					reconAuthToken: ro?.reconAuthToken,
					onBindingDegradation: ro?.onBindingDegradation,
				}),
			),
		cacheTtlSeconds: 30,
	},
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
const BRAND_AUDIT_SINGLE_SYNC_HANDOFF_MS = 24_000;
/**
 * Wall-clock budget for the synchronous `discover_brand_domains` tool path,
 * threaded into `discoverBrandDomains` as both `deadlineMs` and a derived
 * `AbortSignal.timeout(...)`. Kept inside `TOOL_CALL_TIMEOUT_MS` so the
 * orchestrator aborts slow signals (SAN/CT crt.sh retries) and returns the
 * fast signals' partial results *before* the 28s `Promise.race` rejects the
 * whole call. Mirrors the brand_audit_single sync-handoff margin.
 */
const DISCOVER_BRAND_DOMAINS_SYNC_BUDGET_MS = 24_000;

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

		const effectiveFormat = resolveFormat(validatedArgs, runtimeOptions?.clientType);
		const _interactive = isInteractiveClient(runtimeOptions?.clientType);

		const executeDispatch = async (): Promise<McpToolResult> => {
			// Defense-in-depth (P1): the identity_secops M365 tools forward to bv-web's
			// internal proxy carrying the trusted internal bearer. If the dangerous
			// forward is actually possible (m365Proxy bound) but there is no real
			// principal (no keyHash), never forward keyHash:undefined alongside that
			// bearer — hard-reject here even if an upstream gate were bypassed. Gated on
			// m365Proxy presence so the `/internal/*` path (which wires neither m365Proxy
			// nor keyHash) keeps its fail-soft `unprovisioned` behavior unchanged. The
			// public /mcp gate (execute.ts) is the primary control; this is the backstop.
			if (isAuthRequiredTool(name) && runtimeOptions?.m365Proxy && !runtimeOptions?.keyHash) {
				logToolFailure({ ...ctx(), error: 'm365_proxy_unauthenticated', args });
				return buildToolErrorResult('Invalid request: m365_proxy_unauthenticated (authentication required).');
			}

			// Tier gate: csc_complement view requires enterprise or owner tier.
			if (name === 'brand_audit_single' || name === 'brand_audit_batch_start') {
				const requestedView = (validatedArgs as { view?: string }).view;
				if (requestedView === 'csc_complement') {
					const tier = runtimeOptions?.authTier;
					if (tier !== 'enterprise' && tier !== 'owner') {
						return buildToolErrorResult("Invalid view: 'csc_complement' requires enterprise tier");
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
				const checkName = registeredTool.cacheKey(validatedArgs, runtimeOptions);
				// Versioned (cache:v<version>:...) so a deploy auto-invalidates — see buildCheckCacheKey.
				const cacheKey = buildCheckCacheKey(validDomain, checkName);
				let cacheStatus: 'hit' | 'miss' = 'miss';
				let result: CheckResult;
				if (registeredTool.cacheable === false) {
					result = await registeredTool.execute(validDomain, validatedArgs, runtimeOptions);
				} else {
					// Don't cache partial results (e.g. lookalike timeout). The predicate skips the
					// kv.put entirely instead of the old put-then-delete anti-pattern that drove
					// ~13M wasted SCAN_CACHE writes/week (bv-web 2026-05-14 analytics, cluster F5).
					const tracked = await runWithCacheTracked(
						cacheKey,
						() => registeredTool.execute(validDomain, validatedArgs, runtimeOptions),
						scanCacheKV,
						registeredTool.cacheTtlSeconds,
						/* skipCache */ extractForceRefresh(validatedArgs),
						(r) => !r.partial,
					);
					result = tracked.data;
					cacheStatus = tracked.cacheStatus;
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
				return buildToolResult(formatCheckResult(result, effectiveFormat), result, effectiveFormat);
			}

			switch (name) {
				case 'scan_domain': {
					const profile = extractScanProfile(validatedArgs);
					const forceRefresh = extractForceRefresh(validatedArgs);
					const scanOptions = { ...runtimeOptions, ...(profile && { profile }), ...(forceRefresh && { forceRefresh }) };
					const result = await scanDomain(validDomain, scanCacheKV, scanOptions);
					logResult = result.score.grade;
					logDetails = result;
					// scanDomain sets `cached: true` only when the top-level cache:<domain>
					// key returned a hit. Threading that into the analytics emit so
					// `tool_call.blob8` reflects the orchestrator-level cache hit/miss
					// (was 'n/a' for every scan_domain call before — drowned the leaf
					// tools' real hit-rate signal in the .dev/analytics-30d.mjs report).
					const cacheStatus: 'hit' | 'miss' = result.cached ? 'hit' : 'miss';
					logToolSuccess({
						...ctx(),
						status: result.score.overall >= 50 ? 'pass' : 'fail',
						logResult,
						logDetails,
						severity: 'info',
						cacheStatus,
					});
					const structured = buildStructuredScanResult(result, {
						scoringConfigHash: computeScoringConfigHash(runtimeOptions?.scoringConfig),
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
					logToolSuccess({
						...ctx(),
						status: 'pass',
						logResult: `${batchResults.filter((r) => !r.error).length}/${batchResults.length} domains`,
						logDetails: { totalDomains: batchResults.length },
						severity: 'info',
					});
					return buildToolResult(batchText, batchResults, effectiveFormat);
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
						logResult: `${Object.keys(compareResults.scores).length}/${compareResults.domains.length} domains compared`,
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
					logResult = result.passed ? 'pass' : 'fail';
					logDetails = result;
					logToolSuccess({ ...ctx(), status: result.passed ? 'pass' : 'fail', logResult, logDetails, severity: 'info' });
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
							logResult = plan.grade;
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
					logToolSuccess({ ...ctx(), status: result.representative ? 'pass' : 'pass', logResult: result.status, logDetails, severity: 'info' });
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
					const result = await getProviderInsights(runtimeOptions?.profileAccumulator, provider, profile, runtimeOptions?.profileAccumulatorShardMode);
					logToolSuccess({ ...ctx(), status: 'pass', logResult: result.status, logDetails: result, severity: 'info' });
					return buildToolResult(formatProviderInsights(result, effectiveFormat), result, effectiveFormat);
				}
				case 'assess_spoofability': {
					const result = await assessSpoofability(validDomain, buildDnsOptions(runtimeOptions));
					logResult = result.riskLevel;
					logDetails = result;
					logToolSuccess({ ...ctx(), status: result.spoofabilityScore <= 30 ? 'pass' : 'fail', logResult, logDetails, severity: 'info' });
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

					const forceRefresh = extractForceRefresh(validatedArgs);
					const scanOptions = { ...runtimeOptions, ...(forceRefresh && { forceRefresh }) };
					const scanResult = await scanDomain(validDomain, scanCacheKV, scanOptions);
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
					const result = await discoverSubdomains(validDomain, runtimeOptions?.certstream, runtimeOptions?.certstreamAuthToken, {
						signal: AbortSignal.timeout(DISCOVER_SUBDOMAINS_SYNC_BUDGET_MS),
						deadlineMs: Date.now() + DISCOVER_SUBDOMAINS_SYNC_BUDGET_MS,
					});
					logResult = `${result.totalSubdomains} subdomains`;
					logDetails = { totalSubdomains: result.totalSubdomains, issues: result.issues.length };
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
				case 'simulate_attack_paths': {
					const result = await simulateAttackPaths(validDomain, buildDnsOptions(runtimeOptions));
					logResult = `${result.totalPaths} paths, risk: ${result.overallRisk}`;
					logDetails = { totalPaths: result.totalPaths, overallRisk: result.overallRisk };
					logToolSuccess({ ...ctx(), status: result.overallRisk === 'low' ? 'pass' : 'fail', logResult, logDetails, severity: 'info' });
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
						{ authToken: runtimeOptions?.m365ProxyAuthToken, keyHash: runtimeOptions?.keyHash },
					);
					logResult = result.ok ? 'ok' : 'error';
					logDetails = result;
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
						{ authToken: runtimeOptions?.m365ProxyAuthToken, keyHash: runtimeOptions?.keyHash },
					);
					logResult = result.ok ? 'ok' : 'error';
					logDetails = result;
					logToolSuccess({ ...ctx(), status: result.ok ? 'pass' : 'fail', logResult, logDetails, severity: 'info' });
					const text = JSON.stringify(result, null, effectiveFormat === 'compact' ? 0 : 2);
					return buildToolResult(text, result, effectiveFormat);
				}
				case 'get_ca_policies': {
					const result = await getCaPolicies({ ms_tenant_id: String(validatedArgs.ms_tenant_id) }, runtimeOptions?.m365Proxy, {
						authToken: runtimeOptions?.m365ProxyAuthToken,
						keyHash: runtimeOptions?.keyHash,
					});
					logResult = result.ok ? 'ok' : 'error';
					logDetails = result;
					logToolSuccess({ ...ctx(), status: result.ok ? 'pass' : 'fail', logResult, logDetails, severity: 'info' });
					const text = JSON.stringify(result, null, effectiveFormat === 'compact' ? 0 : 2);
					return buildToolResult(text, result, effectiveFormat);
				}
				case 'assess_coverage': {
					const result = await assessCoverage({ ms_tenant_id: String(validatedArgs.ms_tenant_id) }, runtimeOptions?.m365Proxy, {
						authToken: runtimeOptions?.m365ProxyAuthToken,
						keyHash: runtimeOptions?.keyHash,
					});
					logResult = result.ok ? 'ok' : 'error';
					logDetails = result;
					logToolSuccess({ ...ctx(), status: result.ok ? 'pass' : 'fail', logResult, logDetails, severity: 'info' });
					const text = JSON.stringify(result, null, effectiveFormat === 'compact' ? 0 : 2);
					return buildToolResult(text, result, effectiveFormat);
				}
				default:
					logToolFailure({ ...ctx(), error: `Unknown tool: ${name}`, args });
					return buildToolErrorResult(`Unknown tool: ${name}. Call tools/list to see all ${TOOLS.length} available tools.`);
			}
		};

		// Mutating *_start/register tools: collapse a client network-retry that
		// re-sends identical args onto the prior successful result, so it doesn't
		// create a duplicate watch/scan/investigation (#363 item 3). Skipped without
		// an authenticated principal or KV — see withRequestDedup. The dedup wrapper
		// sits INSIDE the timeout race so a replay is still bounded.
		const dedupKv = runtimeOptions?.rateLimitKv;
		const dispatch =
			MUTATING_DEDUP_TOOLS.has(name) && dedupKv
				? () =>
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
						)
				: executeDispatch;

		return await Promise.race([
			dispatch(),
			new Promise<never>((_, reject) => setTimeout(() => reject(new Error('__tool_timeout__')), TOOL_CALL_TIMEOUT_MS)),
		]);
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
