// SPDX-License-Identifier: BUSL-1.1

import type { CheckResult } from '../lib/scoring';
import type { QueryDnsOptions, SecondaryDohConfig } from '../lib/dns-types';
import { runWithCacheTracked } from '../lib/cache';
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
import { checkRdapLookup } from '../tools/check-rdap-lookup';
import { checkNsecWalkability } from '../tools/check-nsec-walkability';
import { checkDnssecChain } from '../tools/check-dnssec-chain';
import { checkFastFlux } from '../tools/check-fast-flux';
import { discoverBrandDomains } from '../tools/discover-brand-domains';
import { brandAuditSingle } from '../tools/brand-audit-single';
import { brandAuditBatchStart } from '../tools/brand-audit-batch-start';
import { brandAuditStatus } from '../tools/brand-audit-status';
import { brandAuditGetReport } from '../tools/brand-audit-get-report';
import { brandAuditWatch } from '../tools/brand-audit-watch';
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
	whoisBinding?: { fetch: typeof fetch };
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
function buildMonthlyEnforceQuota(ro?: ToolRuntimeOptions): ((count: number) => Promise<{ allowed: boolean; remaining?: number; limit?: number; retryAfterMs?: number }>) | undefined {
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
	rdap_lookup: { cacheKey: () => 'rdap', execute: (d, _args, ro) => checkRdapLookup(d, { whoisBinding: ro?.whoisBinding }), cacheTtlSeconds: 3600 },
	check_nsec_walkability: { cacheKey: () => 'nsec_walkability', execute: (d, _args, ro) => checkNsecWalkability(d, buildDnsOptions(ro)), cacheTtlSeconds: 3600 },
	check_dnssec_chain: { cacheKey: () => 'dnssec_chain', execute: (d, _args, ro) => checkDnssecChain(d, buildDnsOptions(ro)) },
	check_fast_flux: { cacheKey: () => 'fast_flux', execute: (d, args, ro) => checkFastFlux(d, (args.rounds as number | undefined) ?? 3, buildDnsOptions(ro)) },
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
		execute: (d, args, ro) =>
			discoverBrandDomains(
				d,
				{
					signals: args.signals as Parameters<typeof discoverBrandDomains>[1] extends infer O ? (O extends { signals?: infer S } ? S : undefined) : undefined,
					depth: args.depth as 'standard' | 'deep' | undefined,
					planner_mode: args.planner_mode as 'off' | 'observe' | 'enforce' | undefined,
					discovery_mode: args.discovery_mode as 'classic' | 'tiered' | undefined,
					brand_aliases: args.brand_aliases as string[] | undefined,
					candidate_domains: args.candidate_domains as string[] | undefined,
					dkim_selectors: args.dkim_selectors as string[] | undefined,
					min_confidence: args.min_confidence as number | undefined,
					certstream: ro?.certstream,
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
			),
		cacheTtlSeconds: 3600,
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
				typeof args.discovery_mode === 'string'
					? args.discovery_mode
					: ro?.discoveryModeDefault === 'tiered'
						? 'tiered'
						: 'classic';
			const aliases = (args.brand_aliases as string[] | undefined) ?? [];
			const candDomains = (args.candidate_domains as string[] | undefined) ?? [];
			const aliasHash = aliases.length === 0 ? '0' : `${aliases.length}:${aliases.slice().sort().join('|').slice(0, 64)}`;
			const candHash = candDomains.length === 0 ? '0' : `${candDomains.length}:${candDomains.slice().sort().join('|').slice(0, 64)}`;
			return `brand_audit_single:${fmt}:d${depth}:p${plannerMode}:dm${discoveryMode}:a${aliasHash}:c${candHash}:m${minConf}`;
		},
		execute: (d, args, ro) =>
			brandAuditSingle(d, {
				format: args.format as 'json' | 'markdown' | 'both' | undefined,
				min_confidence: args.min_confidence as number | undefined,
				depth: args.depth as 'standard' | 'deep' | undefined,
				planner_mode: args.planner_mode as 'off' | 'observe' | 'enforce' | undefined,
				discovery_mode: args.discovery_mode as 'classic' | 'tiered' | undefined,
				brand_aliases: args.brand_aliases as string[] | undefined,
				candidate_domains: args.candidate_domains as string[] | undefined,
				// T13 — propagate the BlackVeil-production runtime override.
				// Pipeline only honours it when the caller omits `discovery_mode`;
				// undefined on BSL self-hosts (schema default `'classic'` wins).
				...(ro?.discoveryModeDefault ? { env: { BRAND_AUDIT_DISCOVERY_MODE_DEFAULT: ro.discoveryModeDefault } } : {}),
			}, {
				certstream: ro?.certstream,
				whoisBinding: ro?.whoisBinding,
				enforceQuota: buildMonthlyEnforceQuota(ro),
				// Tier closures: forwarded through the pipeline → discoverBrandDomains
				// seam. Undefined on BSL self-hosts → pipeline never calls the
				// proprietary lookups.
				...(ro?.tier0Lookup ? { tier0Lookup: ro.tier0Lookup } : {}),
				...(ro?.tier1Lookup ? { tier1Lookup: ro.tier1Lookup } : {}),
				...(ro?.tier2Lookup ? { tier2Lookup: ro.tier2Lookup } : {}),
			}),
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
					createFinding(
						'brand_discovery',
						'Brand audit status unavailable',
						'high',
						'BRAND_AUDIT_DB binding is not provisioned.',
						{ unprovisioned: true },
					),
				]);
			}
			return brandAuditStatus(String(args.auditId ?? ''), principalId, { db });
		},
		cacheable: false,
	},
	brand_audit_get_report: {
		// Mutable read — do not cache. Before completion this can return notReady,
		// and after completion the PDF sidecar URL/pending state can change.
		cacheKey: (args, ro) => `brand_audit_report:${ro?.principalId ?? ro?.keyHash ?? 'anon'}:${String(args.auditId ?? '')}:${String(args.target ?? '')}`,
		execute: async (_domain, args, ro) => {
			const db = ro?.brandAuditDb;
			const principalId = ro?.principalId ?? ro?.keyHash ?? 'anonymous';
			if (!db) {
				const { buildCheckResult, createFinding } = await import('../lib/scoring');
				return buildCheckResult('brand_discovery', [
					createFinding(
						'brand_discovery',
						'Brand audit get-report unavailable',
						'high',
						'BRAND_AUDIT_DB binding is not provisioned.',
						{ unprovisioned: true },
					),
				]);
			}
			return brandAuditGetReport(
				{ auditId: String(args.auditId ?? ''), target: args.target as string | undefined },
				principalId,
				{ db, bucket: ro?.brandReportsR2 as { createSignedUrl?: (input: { key: string; expiresInSeconds: number }) => Promise<string> } | undefined },
			);
		},
		cacheable: false,
	},
	brand_audit_watch: {
		// Mutating tool — random UUID keeps every call a cache-miss.
		cacheKey: () => `__nocache__:brand_audit_watch:${crypto.randomUUID()}`,
		execute: async (_domain, args, ro) => {
			const db = ro?.brandAuditDb;
			const principalId = ro?.principalId ?? ro?.keyHash ?? 'anonymous';
			if (!db) {
				const { buildCheckResult, createFinding } = await import('../lib/scoring');
				return buildCheckResult('brand_discovery', [
					createFinding(
						'brand_discovery',
						'Brand audit watch unavailable',
						'high',
						'BRAND_AUDIT_DB binding is not provisioned.',
						{ unprovisioned: true },
					),
				]);
			}
			return brandAuditWatch(
				{
					action: args.action as 'register' | 'list' | 'delete',
					domain: args.domain as string | undefined,
					interval: args.interval as 'daily' | 'weekly' | 'monthly' | undefined,
					webhook_url: args.webhook_url as string | undefined,
					watchId: args.watchId as string | undefined,
				},
				principalId,
				{ db },
			);
		},
		cacheTtlSeconds: 0,
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
		const DOMAIN_OPTIONAL_TOOLS = new Set([
			'explain_finding', 'get_benchmark', 'get_provider_insights', 'batch_scan', 'compare_domains',
			// v2.21+ brand-audit tools — take `domains[]`, `auditId`, or `action` instead of `domain`.
			'brand_audit_batch_start', 'brand_audit_status', 'brand_audit_get_report', 'brand_audit_watch',
		]);
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
				const checkName = registeredTool.cacheKey(validatedArgs, runtimeOptions);
				const cacheKey = `cache:${validDomain}:check:${checkName}`;
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
						/* skipCache */ undefined,
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
					// scanDomain sets `cached: true` only when the top-level cache:<domain>
					// key returned a hit. Threading that into the analytics emit so
					// `tool_call.blob8` reflects the orchestrator-level cache hit/miss
					// (was 'n/a' for every scan_domain call before — drowned the leaf
					// tools' real hit-rate signal in the .dev/analytics-30d.mjs report).
					const cacheStatus: 'hit' | 'miss' = result.cached ? 'hit' : 'miss';
					logToolSuccess({ ...ctx(), status: result.score.overall >= 50 ? 'pass' : 'fail', logResult, logDetails, severity: 'info', cacheStatus });
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
						return buildToolErrorResult(`Unknown tool: ${name}. Call tools/list to see all ${TOOLS.length} available tools.`);
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
