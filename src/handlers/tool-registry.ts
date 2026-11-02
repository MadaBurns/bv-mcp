// SPDX-License-Identifier: BUSL-1.1
// bv-oversize-ok: TOOL_REGISTRY is one dispatch table; split by tool group only with a functional change

// TOOL_REGISTRY: name -> cache key + execute for the individual check tools, split out of `handlers/tools.ts`.

import type { CheckResult } from '../lib/scoring';
import type { QueryDnsOptions } from '../lib/dns-types';
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
import { checkDbl } from '../tools/check-dbl';
import { checkRbl } from '../tools/check-rbl';
import { checkCymruAsn } from '../tools/check-cymru-asn';
import { checkRdapLookup, RDAP_LOOKUP_SYNC_BUDGET_MS } from '../tools/check-rdap-lookup';
import { checkNsecWalkability } from '../tools/check-nsec-walkability';
import { checkDnssecChain } from '../tools/check-dnssec-chain';
import { checkDnskeyStrength } from '../tools/check-dnskey-strength';
import { checkAgentDiscovery } from '../tools/check-agent-discovery';
import type { AgentProtocol } from '../tools/check-agent-discovery';
import { checkLlmsTxt } from '../tools/check-llms-txt';
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
import { extractDkimSelector } from './tool-args';
import type { ToolName } from '../schemas/tool-definitions';
import type { ToolRuntimeOptions } from './tool-types';

/** Build QueryDnsOptions for individual check calls from runtime options. */
export function buildDnsOptions(runtimeOptions?: ToolRuntimeOptions): QueryDnsOptions | undefined {
	if (!runtimeOptions?.secondaryDoh && !runtimeOptions?.dnsQueryCache) return undefined;
	return {
		...(runtimeOptions.secondaryDoh ? { secondaryDoh: runtimeOptions.secondaryDoh } : {}),
		...(runtimeOptions.dnsQueryCache ? { queryCache: runtimeOptions.dnsQueryCache } : {}),
	};
}

/**
 * Gate for `check_authoritative_dns_infra`'s AXFR + CHAOS active probes (US-4 frozen
 * decision 5). `/mcp` is zero-auth, so an unauthenticated request's `authTier` is `'anon'`;
 * a caller entitled through bv-web but resolving to no MCP tier reads `'free'`. Every OTHER
 * tier (`agent`, `developer`, `enterprise`, `partner`, `owner`) has presented a credential —
 * active probes are enabled ONLY for those, so anonymous/free traffic can never make this
 * server issue an AXFR or CHAOS query on their behalf.
 */
function activeProbesAllowed(runtimeOptions?: ToolRuntimeOptions): boolean {
	const tier = runtimeOptions?.authTier;
	return tier !== undefined && tier !== 'anon' && tier !== 'free';
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
	if (!ro?.principalId || !ro.authTier) return undefined;
	const tier = ro.authTier as import('../lib/config').McpApiKeyTier;
	const kv = ro.rateLimitKv;
	const quotaCoordinator = ro.quotaCoordinator;
	const principalId = ro.principalId;
	return async (count: number) => {
		const { enforceBrandAuditQuota } = await import('../lib/brand-audit-quota');
		return enforceBrandAuditQuota({ kv, quotaCoordinator, principalId, tier, count });
	};
}

/** Wrapper for dynamic check_mx import (required for test mock isolation) */
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
 * Cache-key fragment for a caller-supplied list: `<count>:<sha256 hex prefix>` of the FULL
 * sorted list, or `0` when empty. Truncating the joined plaintext (the old 64/128-char slice)
 * let two different lists sharing a prefix collide on one cached result; hashing keeps every
 * element significant while the key stays bounded. JSON-encoded so a `|` inside an item cannot
 * make two different lists serialize identically.
 */
async function hashListForCacheKey(items: string[]): Promise<string> {
	if (items.length === 0) return '0';
	const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify(items.slice().sort())));
	const hex = Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('');
	return `${items.length}:${hex.slice(0, 32)}`;
}

/** Entry shape for {@link TOOL_REGISTRY}. */
export interface ToolRegistryEntry {
	/** cacheKey may consult runtimeOptions to bind principal (defense against owner-scoped IDOR via cache). */
	cacheKey: (args: Record<string, unknown>, runtimeOptions?: ToolRuntimeOptions) => string | Promise<string>;
	execute: (domain: string, args: Record<string, unknown>, runtimeOptions?: ToolRuntimeOptions) => Promise<CheckResult>;
	cacheable?: boolean;
	cacheTtlSeconds?: number;
}

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

/**
 * Registry mapping tool names to their cache key and execution function.
 * Replaces repetitive switch cases for individual DNS check tools.
 *
 * Kept `Record<string, ...>` (not `Record<ToolName, ...>`) so the dispatch
 * lookup below can safely index with an unvalidated request-supplied tool
 * name; the `satisfies` clause still makes every literal key here a compile
 * error if it drifts from {@link ToolName} (the TOOL_DEFS SSOT), without
 * requiring this necessarily-partial registry to cover every tool — the
 * other half dispatches via DIRECT_DISPATCH_TOOLS (`tool-sets.ts`).
 */
export const TOOL_REGISTRY: Record<string, ToolRegistryEntry> = {
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
				// The ONE call site that opts into CT certificate metadata: this is the
				// direct `check_ssl` tool, whose description promises issuer + expiry,
				// and it is per-domain and result-cached. The fan-out callers
				// (scan_domain, validate_fix, simulate_attack_paths) leave it off —
				// see the `certMetadata` doc comment in tools/check-ssl.ts.
				certMetadata: true,
			}),
	},
	check_mta_sts: { cacheKey: () => 'mta_sts', execute: (d, _args, ro) => checkMtaSts(d, buildDnsOptions(ro)) },
	check_ns: {
		cacheKey: (_args, ro) => (ro?.infraProbe ? 'ns:delegation-probe' : 'ns'),
		execute: (d, _args, ro) => checkNs(d, buildDnsOptions(ro), undefined, { infraProbe: ro?.infraProbe }),
	},
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
	check_dane_https: {
		// #841: with the probe bound the result carries a verified/mismatch verdict the
		// probe-less result cannot, so the two must not share a cache entry (as `ssl`).
		cacheKey: (_a, ro) => (ro?.tlsProbeBinding ? 'dane_https:tls-probe' : 'dane_https'),
		execute: (d, _args, ro) =>
			checkDaneHttps(d, buildDnsOptions(ro), {
				tlsProbeBinding: ro?.tlsProbeBinding,
				tlsProbeAuthToken: ro?.tlsProbeAuthToken,
				onBindingDegradation: ro?.onBindingDegradation,
			}),
	},
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
	check_llms_txt: { cacheKey: () => 'llms_txt', execute: (d, _args, ro) => checkLlmsTxt(d, buildDnsOptions(ro)) },
	check_dnskey_strength: { cacheKey: () => 'dnskey_strength', execute: (d, _args, ro) => checkDnskeyStrength(d, buildDnsOptions(ro)) },
	check_fast_flux: {
		// `rounds` changes the probe count, and rapid rotation is only detectable
		// across rounds, so a shared key would serve a 3-round answer to a caller
		// that asked for 5 (or vice versa) for the whole TTL window. The value is
		// folded CLAMPED, mirroring `Math.max(3, Math.min(5, rounds ?? 3))` inside
		// checkFastFlux, so an out-of-range request collides with the run it
		// actually performs instead of minting unbounded keys.
		cacheKey: (args, ro) => {
			const rounds = Math.max(3, Math.min(5, typeof args.rounds === 'number' ? args.rounds : 3));
			const base = ro?.reconBinding ? 'fast_flux:recon' : 'fast_flux';
			return `${base}:r${rounds}`;
		},
		execute: (d, args, ro) =>
			checkFastFlux(d, (args.rounds as number | undefined) ?? 3, buildDnsOptions(ro), undefined, {
				reconBinding: ro?.reconBinding,
				reconAuthToken: ro?.reconAuthToken,
				onBindingDegradation: ro?.onBindingDegradation,
			}),
	},
	check_subdomain_takeover: {
		cacheKey: async (args) => {
			const subs = Array.isArray(args.subdomains) ? (args.subdomains as string[]) : null;
			// Cache key folds caller-supplied list CONTENTS (not just size) so two
			// different same-length lists don't collide on one entry (5-min TTL,
			// global per domain+checkName) — mirrors the discover_brand_domains
			// sibling. Sorted + length-prefixed + SHA-256 of the full list to keep keys finite.
			return subs && subs.length > 0 ? `subdomain_takeover:custom:${await hashListForCacheKey(subs)}` : 'subdomain_takeover:default';
		},
		execute: (d, args, ro) => {
			const subs = Array.isArray(args.subdomains) ? (args.subdomains as string[]) : undefined;
			return checkSubdomainTakeover(d, buildDnsOptions(ro), subs ? { subdomains: subs } : undefined);
		},
	},
	check_authoritative_dns_infra: {
		// Partitioned on the active-probe gate: an authenticated result carries AXFR/CHAOS
		// fields an anonymous
		// caller must never see served back from cache, and the reverse would hide measured
		// capabilities from a paying caller for the 5-minute TTL.
		cacheKey: (_args, ro) => (activeProbesAllowed(ro) ? 'authoritative_dns_infra:active' : 'authoritative_dns_infra'),
		execute: (d, _args, ro) => checkAuthoritativeDnsInfra(d, { infraProbe: ro?.infraProbe, activeProbes: activeProbesAllowed(ro) }),
	},
	check_root_server_set: {
		cacheKey: () => 'root_server_set',
		execute: (_d, _args, ro) => checkRootServerSet({ infraProbe: ro?.infraProbe }),
		cacheable: false,
	},
	discover_brand_domains: {
		cacheKey: async (args) => {
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
			// The selector list goes straight into the `dkim_key_reuse` signal probe
			// (src/tools/discover-brand-domains.ts), so it changes which candidates are
			// corroborated and at what confidence. Omitted means "built-in common
			// selectors"; an explicit list means "exactly these" — the two must not
			// share this tool's 1-hour cache entry. `hashListForCacheKey` maps an empty
			// list to the same '0' the other two components use, so omitted and explicit-
			// but-empty stay equivalent while any real roster gets its own entry.
			const selectors = (args.dkim_selectors as string[] | undefined) ?? [];
			const aliasHash = await hashListForCacheKey(aliases);
			const candHash = await hashListForCacheKey(candDomains);
			const selHash = await hashListForCacheKey(selectors);
			return `discover_brand:${signals}:d${depth}:p${plannerMode}:dm${discoveryMode}:a${aliasHash}:c${candHash}:k${selHash}:m${minConf}`;
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
					...(ro?.certspotterToken && { certspotterToken: ro.certspotterToken }),
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
		cacheKey: async (args, ro) => {
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
			const aliasHash = await hashListForCacheKey(aliases);
			const candHash = await hashListForCacheKey(candDomains);
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
					view: args.view as 'standard' | 'registrar_complement' | undefined,
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
					...(ro?.certspotterToken ? { certspotterToken: ro.certspotterToken } : {}),
					whoisBinding: ro?.whoisBinding,
					enforceQuota: buildMonthlyEnforceQuota(ro),
					// The brand-audit queue binding doubles as the registrar fast→full
					// deep-scan trigger in the pipeline (brand-audit-pipeline.ts:1061).
					// Without it, sync view='registrar_complement' audits write only the
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
					view: args.view as 'standard' | 'registrar_complement' | undefined,
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
				publicOrigin: ro?.publicOrigin,
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
						principalId: ro?.keyHash ?? ro?.principalId,
						onBindingDegradation: ro?.onBindingDegradation,
					},
				),
			),
		cacheTtlSeconds: 0,
	},
	scan_buckets_status: {
		cacheKey: (a, ro) => `bucketstatus:${ro?.keyHash ?? ro?.principalId ?? 'anon'}:${String(a.scanId)}`,
		execute: (_d, a, ro) =>
			import('../tools/scan-buckets').then((m) =>
				m.scanBucketsStatus(
					{ scanId: String(a.scanId) },
					{
						reconBinding: ro?.reconBinding,
						reconAuthToken: ro?.reconAuthToken,
						bucketScanKv: ro?.rateLimitKv,
						principalId: ro?.keyHash ?? ro?.principalId,
						onBindingDegradation: ro?.onBindingDegradation,
					},
				),
			),
		cacheTtlSeconds: 15,
	},
	scan_buckets_findings: {
		cacheKey: (a, ro) =>
			`bucketfindings:${ro?.keyHash ?? ro?.principalId ?? 'anon'}:${String(a.scanId)}:${String(a.target ?? '')}:${JSON.stringify(a.providers ?? [])}`,
		execute: (_d, a, ro) =>
			import('../tools/scan-buckets').then((m) =>
				m.scanBucketsFindings(
					{
						scanId: String(a.scanId),
						target: a.target ? String(a.target) : undefined,
						providers: Array.isArray(a.providers) ? (a.providers as string[]) : undefined,
					},
					{
						reconBinding: ro?.reconBinding,
						reconAuthToken: ro?.reconAuthToken,
						bucketScanKv: ro?.rateLimitKv,
						principalId: ro?.keyHash ?? ro?.principalId,
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
					reconJobKv: ro?.rateLimitKv,
					principalId: ro?.keyHash ?? ro?.principalId,
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
					reconJobKv: ro?.rateLimitKv,
					principalId: ro?.keyHash ?? ro?.principalId,
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
					reconJobKv: ro?.rateLimitKv,
					principalId: ro?.keyHash ?? ro?.principalId,
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
					reconJobKv: ro?.rateLimitKv,
					principalId: ro?.keyHash ?? ro?.principalId,
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
					reconJobKv: ro?.rateLimitKv,
					principalId: ro?.keyHash ?? ro?.principalId,
					authTier: ro?.authTier,
					onBindingDegradation: ro?.onBindingDegradation,
				}),
			),
		cacheTtlSeconds: 0,
	},
	osint_investigation_status: {
		cacheKey: (a, ro) => `osintstatus:${ro?.keyHash ?? ro?.principalId ?? 'anon'}:${String(a.investigationId)}`,
		execute: (_d, a, ro) =>
			import('../tools/osint-investigate').then((m) =>
				m.osintInvestigationStatus(String(a.investigationId), {
					reconBinding: ro?.reconBinding,
					reconAuthToken: ro?.reconAuthToken,
					reconJobKv: ro?.rateLimitKv,
					principalId: ro?.keyHash ?? ro?.principalId,
					onBindingDegradation: ro?.onBindingDegradation,
				}),
			),
		cacheTtlSeconds: 15,
	},
	osint_investigation_report: {
		cacheKey: (a, ro) => `osintreport:${ro?.keyHash ?? ro?.principalId ?? 'anon'}:${String(a.investigationId)}`,
		execute: (_d, a, ro) =>
			import('../tools/osint-investigate').then((m) =>
				m.osintInvestigationReport(String(a.investigationId), {
					reconBinding: ro?.reconBinding,
					reconAuthToken: ro?.reconAuthToken,
					reconJobKv: ro?.rateLimitKv,
					principalId: ro?.keyHash ?? ro?.principalId,
					onBindingDegradation: ro?.onBindingDegradation,
					// A deep_infrastructure report composes this Worker's own discover_subdomains
					// (the quota-aware CT ladder) for the remembered target; see the tool module.
					ctDiscovery: {
						certstream: ro?.certstream,
						certstreamAuthToken: ro?.certstreamAuthToken,
						...(ro?.certspotterToken ? { certspotterToken: ro.certspotterToken } : {}),
						...(ro?.scanCacheKv ? { cacheKv: ro.scanCacheKv } : {}),
						...(ro?.waitUntil ? { waitUntil: ro.waitUntil } : {}),
					},
				}),
			),
		cacheTtlSeconds: 30,
	},
} satisfies Partial<Record<ToolName, ToolRegistryEntry>>;
