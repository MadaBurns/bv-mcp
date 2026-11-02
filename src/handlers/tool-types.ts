// SPDX-License-Identifier: BUSL-1.1

// Runtime option and result types shared by the tools/call dispatch modules (`tools.ts`, `tool-registry.ts`).

import type { CheckResult } from '../lib/scoring';
import type { QueryDnsOptions, SecondaryDohConfig } from '../lib/dns-types';
import { type AsyncBatchQueueProducer } from '../tools/batch-scan-async';
import type { AnalyticsClient } from '../lib/analytics';
import type { BindingDegradationSink } from '../lib/binding-degradation';
import type { McpContent } from './tool-formatters';
import type { McpTool } from '../schemas/tool-definitions';
import type { QuotaCoordinator } from '../lib/quota-coordinator';

/** MCP tools/call result */
export interface McpToolResult {
	content: McpContent[];
	structuredContent?: Record<string, unknown>;
	isError?: boolean;
	_meta?: Record<string, unknown>;
}

/**
 * MCP-spec-shaped tool descriptor as sent over the wire. Server-specific
 * metadata (functional group, scoring tier, scan inclusion) is nested under
 * `_meta` — the spec-sanctioned extension point — rather than leaked as
 * top-level fields the MCP `Tool` shape does not define.
 */
export interface WireTool {
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

export interface ToolRuntimeOptions {
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
	/**
	 * When provided, receives the raw CheckResult before MCP text formatting. Used by internal structured response mode.
	 *
	 * Fires ONLY on the `TOOL_REGISTRY` (single-`CheckResult`) path and
	 * `check_resolver_consistency`. `scan_domain` is an orchestrator, not a
	 * check — it produces a `ScanDomainResult`, never a `CheckResult` — so it
	 * does NOT invoke this. Use `scanResultCapture` for scan_domain.
	 */
	resultCapture?: (result: CheckResult) => void;
	/**
	 * When provided, receives the raw `ScanDomainResult` from `scan_domain`
	 * before MCP text formatting — the scan-orchestrator counterpart to
	 * `resultCapture`.
	 *
	 * Exists because `scan_domain` returns a `ScanDomainResult` (nested
	 * `score.overall` / `score.grade` / `score.findings` plus `maturity`), which
	 * does not fit `resultCapture`'s `CheckResult` contract. Callers that need
	 * the full scan — the tenant scan-persistence paths — must use this hook;
	 * `resultCapture` silently never fires for scan_domain.
	 */
	scanResultCapture?: (result: import('../tools/scan-domain').ScanDomainResult) => void;
	/** Override cache TTL in seconds for scan results. Threaded to scanDomain. */
	cacheTtlSeconds?: number;
	/** Scan-level wall-clock budget in milliseconds. Threaded to scanDomain. */
	scanTimeoutMs?: number;
	/** Per-check wall-clock budget in milliseconds. Threaded to scanDomain. */
	perCheckTimeoutMs?: number;
	/** `WEB_POSTURE_ENABLED` kill switch for scan_domain's non-scoring web posture section. Threaded to scanDomain. */
	webPostureEnabled?: boolean;
	/** Custom secondary DoH resolver config (bv-dns). Threaded to dnsOptions for individual checks. */
	secondaryDoh?: SecondaryDohConfig;
	country?: string;
	clientType?: string;
	authTier?: string;
	/** Full authenticated security principal; never emit directly to analytics. */
	keyHash?: string;
	/** 16-hex analytics-only pseudonym derived at the request boundary. */
	analyticsKeyHash?: string;
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
	/** SSLMate Cert Spotter API token for CT queries. Absent → unauthenticated. */
	certspotterToken?: string;
	/**
	 * The SCAN_CACHE namespace, threaded to registry tools that compose
	 * `discover_subdomains` (`osint_investigation_report` on a deep_infrastructure
	 * target) so they share its fresh-window / last-known-good entries instead of
	 * spending a second CT query on data the direct tool just cached. Set by
	 * `handleToolsCall` from its own `scanCacheKV` parameter.
	 */
	scanCacheKv?: KVNamespace;
	whoisBinding?: { fetch: typeof fetch };
	/** Operator-only bv-recon service binding. Fail-soft; absent on BSL self-hosts. */
	reconBinding?: { fetch: typeof fetch };
	/** Operator-only bv-tls-probe service binding (negotiated-TLS-version detection for `ssl`; served-certificate capture for `dane_https` pin verification, #841). Fail-soft; absent on BSL self-hosts → no TLS-version finding, DANE pins reported present-not-verified. */
	tlsProbeBinding?: { fetch: typeof fetch };
	/** Bearer token forwarded to bv-tls-probe. */
	tlsProbeAuthToken?: string;
	/** Service binding to bv-web's internal M365 proxy surface. Fail-soft; absent when bv-web is not provisioned. */
	m365Proxy?: { fetch: typeof fetch };
	/** Dedicated bearer (BV_MCP_M365_KEY) forwarded to bv-web's internal M365 endpoints. */
	m365ProxyAuthToken?: string;
	/** Verified identity contract forwarded to the internal M365 resolver. */
	m365Identity?: import('../tools/m365/proxy').M365PrincipalIdentity;
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
	/** Queue and KV durability bindings for asynchronous batch scans. */
	asyncBatchQueue?: AsyncBatchQueueProducer;
	asyncBatchKv?: KVNamespace;
	/** RATE_LIMIT KV — also used by enforceBrandAuditQuota for the per-tier monthly window. */
	rateLimitKv?: KVNamespace;
	/** Strong, atomic state for paid monthly brand-audit budgets. Missing binding fails closed. */
	quotaCoordinator?: DurableObjectNamespace<QuotaCoordinator>;
	/** Validated caller-supplied key for durable replay protection on internal mutations. */
	idempotencyKey?: string;
	/** Authenticated internal principal bound into the idempotency claim. */
	idempotencyPrincipal?: string;
	/** principalId of the calling user — required for enforceBrandAuditQuota. Key hash for auth, IP hash for unauth. */
	principalId?: string;
	/** R2 bucket binding for brand-audit PDF reports. v2.20.0+; written by the PDF queue consumer, served via the /reports/ download route. */
	brandReportsR2?: R2Bucket;
	/** Public origin of the inbound request; brand_audit_get_report uses it to build the /reports/... PDF download URL. Absent (internal path) → relative path. */
	publicOrigin?: string;
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
	/**
	 * Per-call DNS query cache (`QueryDnsOptions.queryCache`). Set by the registry dispatch for an
	 * NXDOMAIN-gated tool so the gate's apex NS probe and the check itself share one NS answer
	 * (SQ-268). Never set by callers.
	 */
	dnsQueryCache?: QueryDnsOptions['queryCache'];
}
