// SPDX-License-Identifier: BUSL-1.1

import { z } from 'zod';
import {
	BaseDomainArgs,
	ScanDomainArgs,
	BatchScanArgs,
	CompareDomainsArgs,
	CheckDkimArgs,
	CheckResolverConsistencyArgs,
	GenerateSpfArgs,
	GenerateDmarcArgs,
	GenerateDkimConfigArgs,
	GenerateMtaStsArgs,
	ExplainFindingArgs,
	CompareBaselineArgs,
	GetBenchmarkArgs,
	GetProviderInsightsArgs,
	ValidateFixArgs,
	MapSupplyChainArgs,
	AnalyzeDriftArgs,
	GenerateRolloutPlanArgs,
	CheckFastFluxArgs,
	CheckSubdomainTakeoverArgs,
	RootServerSetArgs,
	DiscoverBrandDomainsArgs,
	BrandAuditSingleArgs,
	BrandAuditBatchStartArgs,
	BrandAuditStatusArgs,
	BrandAuditGetReportArgs,
	ListBrandAuditWatchesArgs,
	RegisterBrandAuditWatchArgs,
	DeleteBrandAuditWatchArgs,
	ScanBucketsStartArgs,
	ScanBucketsStatusArgs,
	ScanBucketsFindingsArgs,
	OsintInvestigateArgs,
	OsintInvestigationIdArgs,
	TOOL_SCHEMA_MAP,
} from './tool-args';
import { buildCheckResultOutputJsonSchema } from './check-result-output';

export type ToolGroup =
	| 'email_auth'
	| 'infrastructure'
	| 'brand_threats'
	| 'dns_hygiene'
	| 'intelligence'
	| 'remediation'
	| 'meta'
	| 'discovery';
export type ToolTier = 'core' | 'protective' | 'hardening';

export interface McpTool {
	name: string;
	description: string;
	inputSchema: {
		type: string;
		properties: Record<string, unknown>;
		required?: string[];
		[key: string]: unknown;
	};
	/**
	 * MCP `outputSchema` for the tool's `structuredContent`. Present only on tools
	 * whose `structuredContent` is a `CheckResult` (the registry-driven check/recon
	 * tools); absent for special-case tools that return custom shapes. Lenient so any
	 * real CheckResult validates — see `schemas/check-result-output.ts`.
	 */
	outputSchema?: McpTool['inputSchema'];
	annotations?: {
		title?: string;
		readOnlyHint?: boolean;
		destructiveHint?: boolean;
		idempotentHint?: boolean;
		openWorldHint?: boolean;
	};
	/** Functional group for client-side tool discoverability. Not used in dispatch. */
	group: ToolGroup;
	/** Scoring tier from the three-tier model. Absent for non-scoring tools (meta/intelligence/remediation). */
	tier?: ToolTier;
	/** True when this tool is included in the scan_domain parallel orchestration. */
	scanIncluded: boolean;
}

interface ToolDef {
	description: string;
	schema: z.ZodTypeAny;
	group: ToolGroup;
	tier?: ToolTier;
	scanIncluded: boolean;
	mutating?: boolean;
	/** True when the tool deletes or overwrites data → drives `destructiveHint`. Implies `mutating`. */
	destructive?: boolean;
}

/** DNS/security acronyms that should be uppercased in human-readable tool titles. */
const KNOWN_ACRONYMS = new Set([
	'mx',
	'spf',
	'dmarc',
	'dkim',
	'dns',
	'dnssec',
	'ssl',
	'mta',
	'sts',
	'ns',
	'caa',
	'bimi',
	'tlsrpt',
	'http',
	'https',
	'dane',
	'svcb',
	'srv',
	'txt',
	'doh',
	'rpm',
	'dbl',
	'rdap',
	'nsec',
]);

/** Convert a snake_case tool name to a human-readable title. e.g. "check_mta_sts" → "Check MTA STS" */
function toolNameToTitle(name: string): string {
	return name
		.split('_')
		.map((word) => (KNOWN_ACRONYMS.has(word) ? word.toUpperCase() : word.charAt(0).toUpperCase() + word.slice(1)))
		.join(' ');
}

/** Convert a Zod schema to a JSON Schema object suitable for MCP inputSchema. */
function toInputSchema(schema: z.ZodTypeAny): McpTool['inputSchema'] {
	const jsonSchema = z.toJSONSchema(schema) as Record<string, unknown>;
	delete jsonSchema.$schema;
	// Clean up additionalProperties: {} (equivalent to not having it, but cleaner)
	if (
		jsonSchema.additionalProperties !== undefined &&
		typeof jsonSchema.additionalProperties === 'object' &&
		jsonSchema.additionalProperties !== null &&
		Object.keys(jsonSchema.additionalProperties).length === 0
	) {
		delete jsonSchema.additionalProperties;
	}
	// Strip additionalProperties: false — MCP clients must not be constrained by strict schema markers
	if (jsonSchema.additionalProperties === false) {
		delete jsonSchema.additionalProperties;
	}
	return jsonSchema as McpTool['inputSchema'];
}

/** All MCP tool definitions. */
const TOOL_DEFS: Record<string, ToolDef> = {
	check_mx: {
		description: 'Look up MX records for a domain. Shows mail servers, email provider detection, and validates configuration.',
		schema: BaseDomainArgs,
		group: 'email_auth',
		tier: 'protective',
		scanIncluded: true,
	},
	check_spf: {
		description: 'Look up and validate SPF record for a domain. Shows authorized senders, syntax issues, and trust surface.',
		schema: BaseDomainArgs,
		group: 'email_auth',
		tier: 'core',
		scanIncluded: true,
	},
	check_dmarc: {
		description: 'Look up and validate DMARC record for a domain. Shows policy enforcement, alignment mode, and reporting config.',
		schema: BaseDomainArgs,
		group: 'email_auth',
		tier: 'core',
		scanIncluded: true,
	},
	check_dkim: {
		description: 'Look up DKIM records for a domain. Probes common selectors and validates key strength and algorithm.',
		schema: CheckDkimArgs,
		group: 'email_auth',
		tier: 'core',
		scanIncluded: true,
	},
	check_dnssec: {
		description: 'Check DNSSEC status for a domain. Verifies DNSKEY/DS records and validation chain.',
		schema: BaseDomainArgs,
		group: 'infrastructure',
		tier: 'core',
		scanIncluded: true,
	},
	check_ssl: {
		description: 'Check SSL/TLS certificate for a domain. Shows issuer, expiry, protocol versions, and HTTPS configuration.',
		schema: BaseDomainArgs,
		group: 'infrastructure',
		tier: 'core',
		scanIncluded: true,
	},
	check_mta_sts: {
		description: 'Validate MTA-STS SMTP encryption policy.',
		schema: BaseDomainArgs,
		group: 'email_auth',
		tier: 'protective',
		scanIncluded: true,
	},
	check_ns: {
		description: 'Look up NS (nameserver) records for a domain. Shows DNS provider, delegation, and redundancy.',
		schema: BaseDomainArgs,
		group: 'infrastructure',
		tier: 'protective',
		scanIncluded: true,
	},
	check_caa: {
		description: 'Look up CAA records for a domain. Shows which Certificate Authorities are authorized to issue certificates.',
		schema: BaseDomainArgs,
		group: 'infrastructure',
		tier: 'protective',
		scanIncluded: true,
	},
	check_bimi: {
		description: 'Validate BIMI record and VMC evidence.',
		schema: BaseDomainArgs,
		group: 'brand_threats',
		tier: 'hardening',
		scanIncluded: true,
	},
	check_tlsrpt: {
		description: 'Validate TLS-RPT SMTP failure reporting.',
		schema: BaseDomainArgs,
		group: 'brand_threats',
		tier: 'hardening',
		scanIncluded: true,
	},
	check_http_security: {
		description: 'Audit HTTP security headers (CSP, COOP, etc.).',
		schema: BaseDomainArgs,
		group: 'infrastructure',
		tier: 'protective',
		scanIncluded: true,
	},
	check_dane: {
		description: 'Verify DANE/TLSA certificate pinning.',
		schema: BaseDomainArgs,
		group: 'infrastructure',
		tier: 'hardening',
		scanIncluded: true,
	},
	check_dane_https: {
		description: 'Verify DANE certificate pinning for HTTPS via TLSA records at _443._tcp.{domain}.',
		schema: BaseDomainArgs,
		group: 'infrastructure',
		tier: 'protective',
		scanIncluded: true,
	},
	check_svcb_https: {
		description: 'Validate HTTPS/SVCB records (RFC 9460) for modern transport capability advertisement.',
		schema: BaseDomainArgs,
		group: 'infrastructure',
		tier: 'protective',
		scanIncluded: true,
	},
	check_lookalikes: {
		description: 'Detect active typosquat/lookalike domains. Standalone.',
		schema: BaseDomainArgs,
		group: 'brand_threats',
		tier: 'protective',
		scanIncluded: false,
	},
	check_subdomailing: {
		description: 'Detect SubdoMailing risk by analyzing SPF include chain for takeover-vulnerable domains.',
		schema: BaseDomainArgs,
		group: 'email_auth',
		tier: 'protective',
		scanIncluded: true,
	},
	scan_domain: {
		description:
			'Runs a full DNS and email security audit for a domain, aggregating every scan-included check in parallel: SPF, DKIM, DMARC, DNSSEC, TLS/SSL, MTA-STS, CAA, BIMI, subdomain takeover, and more. Returns an overall score, letter grade, maturity stage, and prioritized findings. The broadest single-domain tool; the individual check_* tools each cover one control in isolation.',
		schema: ScanDomainArgs,
		group: 'meta',
		scanIncluded: false,
	},
	batch_scan: {
		description: 'Scan up to 10 domains at once. Returns score, grade, and finding counts per domain.',
		schema: BatchScanArgs,
		group: 'meta',
		scanIncluded: false,
	},
	compare_domains: {
		description: 'Side-by-side security comparison of 2–5 domains. Shows scores, category gaps, and unique weaknesses.',
		schema: CompareDomainsArgs,
		group: 'meta',
		scanIncluded: false,
	},
	compare_baseline: {
		description: 'Compare domain security against a policy baseline.',
		schema: CompareBaselineArgs,
		group: 'meta',
		scanIncluded: false,
	},
	check_shadow_domains: {
		description: 'Find TLD variants with email auth gaps. Standalone.',
		schema: BaseDomainArgs,
		group: 'brand_threats',
		tier: 'protective',
		scanIncluded: false,
	},
	check_txt_hygiene: {
		description: 'Audit TXT records for stale entries and SaaS exposure.',
		schema: BaseDomainArgs,
		group: 'dns_hygiene',
		tier: 'hardening',
		scanIncluded: false,
	},
	check_mx_reputation: {
		description: 'Check MX blocklist status and reverse DNS.',
		schema: BaseDomainArgs,
		group: 'email_auth',
		tier: 'hardening',
		scanIncluded: false,
	},
	check_srv: {
		description: 'Probe SRV records for service footprint.',
		schema: BaseDomainArgs,
		group: 'infrastructure',
		tier: 'hardening',
		scanIncluded: false,
	},
	check_zone_hygiene: {
		description: 'Audit SOA propagation and sensitive subdomains.',
		schema: BaseDomainArgs,
		group: 'infrastructure',
		tier: 'hardening',
		scanIncluded: false,
	},
	generate_fix_plan: {
		description: 'Generate prioritized remediation plan with effort estimates.',
		schema: BaseDomainArgs,
		group: 'remediation',
		scanIncluded: false,
	},
	generate_spf_record: {
		description: 'Generate corrected SPF record from detected providers.',
		schema: GenerateSpfArgs,
		group: 'remediation',
		scanIncluded: false,
	},
	generate_dmarc_record: {
		description: 'Generate DMARC record with configurable policy.',
		schema: GenerateDmarcArgs,
		group: 'remediation',
		scanIncluded: false,
	},
	generate_dkim_config: {
		description: 'Generate DKIM setup instructions and DNS record.',
		schema: GenerateDkimConfigArgs,
		group: 'remediation',
		scanIncluded: false,
	},
	generate_mta_sts_policy: {
		description: 'Generate MTA-STS record and policy file.',
		schema: GenerateMtaStsArgs,
		group: 'remediation',
		scanIncluded: false,
	},
	get_benchmark: {
		description: 'Get score benchmarks: percentiles, mean, top failures.',
		schema: GetBenchmarkArgs,
		group: 'intelligence',
		scanIncluded: false,
	},
	get_provider_insights: {
		description: 'Get provider cohort benchmarks and common issues.',
		schema: GetProviderInsightsArgs,
		group: 'intelligence',
		scanIncluded: false,
	},
	assess_spoofability: {
		description: 'Composite email spoofability score (0-100).',
		schema: BaseDomainArgs,
		group: 'intelligence',
		scanIncluded: false,
	},
	check_resolver_consistency: {
		description: 'Check DNS consistency across 4 public resolvers.',
		schema: CheckResolverConsistencyArgs,
		group: 'infrastructure',
		scanIncluded: false,
	},
	explain_finding: {
		description: 'Explain a finding with impact and remediation.',
		schema: ExplainFindingArgs,
		group: 'meta',
		scanIncluded: false,
	},
	map_supply_chain: {
		description:
			'Map third-party service dependencies from DNS records. Correlates SPF, NS, TXT verifications, SRV services, and CAA to show who can send as you, control your DNS, and what services are integrated.',
		schema: MapSupplyChainArgs,
		group: 'intelligence',
		scanIncluded: false,
	},
	analyze_drift: {
		description: 'Compare current security posture against a previous baseline. Shows what improved, regressed, or changed.',
		schema: AnalyzeDriftArgs,
		group: 'intelligence',
		scanIncluded: false,
	},
	validate_fix: {
		description: 'Re-check a specific control after applying a fix. Confirms whether the finding is resolved.',
		schema: ValidateFixArgs,
		group: 'remediation',
		scanIncluded: false,
	},
	generate_rollout_plan: {
		description: 'Generate a phased DMARC enforcement timeline with exact DNS records per phase.',
		schema: GenerateRolloutPlanArgs,
		group: 'remediation',
		scanIncluded: false,
	},
	resolve_spf_chain: {
		description:
			'Trace the full SPF include chain for a domain. Recursively resolves all includes, shows lookup count, tree depth, and flags circular includes or exceeding the 10-lookup limit.',
		schema: BaseDomainArgs,
		group: 'intelligence',
		scanIncluded: false,
	},
	discover_subdomains: {
		description:
			'Find subdomains of a domain using Certificate Transparency logs. Reveals shadow IT, forgotten services, and unauthorized certificate issuance.',
		schema: BaseDomainArgs,
		group: 'intelligence',
		scanIncluded: false,
	},
	map_compliance: {
		description:
			'Map scan findings to compliance frameworks: NIST 800-177, PCI DSS 4.0, SOC 2, CIS Controls. Shows pass/fail/partial status per control.',
		schema: BaseDomainArgs,
		group: 'intelligence',
		scanIncluded: false,
	},
	simulate_attack_paths: {
		description:
			'Analyze current DNS posture and enumerate specific attack paths an adversary could exploit, with severity, feasibility, steps, and mitigations.',
		schema: BaseDomainArgs,
		group: 'intelligence',
		scanIncluded: false,
	},
	check_dbl: {
		description:
			'Check domain reputation against DNS-based Domain Block Lists (Spamhaus DBL, URIBL, SURBL). Returns listing status with decoded return codes.',
		schema: BaseDomainArgs,
		group: 'intelligence',
		scanIncluded: false,
	},
	check_rbl: {
		description:
			'Check MX server IP reputation against 8 DNS-based Real-time Blocklists (Spamhaus ZEN, SpamCop, UCEProtect, Mailspike, Barracuda, PSBL, SORBS). Resolves MX hosts to IPs first.',
		schema: BaseDomainArgs,
		group: 'intelligence',
		scanIncluded: false,
	},
	cymru_asn: {
		description:
			'Map domain IPs to Autonomous System Numbers via Team Cymru DNS. Returns ASN, prefix, country, registry, and organization for each IP. Flags high-risk hosting ASNs.',
		schema: BaseDomainArgs,
		group: 'intelligence',
		scanIncluded: false,
	},
	rdap_lookup: {
		description:
			'Fetch domain registration data via RDAP (modern WHOIS replacement). Returns registrar, creation/expiration dates, EPP status, registrant info, and domain age.',
		schema: BaseDomainArgs,
		group: 'intelligence',
		scanIncluded: false,
	},
	check_realtime_threat_feed: {
		description:
			'Check a domain against BlackVeil real-time threat intelligence (curated intel-gateway feed). Distinct from DNSBL checks. Operator-deploy only; degrades to info when unprovisioned.',
		schema: BaseDomainArgs,
		group: 'intelligence',
		scanIncluded: false,
	},
	check_nsec_walkability: {
		description:
			'Assess zone walkability risk by analyzing NSEC3PARAM configuration. Detects plain NSEC zones, weak NSEC3 parameters, and opt-out flags.',
		schema: BaseDomainArgs,
		group: 'intelligence',
		scanIncluded: false,
	},
	check_dnssec_chain: {
		description:
			'Walk the DNSSEC chain of trust from root to target domain. Reports DS/DNSKEY records, algorithm usage, and linkage status at each zone level.',
		schema: BaseDomainArgs,
		group: 'intelligence',
		scanIncluded: false,
	},
	check_fast_flux: {
		description:
			'Detect fast-flux DNS behavior by performing multiple rounds of A/AAAA queries with delays. Compares IP answer sets and TTLs across rounds to identify rotating infrastructure.',
		schema: CheckFastFluxArgs,
		group: 'intelligence',
		scanIncluded: false,
	},
	check_subdomain_takeover: {
		description:
			'Sweep an explicit subdomain list (or a built-in 15-name list of common labels) for dangling CNAMEs and provider-deprovisioned takeover fingerprints. Pair with discover_subdomains for full-inventory coverage. Detects 16 provider families (AWS S3/CloudFront, Azure Front Door/CDN/Blob/App Service, GCP Cloud Storage, Heroku, GitHub Pages, Vercel, Firebase, Shopify, etc.).',
		schema: CheckSubdomainTakeoverArgs,
		group: 'infrastructure',
		tier: 'protective',
		scanIncluded: false,
	},
	check_authoritative_dns_infra: {
		description:
			'Check authoritative DNS infrastructure posture for a hostname. Uses BV_INFRA_PROBE when available for raw DNS, routing, RPKI, and vantage-point evidence.',
		schema: BaseDomainArgs,
		group: 'infrastructure',
		tier: 'core',
		scanIncluded: false,
	},
	check_root_server_set: {
		description:
			'Check the DNS root server set against official root hints, root glue, delegation, serial, and DNSKEY cross-root evidence.',
		schema: RootServerSetArgs,
		group: 'infrastructure',
		tier: 'core',
		scanIncluded: false,
	},
	discover_brand_domains: {
		description:
			"Find a brand's hidden domain portfolio with standard or deep discovery by aggregating certificate, DNS, mail-policy, redirect, TXT verification, MX platform, and candidate-seeding signals. Returns ranked candidate domains with provenance and combined-confidence scoring.",
		schema: DiscoverBrandDomainsArgs,
		group: 'discovery',
		scanIncluded: false,
	},
	brand_audit_single: {
		description:
			'Run a full brand audit on a single target with optional standard/deep discovery depth, brand aliases, and caller-supplied candidate domains. Discovers brand-related domains, looks up registrar + registrant for each candidate, and classifies each into consolidated, real registrar-sprawl shadowIt, authorized vendor dependency, indeterminate, or impersonation relationships. Gated tier-wide by monthly BRAND_AUDIT_QUOTAS (free/agent=0, developer=50, partner=200, enterprise=500, owner=unlimited).',
		schema: BrandAuditSingleArgs,
		group: 'discovery',
		scanIncluded: false,
	},
	brand_audit_batch_start: {
		description:
			'Enqueue an async brand audit across up to 50 target domains with optional standard/deep discovery depth, brand aliases, and caller-supplied candidate domains. Returns { auditId, queuedAt, targetCount, etaSeconds } immediately; poll with brand_audit_status and fetch results with brand_audit_get_report once complete. Each target consumes 1 unit of the monthly BRAND_AUDIT_QUOTAS budget.',
		schema: BrandAuditBatchStartArgs,
		group: 'discovery',
		scanIncluded: false,
		mutating: true,
	},
	brand_audit_status: {
		description:
			"Poll the status of an enqueued brand audit. Returns audit-level status (queued | running | completed | failed), progress 'N/M', and per-target statuses. Owner-scoped — auditIds owned by other principals surface as notFound.",
		schema: BrandAuditStatusArgs,
		group: 'discovery',
		scanIncluded: false,
	},
	brand_audit_get_report: {
		description:
			'Fetch the result JSON for a completed brand audit. With `target` set, returns the per-target CheckResult; without, returns the audit-level aggregate. Returns notReady when polling an in-flight audit. When a rendered PDF sidecar exists and the R2 binding is configured, metadata includes a signed PDF URL; completed targets without a PDF URL include pdfPending so callers can poll again.',
		schema: BrandAuditGetReportArgs,
		group: 'discovery',
		scanIncluded: false,
	},
	list_brand_audit_watches: {
		description:
			"Returns the caller's recurring brand-audit watches: watchId, domain, interval, webhook presence, last-run time, and active state. Owner-scoped. Read-only.",
		schema: ListBrandAuditWatchesArgs,
		group: 'discovery',
		scanIncluded: false,
	},
	register_brand_audit_watch: {
		description:
			'Creates a recurring brand-audit watch for a domain on a daily/weekly/monthly cadence. Each run enqueues a fresh brand_audit_batch_start and (when a webhook is configured) POSTs a diff webhook on classification drift. Returns the new watchId. Owner-scoped; per-principal cap of 20 active watches.',
		schema: RegisterBrandAuditWatchArgs,
		group: 'discovery',
		scanIncluded: false,
		mutating: true,
	},
	delete_brand_audit_watch: {
		description:
			'Permanently removes a recurring brand-audit watch by watchId. Owner-scoped — a watchId owned by another principal surfaces as notFound. Returns confirmation of deletion.',
		schema: DeleteBrandAuditWatchArgs,
		group: 'discovery',
		scanIncluded: false,
		mutating: true,
		destructive: true,
	},
	scan_buckets_start: {
		description:
			'Start an async cloud-bucket discovery scan for a target domain. Operator-deploy only; degrades to info when unprovisioned. Returns a scanId immediately — poll progress with scan_buckets_status and retrieve results with scan_buckets_findings.',
		schema: ScanBucketsStartArgs,
		group: 'intelligence',
		scanIncluded: false,
		mutating: true,
	},
	scan_buckets_status: {
		description:
			'Poll the status of a cloud-bucket discovery scan by scanId. Operator-deploy only; degrades to info when unprovisioned. Returns scan status (running | completed | failed) and progress metadata.',
		schema: ScanBucketsStatusArgs,
		group: 'intelligence',
		scanIncluded: false,
	},
	scan_buckets_findings: {
		description:
			'Retrieve findings from a completed cloud-bucket discovery scan. Operator-deploy only; degrades to info when unprovisioned. Optionally scoped to a specific scanId; omit to retrieve the most recent findings.',
		schema: ScanBucketsFindingsArgs,
		group: 'intelligence',
		scanIncluded: false,
	},
	osint_investigate_domain_start: {
		description:
			'Start an async OSINT investigation for a domain. Operator-deploy only; degrades to info when unprovisioned. Returns an investigationId immediately — poll with osint_investigation_status and retrieve results with osint_investigation_report.',
		schema: OsintInvestigateArgs,
		group: 'intelligence',
		scanIncluded: false,
		mutating: true,
	},
	osint_investigate_infrastructure_start: {
		description:
			'Start an async deep-infrastructure OSINT investigation for a query (domain, IP, or org). Operator-deploy only; degrades to info when unprovisioned. Returns an investigationId immediately — poll with osint_investigation_status.',
		schema: OsintInvestigateArgs,
		group: 'intelligence',
		scanIncluded: false,
		mutating: true,
	},
	osint_investigate_supply_chain_start: {
		description:
			'Start an async supply-chain OSINT investigation for a query. Operator-deploy only; degrades to info when unprovisioned. Returns an investigationId immediately — poll with osint_investigation_status.',
		schema: OsintInvestigateArgs,
		group: 'intelligence',
		scanIncluded: false,
		mutating: true,
	},
	osint_investigate_username_start: {
		description:
			'Start an async OSINT investigation for a username (cross-platform presence, breach correlation). Owner/enterprise tier only — people-centric OSINT is restricted to prevent misuse. Returns an investigationId immediately — poll with osint_investigation_status and retrieve results with osint_investigation_report.',
		schema: OsintInvestigateArgs,
		group: 'intelligence',
		scanIncluded: false,
		mutating: true,
	},
	osint_investigate_email_start: {
		description:
			'Start an async OSINT investigation for an email address (breach exposure, account correlation). Owner/enterprise tier only — people-centric OSINT is restricted to prevent misuse. Returns an investigationId immediately — poll with osint_investigation_status and retrieve results with osint_investigation_report.',
		schema: OsintInvestigateArgs,
		group: 'intelligence',
		scanIncluded: false,
		mutating: true,
	},
	osint_investigation_status: {
		description:
			'Poll the status of an OSINT investigation by investigationId. Operator-deploy only; degrades to info when unprovisioned. Returns current status (running | completed | failed) and progress metadata.',
		schema: OsintInvestigationIdArgs,
		group: 'intelligence',
		scanIncluded: false,
	},
	osint_investigation_report: {
		description:
			'Retrieve the final report of a completed OSINT investigation by investigationId. Operator-deploy only; degrades to info when unprovisioned or not yet complete.',
		schema: OsintInvestigationIdArgs,
		group: 'intelligence',
		scanIncluded: false,
	},
};

/**
 * Special-case tools whose `tools/call` `structuredContent` is NOT a `CheckResult`
 * (custom shapes: scan reports, batch arrays, generated records, comparisons,
 * baseline results, etc.). These dispatch outside the `TOOL_REGISTRY` CheckResult
 * path in `handlers/tools.ts` and therefore get NO `outputSchema`.
 *
 * Every other tool flows through the registry path (`buildToolResult(..., result, ...)`
 * where `result: CheckResult`), so its `structuredContent` IS a `CheckResult` and
 * gets the lenient CheckResult `outputSchema`.
 */
const NON_CHECK_RESULT_TOOLS = new Set<string>([
	'scan_domain',
	'batch_scan',
	'compare_domains',
	'compare_baseline',
	'generate_fix_plan',
	'generate_spf_record',
	'generate_dmarc_record',
	'generate_dkim_config',
	'generate_mta_sts_policy',
	'get_benchmark',
	'get_provider_insights',
	'assess_spoofability',
	'check_resolver_consistency',
	'explain_finding',
	'map_supply_chain',
	'analyze_drift',
	'validate_fix',
	'generate_rollout_plan',
	'resolve_spf_chain',
	'discover_subdomains',
	'map_compliance',
	'simulate_attack_paths',
]);

/** Lenient CheckResult output schema — derived once, shared across all CheckResult tools. */
const CHECK_RESULT_OUTPUT_SCHEMA = buildCheckResultOutputJsonSchema();

export const TOOLS: McpTool[] = Object.entries(TOOL_DEFS).map(([name, def]) => ({
	name,
	description: def.description,
	inputSchema: toInputSchema(def.schema),
	...(NON_CHECK_RESULT_TOOLS.has(name) ? {} : { outputSchema: CHECK_RESULT_OUTPUT_SCHEMA }),
	annotations: {
		title: toolNameToTitle(name),
		readOnlyHint: !def.mutating,
		destructiveHint: Boolean(def.destructive),
		idempotentHint: !def.mutating,
		openWorldHint: true,
	},
	group: def.group,
	...(def.tier !== undefined && { tier: def.tier }),
	scanIncluded: def.scanIncluded,
}));

export { TOOL_SCHEMA_MAP };
