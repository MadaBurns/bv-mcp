// SPDX-License-Identifier: BUSL-1.1

import { z } from 'zod';
import {
	BaseDomainArgs,
	ScanDomainArgs,
	BatchScanArgs,
	CompareDomainsArgs,
	CheckDkimArgs,
	CheckResolverConsistencyArgs,
	GenerateArgs,
	ExplainFindingArgs,
	CompareBaselineArgs,
	GetDomainRankArgs,
	GetBenchmarkArgs,
	GetProviderInsightsArgs,
	ValidateFixArgs,
	MapSupplyChainArgs,
	AnalyzeDriftArgs,
	CheckFastFluxArgs,
	CheckAgentDiscoveryArgs,
	CheckSubdomainTakeoverArgs,
	RootServerSetArgs,
	DiscoverBrandDomainsArgs,
	DiscoverBrandDomainsStartArgs,
	DiscoverBrandDomainsStatusArgs,
	DiscoverBrandDomainsFindingsArgs,
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
	QuerySigninsArgs,
	QueryUalArgs,
	GetCaPoliciesArgs,
	AssessCoverageArgs,
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
	| 'discovery'
	| 'identity_secops';
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
	/**
	 * True for the curated "starter set" — the small, high-value subset a client
	 * can surface to avoid overwhelming an LLM with the full flat tool list. Additive
	 * signal only (every tool is still listed); absent means "not curated", not a
	 * negative. MUST mirror the tools named in SERVER_INSTRUCTIONS (the channel
	 * that actually reaches the model) — see src/mcp/server-instructions.ts.
	 */
	recommended?: boolean;
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
	/**
	 * Explicit `idempotentHint` override. Annotations default `idempotentHint` to
	 * `!mutating`, which is wrong for a destructive-but-idempotent operation such
	 * as a delete-by-id (deleting the same id twice yields the same end state).
	 * Set this `true` on such tools so the published annotation is honest; leave
	 * unset to use the `!mutating` default.
	 */
	idempotent?: boolean;
	/** Curated starter-set member (see McpTool.recommended). Mirror SERVER_INSTRUCTIONS. */
	recommended?: boolean;
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
	// `additionalProperties: false` (from a `.strict()` runtime schema) is KEPT so
	// the published surface is HONEST about extra-prop handling: the runtime hard-
	// rejects unknown props, so the schema must say so too (F6). `.passthrough()`
	// schemas never reach here with `false` — they emit `{}`, cleaned away above.
	return jsonSchema as McpTool['inputSchema'];
}

/** All MCP tool definitions. */
const TOOL_DEFS: Record<string, ToolDef> = {
	check_mx: {
		description: 'Look up MX records for a domain. Identifies which mail servers receive inbound email for the domain and which email hosting provider is used (Google Workspace, Microsoft 365, Proofpoint, etc.). Use when asked which email provider hosts inbound mail for a domain, or to see MX record configuration.',
		schema: BaseDomainArgs,
		group: 'email_auth',
		tier: 'protective',
		scanIncluded: true,
	},
	check_spf: {
		description: 'Look up and validate the SPF record for a domain. Lists all IP addresses and third-party senders authorised to send email on behalf of the domain, flags syntax errors, and shows the trust surface (which mail servers are whitelisted). Use when you need to know who is permitted to send email as a domain.',
		schema: BaseDomainArgs,
		group: 'email_auth',
		tier: 'core',
		scanIncluded: true,
	},
	check_dmarc: {
		description: 'Look up and validate the DMARC record for a domain. Shows the enforcement level (none/quarantine/reject), alignment mode (strict/relaxed), and aggregate/forensic reporting destinations. Use to determine a domain\'s DMARC enforcement level, whether it sends aggregate reports, or if it is protected against email impersonation — distinct from check_shadow_domains (which checks TLD variants) and assess_spoofability (composite score).',
		schema: BaseDomainArgs,
		group: 'email_auth',
		tier: 'core',
		scanIncluded: true,
	},
	check_dkim: {
		description: 'Look up DKIM records for a domain. Probes common selectors, validates the signing algorithm used for outgoing email (RSA-1024/2048, Ed25519), and reports key strength. Use to verify that outbound email signatures are cryptographically sound.',
		schema: CheckDkimArgs,
		group: 'email_auth',
		tier: 'core',
		scanIncluded: true,
	},
	check_dnssec: {
		description: 'Check DNSSEC status for a domain. Verifies whether DNS is tamper-proof and protected against cache poisoning and DNS spoofing attacks by validating DNSKEY and DS records. Reports whether DNSSEC is enabled and validating.',
		schema: BaseDomainArgs,
		group: 'infrastructure',
		tier: 'core',
		scanIncluded: true,
	},
	check_ssl: {
		description: 'Check the SSL/TLS certificate for a domain. Shows the issuer (Certificate Authority), expiry date (when the certificate expires), supported protocol versions (TLS 1.2/1.3), and HTTPS configuration. Use to verify certificate validity and who issued it.',
		schema: BaseDomainArgs,
		group: 'infrastructure',
		tier: 'core',
		scanIncluded: true,
	},
	check_mta_sts: {
		description:
			'Check whether a domain enforces SMTP TLS for inbound mail via MTA-STS, protecting against downgrade attacks. Queries _mta-sts.<domain> and fetches the policy file, reports mode (enforce/testing/none) and MX coverage. Use to verify whether inbound SMTP is protected against TLS downgrade or MITM — distinct from check_dane which uses TLSA pinning.',
		schema: BaseDomainArgs,
		group: 'email_auth',
		tier: 'protective',
		scanIncluded: true,
	},
	check_ns: {
		description: 'Look up NS (nameserver) records for a domain. Identifies the DNS nameserver provider (Cloudflare, Route53, NS1, etc.) and shows delegation and redundancy. Use to find out which authoritative nameserver or DNS hosting service is used for a domain.',
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
		description:
			'Check the BIMI brand-logo record at default._bimi.<domain>. Validates the logo URL (l=) and VMC certificate evidence (a=), and verifies the DMARC enforcement prerequisite (p=quarantine/reject) that mail clients require before displaying a BIMI logo. Returns findings for a missing/malformed record or unmet prerequisites. Use to assess brand-indicator readiness in inboxes.',
		schema: BaseDomainArgs,
		group: 'brand_threats',
		tier: 'hardening',
		scanIncluded: true,
	},
	check_tlsrpt: {
		description:
			'Check whether a domain has SMTP TLS Reporting (TLS-RPT) configured. Queries _smtp._tls.<domain> for the v=TLSRPTv1 record and validates its reporting destination (rua= mailto:/https:), flagging a missing record, duplicate records, or an invalid/absent reporting URI. Complements MTA-STS by giving visibility into TLS delivery failures.',
		schema: BaseDomainArgs,
		group: 'brand_threats',
		tier: 'hardening',
		scanIncluded: true,
	},
	check_http_security: {
		description:
			'Audit a domain\'s browser-facing HTTP security headers over HTTPS. Inspects Content-Security-Policy (flagging unsafe-inline/unsafe-eval/wildcards), X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, and the cross-origin isolation headers (COOP/COEP/CORP), and detects CDN/WAF interception. Returns per-header findings for missing or weak protections against XSS, clickjacking, and cross-origin attacks.',
		schema: BaseDomainArgs,
		group: 'infrastructure',
		tier: 'protective',
		scanIncluded: true,
	},
	check_dane: {
		description:
			'Check DANE/TLSA certificate pinning for SMTP at port 25. Resolves the domain\'s MX hosts and looks up TLSA records at _25._tcp.<mx-host>, verifying whether SMTP mail-server certificates are bound in DNS (DNSSEC-backed protection against CA misissuance and MITM on inbound mail). Use when asked if SMTP connections are protected by DANE/TLSA pinning. For HTTPS DANE at port 443, use check_dane_https instead.',
		schema: BaseDomainArgs,
		group: 'infrastructure',
		tier: 'hardening',
		scanIncluded: true,
	},
	check_ptr: {
		description: 'Verify forward-confirmed reverse DNS (PTR/FCrDNS) for mail servers.',
		schema: BaseDomainArgs,
		group: 'infrastructure',
		tier: 'hardening',
		scanIncluded: true,
	},
	check_dane_https: {
		description: 'Verify DANE certificate pinning for HTTPS connections. Looks up TLSA records at _443._tcp.{domain} (port 443) to confirm the web certificate is pinned in DNS. Distinct from check_dane which covers SMTP at port 25.',
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
		description: 'Detect active typosquat and lookalike/homoglyph domains that impersonate your brand and could be used in phishing. Identifies character-substitution and visual-confusion domains registered by attackers. Distinct from check_shadow_domains (TLD variants with auth gaps) and discover_brand_domains (legitimate brand portfolio).',
		schema: BaseDomainArgs,
		group: 'brand_threats',
		tier: 'protective',
		scanIncluded: false,
	},
	check_subdomailing: {
		description: 'Detect SubdoMailing risk: analyzes the SPF include chain for dangling or hijackable subdomains that could let an attacker send email as the domain. Use when you want to know if an SPF include chain can be hijacked through a dangling domain, or to detect subdomain mailing risk hidden in SPF includes.',
		schema: BaseDomainArgs,
		group: 'email_auth',
		tier: 'protective',
		scanIncluded: true,
	},
	scan_domain: {
		description:
			'Run a full DNS and email security audit for a single domain. Aggregates every scan-included check in parallel (SPF, DKIM, DMARC, DNSSEC, TLS/SSL, MTA-STS, CAA, BIMI, subdomain takeover, and more) and returns an overall security score, letter grade (A–F), maturity stage, and prioritized findings. Use for a comprehensive single-domain audit, to get a domain\'s overall security grade, or to assess email security maturity.',
		schema: ScanDomainArgs,
		group: 'meta',
		scanIncluded: false,
		recommended: true,
	},
	batch_scan: {
		description: 'Bulk-scan up to 10 domains in parallel. Runs a full security audit on each domain in the list and returns score, letter grade, and finding counts per domain. Use when you want to audit multiple domains at once or do a bulk scan of several domains simultaneously — distinct from compare_domains which does a side-by-side analysis of 2–5 domains.',
		schema: BatchScanArgs,
		group: 'meta',
		scanIncluded: false,
	},
	compare_domains: {
		description: 'Side-by-side security comparison of 2–5 domains. Shows relative scores, category gaps, and unique weaknesses for each domain. Use when comparing your security posture against a competitor, or doing a head-to-head comparison between multiple domains.',
		schema: CompareDomainsArgs,
		group: 'meta',
		scanIncluded: false,
	},
	compare_baseline: {
		description: 'Compare a domain\'s current security configuration against a fixed policy baseline to determine compliance. Use to check whether a domain meets a policy requirement — not for tracking improvement/regression over time (use analyze_drift) and not for comparing multiple domains (use compare_domains).',
		schema: CompareBaselineArgs,
		group: 'meta',
		scanIncluded: false,
		recommended: true,
	},
	check_shadow_domains: {
		description: 'Find alternate TLD variants of a domain (e.g. example.net, example.co) that have weak or missing email authentication and could be used to spoof email. Use when asked about TLD variants with email auth gaps — distinct from check_lookalikes which detects typosquat/homoglyph impersonation domains.',
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
		description: 'Check whether the mail server (MX) IP addresses are listed on spam blocklists (Spamhaus, Barracuda, SORBS, and other RBLs). Also verifies reverse DNS for MX hosts. Use when you want to know if your mail server IP is blacklisted, or if your MX is on any blocklist — distinct from check_rbl which checks a specific IP directly.',
		schema: BaseDomainArgs,
		group: 'email_auth',
		tier: 'hardening',
		scanIncluded: false,
	},
	check_srv: {
		description:
			'Map a domain\'s DNS-visible service footprint by probing ~16 common SRV record prefixes (email, calendar, messaging, web, directory) in parallel. Returns discovered services and flags insecure service advertisements — e.g. plaintext IMAP/POP3 without an encrypted variant. Use when asked to map DNS-visible services or flag insecure service advertisements.',
		schema: BaseDomainArgs,
		group: 'infrastructure',
		tier: 'hardening',
		scanIncluded: false,
	},
	check_zone_hygiene: {
		description: 'Audit DNS zone hygiene: identifies sensitive or forgotten subdomains exposed in DNS, stale SOA records, and zone propagation issues. Use to find any sensitive subdomains that should not be publicly visible, or to audit overall DNS zone cleanliness.',
		schema: BaseDomainArgs,
		group: 'infrastructure',
		tier: 'hardening',
		scanIncluded: false,
	},
	generate: {
		description:
			'Generate a DNS/email security remediation artifact. Artifact types: spf_record (build a new SPF record), dmarc_record (create a DMARC policy), dkim_config (DKIM key setup), mta_sts_policy (generate an MTA-STS policy file), fix_plan (prioritized remediation plan for all findings), or rollout_plan (phased DMARC enforcement timeline). Use when asked to generate or create a record or policy.',
		schema: GenerateArgs,
		group: 'remediation',
		scanIncluded: false,
	},
	get_domain_rank: {
		description:
			'Rank a domain against its country or global cohort using the GSI benchmark corpus. Accepts a domain score (from scan_domain) and optional country/sector; returns a percentile: "scores better than X% of peers". Owner-gate exempt — public cohort data only.',
		schema: GetDomainRankArgs,
		group: 'intelligence',
		scanIncluded: false,
	},
	get_benchmark: {
		description: 'Get industry benchmark data: shows what percentile a domain\'s security score ranks at within its sector or country cohort, the mean score, and the most common DNS security failures across the industry. Use when asked how a score compares to the industry average, what percentile a score is in, or what the most common security failures are in an industry or sector.',
		schema: GetBenchmarkArgs,
		group: 'intelligence',
		scanIncluded: false,
	},
	get_provider_insights: {
		description: 'Get security benchmarks and common configuration issues for a specific email or DNS service-provider cohort (e.g. Google Workspace customers, Microsoft 365 customers). Use when asked how an email service provider compares to competitors on security posture, or to see typical misconfigurations for a named vendor\'s customers.',
		schema: GetProviderInsightsArgs,
		group: 'intelligence',
		scanIncluded: false,
	},
	assess_spoofability: {
		description:
			'Compute a composite email spoofability risk score (0–100, higher = more spoofable) by combining SPF trust surface, DMARC enforcement, and DKIM coverage. Returns a risk level (minimal→critical), per-control sub-scores, and plain-language summary of how easy it would be to spoof email from the domain. Use when asked how easy it is to spoof email from a domain, or for a composite email spoofing risk score.',
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
		recommended: true,
	},
	map_supply_chain: {
		description:
			'Map DNS-visible third-party service dependencies for a domain. Correlates SPF, NS, TXT verifications, SRV services, and CAA records to reveal which third-party vendors can send email as the domain, control DNS, or access integrated services. Use when asked to map third-party or supply-chain dependencies — not for listing who can send email (use check_spf for that).',
		schema: MapSupplyChainArgs,
		group: 'intelligence',
		scanIncluded: false,
	},
	analyze_drift: {
		description: 'Measure whether a domain\'s DNS security posture improved or regressed by comparing the current state against a prior scan snapshot. Returns a drift classification (improving/stable/regressing/mixed), score delta, and lists of improvements and regressions. Use to answer "did our security score improve or regress since last time?" — distinct from compare_baseline which checks compliance against a fixed policy (not improvement over time).',
		schema: AnalyzeDriftArgs,
		group: 'intelligence',
		scanIncluded: false,
	},
	validate_fix: {
		description: 'Re-check a specific security control after applying a fix, to confirm the finding is now resolved. Use only when a fix has already been applied and you want to verify or confirm the remediation was successful — not for initial inspection of a record.',
		schema: ValidateFixArgs,
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
			'Check MX server IP reputation against 7 DNS-based Real-time Blocklists (SpamCop, UCEProtect, Mailspike, Barracuda, PSBL, SORBS). Resolves MX hosts to IPs first.',
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
			'Fetch domain registration data via RDAP (modern WHOIS replacement). Returns the domain registrar (the company the domain was registered with), registrant contact, creation/expiration dates, EPP status codes, and domain age. Use when asked who registered the domain, who the registrar is, or when the registration expires — distinct from check_ns which identifies the DNS nameserver provider.',
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
			'Walk the full DNSSEC chain of trust from the DNS root down to the target domain, tracing DS/DNSKEY records and algorithm usage at each zone level. Use when asked to trace the chain of trust from the DNS root, or to see the full DNSSEC delegation path step by step.',
		schema: BaseDomainArgs,
		group: 'intelligence',
		scanIncluded: false,
	},
	check_agent_discovery: {
		description:
			'Assess the security posture of IETF BANDAID agent-discovery records (draft-mozleywilliams-dnsop-dnsaid). Detects SVCB agent records under _agents/_index._{protocol}._agents, reports whether the discovery zone is DNSSEC-anchored (unsigned = spoofable agent endpoints), evaluates DANE/TLSA binding trust (RFC 6698 §10.1), and checks capability-document integrity (cap / cap-sha256). Read-only; uses Private-Use SVCB param code points pending IANA assignment.',
		schema: CheckAgentDiscoveryArgs,
		group: 'intelligence',
		scanIncluded: false,
	},
	check_dnskey_strength: {
		description:
			'Audit the cryptographic strength of DNSKEY signing algorithms used for DNSSEC. Reports which algorithm is used for DNSSEC signing keys (RSA/SHA-1, RSA/SHA-256, ECDSA P-256, Ed25519, etc.), flags deprecated algorithms (RSA/SHA-1, DSA), independent of whether the DNSSEC chain validates. Use when asked what algorithm is used for DNSSEC signing keys, or if deprecated DNSKEY algorithms are in use.',
		schema: BaseDomainArgs,
		group: 'infrastructure',
		tier: 'hardening',
		scanIncluded: true,
	},
	check_fast_flux: {
		description:
			'Detect fast-flux DNS behavior: performs multiple rounds of A/AAAA queries and checks whether IP addresses are rotating rapidly on each DNS query (a sign of botnet or malicious infrastructure). Compares IP answer sets and TTLs across rounds to identify rapidly rotating infrastructure used to hide malicious activity.',
		schema: CheckFastFluxArgs,
		group: 'intelligence',
		scanIncluded: false,
	},
	check_subdomain_takeover: {
		description:
			'Sweep subdomains for dangling CNAMEs pointing to deprovisioned cloud services that could be claimed by an attacker (subdomain takeover vulnerabilities). Detects 16 provider families (AWS S3/CloudFront, Azure Front Door/CDN/Blob/App Service, GCP Cloud Storage, Heroku, GitHub Pages, Vercel, Firebase, Shopify, etc.). Use when asked if subdomains are pointing to deprovisioned cloud services. Pair with discover_subdomains for full inventory.',
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
			"Discover all domains that belong to a brand's portfolio by aggregating certificate, DNS, redirect, and mail-policy signals. Use when asked what domains are part of a brand portfolio, or to find all domains related to a brand. Pass the EXACT seed domain verbatim — do NOT normalize or substitute a canonical domain.",
		schema: DiscoverBrandDomainsArgs,
		group: 'discovery',
		scanIncluded: false,
	},
	discover_brand_domains_start: {
		description:
			'Start an async brand-domain discovery for the EXACT seed domain provided (the async sibling of discover_brand_domains, which can run ~24s and time out interactive clients). Same args as discover_brand_domains. Returns { auditId, queuedAt, etaSeconds } immediately; poll with discover_brand_domains_status and fetch ranked candidates with discover_brand_domains_findings once complete.',
		schema: DiscoverBrandDomainsStartArgs,
		group: 'discovery',
		scanIncluded: false,
		mutating: true,
	},
	discover_brand_domains_status: {
		description:
			"Poll the status of an async brand-domain discovery started with discover_brand_domains_start. Returns status (queued | running | completed | failed) and progress. Owner-scoped — operationIds owned by other principals surface as notFound.",
		schema: DiscoverBrandDomainsStatusArgs,
		group: 'discovery',
		scanIncluded: false,
	},
	discover_brand_domains_findings: {
		description:
			'Fetch the ranked candidate domains (the discovery CheckResult) for an async run started with discover_brand_domains_start. Returns notReady while the discovery is still in-flight; the discovery result once complete. Owner-scoped.',
		schema: DiscoverBrandDomainsFindingsArgs,
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
		// delete-by-id: re-deleting the same watchId is a no-op (notFound), so the
		// operation is idempotent even though it is destructive (F5).
		idempotent: true,
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
			'Retrieve findings from a completed cloud-bucket discovery scan. Operator-deploy only; degrades to info when unprovisioned. Optionally scoped to a specific scanId, target, and provider list; omit scanId to retrieve the most recent findings.',
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
	query_signins: {
		description:
			'Query Microsoft Entra sign-in logs for a tenant. Optionally filter by user principal name, failure status, or lookback window. Requires m365Proxy service binding; returns { unprovisioned: true } when absent. A `representative: true` field in the response marks sample (non-live) data until live Graph reads land.',
		schema: QuerySigninsArgs,
		group: 'identity_secops',
		tier: 'protective',
		scanIncluded: false,
	},
	query_ual: {
		description:
			'Query the Microsoft 365 Unified Audit Log for a tenant. Optionally filter by operation type, user, or lookback window. Requires m365Proxy service binding; returns { unprovisioned: true } when absent. A `representative: true` field in the response marks sample (non-live) data until live Graph reads land.',
		schema: QueryUalArgs,
		group: 'identity_secops',
		tier: 'protective',
		scanIncluded: false,
	},
	get_ca_policies: {
		description:
			'Retrieve Conditional Access policies for a Microsoft Entra tenant. Requires m365Proxy service binding; returns { unprovisioned: true } when absent. A `representative: true` field in the response marks sample (non-live) data until live Graph reads land.',
		schema: GetCaPoliciesArgs,
		group: 'identity_secops',
		tier: 'protective',
		scanIncluded: false,
	},
	assess_coverage: {
		description:
			'Assess Conditional Access coverage gaps for a Microsoft Entra tenant — identifies users and apps not protected by any enforced policy. Requires m365Proxy service binding; returns { unprovisioned: true } when absent. A `representative: true` field in the response marks sample (non-live) data until live Graph reads land.',
		schema: AssessCoverageArgs,
		group: 'identity_secops',
		tier: 'protective',
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
 *
 * Exported as the single source of truth for the CheckResult/non-CheckResult
 * partition: it drives `outputSchema` population on `TOOLS` below, and tests
 * import it rather than re-declaring a drift-prone copy (see
 * `test/tool-output-schema.spec.ts`).
 */
export const NON_CHECK_RESULT_TOOLS = new Set<string>([
	'scan_domain',
	'batch_scan',
	'compare_domains',
	'compare_baseline',
	'generate',
	'get_domain_rank',
	'get_benchmark',
	'get_provider_insights',
	'assess_spoofability',
	'check_resolver_consistency',
	'explain_finding',
	'map_supply_chain',
	'analyze_drift',
	'validate_fix',
	'resolve_spf_chain',
	'discover_subdomains',
	'map_compliance',
	'simulate_attack_paths',
	// discover_brand_domains async trio — custom summary-metadata shape
	'discover_brand_domains_start',
	'discover_brand_domains_status',
	'discover_brand_domains_findings',
	// identity_secops — M365 read tools (custom shape, not CheckResult)
	'query_signins',
	'query_ual',
	'get_ca_policies',
	'assess_coverage',
]);

/** Lenient CheckResult output schema — derived once, shared across all CheckResult tools. */
const CHECK_RESULT_OUTPUT_SCHEMA = buildCheckResultOutputJsonSchema();

export const TOOLS: McpTool[] = Object.entries(TOOL_DEFS).map(([name, def]) => ({
	name,
	description: def.scanIncluded ? `${def.description} Part of the scan_domain audit.` : def.description,
	inputSchema: toInputSchema(def.schema),
	...(NON_CHECK_RESULT_TOOLS.has(name) ? {} : { outputSchema: CHECK_RESULT_OUTPUT_SCHEMA }),
	annotations: {
		title: toolNameToTitle(name),
		readOnlyHint: !def.mutating,
		destructiveHint: Boolean(def.destructive),
		// `!mutating` is the default, but a destructive-but-idempotent op (e.g. a
		// delete-by-id) sets `idempotent: true` explicitly to override it (F5).
		idempotentHint: def.idempotent ?? !def.mutating,
		openWorldHint: true,
	},
	group: def.group,
	...(def.tier !== undefined && { tier: def.tier }),
	scanIncluded: def.scanIncluded,
	...(def.recommended && { recommended: true as const }),
}));

export { TOOL_SCHEMA_MAP };
