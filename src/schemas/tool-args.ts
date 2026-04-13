// SPDX-License-Identifier: BUSL-1.1

import { z } from 'zod';
import {
	DomainSchema,
	FormatSchema,
	ProfileSchema,
	BenchmarkProfileSchema,
	DkimSelectorSchema,
	RecordTypeSchema,
	GradeSchema,
	SafeLabelSchema,
	DmarcPolicySchema,
	ExplainStatusSchema,
} from './primitives';

/** Domain + optional format — shared by most check tools. */
export const BaseDomainArgs = z.object({
	domain: DomainSchema.describe('Domain to check (e.g., example.com)'),
	format: FormatSchema.optional().describe('Output verbosity. Auto-detected if omitted.'),
}).passthrough();

/** scan_domain */
export const ScanDomainArgs = z.object({
	domain: DomainSchema.describe('Domain to check (e.g., example.com)'),
	profile: ProfileSchema.optional().describe('Scoring profile. Default "auto" detects.'),
	force_refresh: z.boolean().optional().describe('Bypass cache and run a fresh scan. Useful after DNS changes.'),
	format: FormatSchema.optional().describe('Output verbosity. Auto-detected if omitted.'),
}).passthrough();

/** batch_scan */
export const BatchScanArgs = z.object({
	domains: z.array(z.string().min(1).max(253)).min(1).max(10).describe('Domains to scan (max 10 per request)'),
	force_refresh: z.boolean().optional().describe('Bypass cache and run fresh scans.'),
	format: FormatSchema.optional().describe('Output verbosity. Auto-detected if omitted.'),
}).passthrough();

/** compare_domains */
export const CompareDomainsArgs = z.object({
	domains: z.array(z.string().min(1).max(253)).min(2).max(5).describe('Domains to compare (2–5 domains)'),
	format: FormatSchema.optional().describe('Output verbosity. Auto-detected if omitted.'),
}).passthrough();

/** check_dkim */
export const CheckDkimArgs = z.object({
	domain: DomainSchema.describe('Domain to check (e.g., example.com)'),
	selector: DkimSelectorSchema.optional().describe('DKIM selector. Omit to probe common ones.'),
	format: FormatSchema.optional().describe('Output verbosity. Auto-detected if omitted.'),
}).passthrough();

/** check_resolver_consistency */
export const CheckResolverConsistencyArgs = z.object({
	domain: DomainSchema.describe('Domain to check (e.g., example.com)'),
	record_type: RecordTypeSchema.optional().describe('Record type. Omit for A/AAAA/MX/TXT/NS.'),
	format: FormatSchema.optional().describe('Output verbosity. Auto-detected if omitted.'),
}).passthrough();

/** generate_spf_record */
export const GenerateSpfArgs = z.object({
	domain: DomainSchema.describe('Domain (e.g., example.com)'),
	// SafeLabelSchema provides min(1)/max(253); .regex() adds a stacking refinement in Zod v4 (does not override).
	include_providers: z.array(SafeLabelSchema.regex(/^[a-z0-9._-]+$/i)).max(15).optional().describe('Providers to include (e.g., ["google"]).'),
	format: FormatSchema.optional().describe('Output verbosity. Auto-detected if omitted.'),
}).passthrough();

/** generate_dmarc_record */
export const GenerateDmarcArgs = z.object({
	domain: DomainSchema.describe('Domain (e.g., example.com)'),
	policy: DmarcPolicySchema.optional().describe('Policy (default "reject").'),
	rua_email: z.string().max(254).optional().describe('Report email. Default: dmarc-reports@{domain}.'),
	format: FormatSchema.optional().describe('Output verbosity. Auto-detected if omitted.'),
}).passthrough();

/** generate_dkim_config */
export const GenerateDkimConfigArgs = z.object({
	domain: DomainSchema.describe('Domain (e.g., example.com)'),
	provider: z.string().max(100).optional().describe('Provider (e.g., "google"). Omit for generic.'),
	format: FormatSchema.optional().describe('Output verbosity. Auto-detected if omitted.'),
}).passthrough();

/** generate_mta_sts_policy */
export const GenerateMtaStsArgs = z.object({
	domain: DomainSchema.describe('Domain (e.g., example.com)'),
	// SafeLabelSchema provides min(1)/max(253); .regex() adds a stacking refinement in Zod v4 (does not override).
	mx_hosts: z.array(SafeLabelSchema.regex(/^[^\s\x00-\x1f\x7f]*$/)).max(20).optional().describe('MX hosts. Omit to detect from DNS.'),
	format: FormatSchema.optional().describe('Output verbosity. Auto-detected if omitted.'),
}).passthrough();

/** explain_finding */
export const ExplainFindingArgs = z.object({
	checkType: z.string().min(1).max(100).describe("Check type (e.g., 'SPF', 'DMARC')."),
	status: ExplainStatusSchema.describe('Finding severity or status.'),
	details: z.string().max(2000).optional().describe('Additional detail from check result.'),
	format: FormatSchema.optional().describe('Output verbosity. Auto-detected if omitted.'),
}).passthrough();

/** compare_baseline */
export const CompareBaselineArgs = z.object({
	domain: DomainSchema.describe('Domain to scan and compare.'),
	format: FormatSchema.optional().describe('Output verbosity. Auto-detected if omitted.'),
	baseline: z.object({
		grade: GradeSchema.optional().describe('Min grade (e.g., "B+").'),
		score: z.number().min(0).max(100).optional().describe('Min score (0-100).'),
		require_dmarc_enforce: z.boolean().optional().describe('Require DMARC enforce.'),
		require_spf: z.boolean().optional().describe('Require SPF.'),
		require_dkim: z.boolean().optional().describe('Require DKIM.'),
		require_dnssec: z.boolean().optional().describe('Require DNSSEC.'),
		require_mta_sts: z.boolean().optional().describe('Require MTA-STS.'),
		require_caa: z.boolean().optional().describe('Require CAA.'),
		max_critical_findings: z.number().int().min(0).optional().describe('Max critical findings (default 0).'),
		max_high_findings: z.number().int().min(0).optional().describe('Max high findings allowed.'),
	}).passthrough().describe('Policy baseline requirements.'),
}).passthrough();

/** get_benchmark */
export const GetBenchmarkArgs = z.object({
	profile: BenchmarkProfileSchema.optional().describe('Profile to benchmark (default "mail_enabled").'),
	format: FormatSchema.optional().describe('Output verbosity. Auto-detected if omitted.'),
}).passthrough();

/** get_provider_insights */
export const GetProviderInsightsArgs = z.object({
	provider: z.string().min(1).describe('Provider (e.g., "google workspace").'),
	profile: BenchmarkProfileSchema.optional().describe('Profile (default "mail_enabled").'),
	format: FormatSchema.optional().describe('Output verbosity. Auto-detected if omitted.'),
}).passthrough();

/** assess_spoofability — same as BaseDomainArgs */
export const AssessSpoofabilityArgs = BaseDomainArgs;

/** generate_fix_plan — same as BaseDomainArgs */
export const GenerateFixPlanArgs = BaseDomainArgs;

const CheckNameSchema = z.string().transform((v) => v.toLowerCase().trim()).pipe(
	z.enum(['spf', 'dmarc', 'dkim', 'dnssec', 'ssl', 'mta_sts', 'ns', 'caa', 'bimi', 'tlsrpt', 'http_security', 'dane']),
);

const TimelineSchema = z.string().transform((v) => v.toLowerCase()).pipe(
	z.enum(['aggressive', 'standard', 'conservative']),
);

const TargetPolicySchema = z.string().transform((v) => v.toLowerCase()).pipe(
	z.enum(['quarantine', 'reject']),
);

/** validate_fix */
export const ValidateFixArgs = z.object({
	domain: DomainSchema.describe('Domain to validate the fix for'),
	check: CheckNameSchema.describe('Check name to re-run (e.g., "dmarc", "spf")'),
	expected: z.string().max(1000).optional().describe('Expected DNS record value to verify against'),
	format: FormatSchema.optional().describe('Output verbosity. Auto-detected if omitted.'),
}).passthrough();

/** map_supply_chain — same as BaseDomainArgs */
export const MapSupplyChainArgs = BaseDomainArgs;

/** analyze_drift */
export const AnalyzeDriftArgs = z.object({
	domain: DomainSchema.describe('Domain to analyze drift for'),
	baseline: z.string().min(1).max(50_000).describe('Previous ScanScore JSON or "cached" to use last cached scan'),
	format: FormatSchema.optional().describe('Output verbosity. Auto-detected if omitted.'),
}).passthrough();

/** generate_rollout_plan */
export const GenerateRolloutPlanArgs = z.object({
	domain: DomainSchema.describe('Domain to generate rollout plan for'),
	target_policy: TargetPolicySchema.optional().describe('Target DMARC policy (default: reject)'),
	timeline: TimelineSchema.optional().describe('Rollout speed: aggressive, standard, conservative (default: standard)'),
	format: FormatSchema.optional().describe('Output verbosity. Auto-detected if omitted.'),
}).passthrough();

/** check_fast_flux — domain + rounds + format */
export const CheckFastFluxArgs = z.object({
	domain: DomainSchema.describe('Domain to check (e.g., example.com)'),
	rounds: z.number().int().min(3).max(5).optional().describe('Number of query rounds (3-5, default 3).'),
	format: FormatSchema.optional().describe('Output verbosity. Auto-detected if omitted.'),
}).passthrough();

/**
 * Map of every tool name to its Zod argument schema.
 * Used for runtime validation in tools.ts and for inputSchema generation.
 */
export const TOOL_SCHEMA_MAP: Record<string, z.ZodTypeAny> = {
	check_mx: BaseDomainArgs,
	check_spf: BaseDomainArgs,
	check_dmarc: BaseDomainArgs,
	check_dkim: CheckDkimArgs,
	check_dnssec: BaseDomainArgs,
	check_ssl: BaseDomainArgs,
	check_mta_sts: BaseDomainArgs,
	check_ns: BaseDomainArgs,
	check_caa: BaseDomainArgs,
	check_bimi: BaseDomainArgs,
	check_tlsrpt: BaseDomainArgs,
	check_lookalikes: BaseDomainArgs,
	check_shadow_domains: BaseDomainArgs,
	check_txt_hygiene: BaseDomainArgs,
	check_http_security: BaseDomainArgs,
	check_dane: BaseDomainArgs,
	check_dane_https: BaseDomainArgs,
	check_svcb_https: BaseDomainArgs,
	check_mx_reputation: BaseDomainArgs,
	check_srv: BaseDomainArgs,
	check_zone_hygiene: BaseDomainArgs,
	check_subdomailing: BaseDomainArgs,
	scan_domain: ScanDomainArgs,
	batch_scan: BatchScanArgs,
	compare_domains: CompareDomainsArgs,
	compare_baseline: CompareBaselineArgs,
	generate_fix_plan: GenerateFixPlanArgs,
	generate_spf_record: GenerateSpfArgs,
	generate_dmarc_record: GenerateDmarcArgs,
	generate_dkim_config: GenerateDkimConfigArgs,
	generate_mta_sts_policy: GenerateMtaStsArgs,
	get_benchmark: GetBenchmarkArgs,
	get_provider_insights: GetProviderInsightsArgs,
	assess_spoofability: AssessSpoofabilityArgs,
	check_resolver_consistency: CheckResolverConsistencyArgs,
	explain_finding: ExplainFindingArgs,
	validate_fix: ValidateFixArgs,
	map_supply_chain: MapSupplyChainArgs,
	analyze_drift: AnalyzeDriftArgs,
	generate_rollout_plan: GenerateRolloutPlanArgs,
	resolve_spf_chain: BaseDomainArgs,
	discover_subdomains: BaseDomainArgs,
	map_compliance: BaseDomainArgs,
	simulate_attack_paths: BaseDomainArgs,
	check_dbl: BaseDomainArgs,
	check_rbl: BaseDomainArgs,
	cymru_asn: BaseDomainArgs,
	rdap_lookup: BaseDomainArgs,
	check_nsec_walkability: BaseDomainArgs,
	check_dnssec_chain: BaseDomainArgs,
	check_fast_flux: CheckFastFluxArgs,
};
