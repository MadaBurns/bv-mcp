// SPDX-License-Identifier: BUSL-1.1

import type { Tier } from '../schemas/primitives';

/**
 * Centralized configuration for domain normalization and validation.
 */
export const BLOCKED_SUFFIXES = [
	'.local',
	'.localhost',
	'.internal',
	'.example',
	'.invalid',
	'.test',
	'.onion',
	'.lan',
	'.home',
	'.corp',
	'.intranet',
];
export const BLOCKED_HOSTS = ['localhost', 'localhost.localdomain'];
export const BLOCKED_IP_PATTERNS = [
	/^127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$/,
	/^10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$/,
	/^172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}$/,
	/^192\.168\.[0-9]{1,3}\.[0-9]{1,3}$/,
	/^169\.254\.[0-9]{1,3}\.[0-9]{1,3}$/,
	/^0\.0\.0\.0$/,
	/^::1$/,
	/^fc00:/i,
	/^fd[0-9a-f]{2}:/i,
	/^fe[89ab][0-9a-f]:/i,
];
export const BLOCKED_DNS_REBINDING = ['.nip.io', '.sslip.io', '.xip.io', '.nip.direct'];
export const MAX_DOMAIN_LENGTH = 253;
export const MAX_LABEL_LENGTH = 63;
export const LABEL_REGEX = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/i;

/** Hard limit on incoming JSON-RPC request body size (bytes). */
export const MAX_REQUEST_BODY_BYTES = 10_240;

/** Timeout for outbound HTTPS fetches (SSL, MTA-STS policy, etc.). */
export const HTTPS_TIMEOUT_MS = 4_000;

/** Default timeout for DNS-over-HTTPS queries. CF DoH p99 is <500ms. */
export const DNS_TIMEOUT_MS = 3_000;

/** Default number of retry attempts for DNS-over-HTTPS queries. */
export const DNS_RETRIES = 1;

/** Edge cache TTL (seconds) for outbound DoH fetch requests via Cloudflare's cf API. */
export const DOH_EDGE_CACHE_TTL = 300;

/** Timeout (ms) after which a stuck INFLIGHT promise is evicted from the dedup map. */
export const INFLIGHT_CLEANUP_MS = 30_000;

/** Base delay (ms) between DNS retry attempts. Actual delay = base * (attempt+1) + jitter. */
export const DNS_RETRY_BASE_DELAY_MS = 75;

/**
 * When true, empty DoH answers from the primary resolver are optionally
 * confirmed with a secondary resolver to reduce false negatives.
 */
export const DNS_CONFIRM_WITH_SECONDARY_ON_EMPTY = true;

/** Default cache TTL in seconds. Override via CACHE_TTL_SECONDS env var. */
export const DEFAULT_CACHE_TTL_SECONDS = 300;

/**
 * Parse CACHE_TTL_SECONDS env var, clamping to [60, 3600].
 * Returns DEFAULT_CACHE_TTL_SECONDS when absent or invalid.
 */
export function parseCacheTtl(envValue?: string): number {
	if (!envValue) return DEFAULT_CACHE_TTL_SECONDS;
	const parsed = Number(envValue);
	if (!Number.isFinite(parsed) || parsed < 60) return DEFAULT_CACHE_TTL_SECONDS;
	return Math.min(parsed, 3600);
}

/**
 * Global daily free-tier request ceiling across all unauthenticated IPs.
 * Protects from abuse by capping free usage at a service-wide level.
 * Authenticated requests are exempt.
 */
export const GLOBAL_DAILY_TOOL_LIMIT = 500_000;

/**
 * Free-tier daily tool quotas for unauthenticated callers.
 * Tools omitted from this map are governed only by baseline per-IP rate limits.
 */
/** MCP API key tiers with daily scan quotas. Derived from the Zod TierSchema in schemas/primitives. */
export type McpApiKeyTier = Tier;

/** Daily scan limits per API key tier (applies per tool unless overridden by TIER_TOOL_DAILY_LIMITS). */
export const TIER_DAILY_LIMITS: Record<McpApiKeyTier, number> = {
	free: 50,
	agent: 200,
	developer: 500,
	enterprise: 10_000,
	partner: 100_000,
	owner: Infinity,
};

/**
 * Per-tool daily limit overrides for specific tiers.
 * When a tier+tool combo exists here, it takes precedence over the flat TIER_DAILY_LIMITS value.
 */
export const TIER_TOOL_DAILY_LIMITS: Partial<Record<McpApiKeyTier, Record<string, number>>> = {
	partner: {
		scan_domain: 100_000,
		scan: 100_000,
		compare_baseline: 100_000,
		check_spf: 500_000,
		check_dmarc: 500_000,
		check_dkim: 500_000,
		check_mx: 500_000,
		check_ns: 500_000,
		check_ssl: 500_000,
		check_dnssec: 500_000,
		check_mta_sts: 500_000,
		check_caa: 500_000,
		check_bimi: 500_000,
		check_tlsrpt: 500_000,
		check_lookalikes: 50_000,
		check_shadow_domains: 50_000,
		check_txt_hygiene: 500_000,
		check_http_security: 500_000,
		check_dane: 500_000,
		check_mx_reputation: 50_000,
		check_srv: 500_000,
		check_zone_hygiene: 500_000,
		explain_finding: 500_000,
	},
};

export const FREE_TOOL_DAILY_LIMITS: Record<string, number> = {
	scan_domain: 75,
	scan: 75,
	check_spf: 200,
	check_dmarc: 200,
	check_dkim: 200,
	check_mx: 200,
	check_ns: 200,
	check_ssl: 200,
	check_dnssec: 200,
	check_mta_sts: 200,
	check_caa: 200,
	check_bimi: 200,
	check_tlsrpt: 200,
	check_lookalikes: 20,
	explain_finding: 200,
	compare_baseline: 150,
	check_shadow_domains: 20,
	check_txt_hygiene: 200,
	check_http_security: 200,
	check_dane: 200,
	check_mx_reputation: 20,
	check_srv: 200,
	check_zone_hygiene: 200,
	generate_fix_plan: 75,
	generate_spf_record: 200,
	generate_dmarc_record: 200,
	generate_dkim_config: 200,
	generate_mta_sts_policy: 200,
	get_benchmark: 100,
	get_provider_insights: 50,
	assess_spoofability: 150,
	check_resolver_consistency: 50,
	map_supply_chain: 75,
	analyze_drift: 75,
	validate_fix: 200,
	generate_rollout_plan: 150,
	resolve_spf_chain: 100,
	discover_subdomains: 50,
	map_compliance: 75,
	simulate_attack_paths: 75,
};
