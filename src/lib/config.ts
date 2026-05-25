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

/**
 * Hard limit on /internal/tools/batch and /internal/tenants/scan body size (bytes).
 *
 * Set to 256 KB so a service-binding caller can submit ~500 domains in a single
 * scan dispatch. Mirrors the existing local constant in `src/internal.ts`
 * (`BATCH_MAX_BODY_BYTES`); promoted here so the Tenant routes share the cap.
 */
export const MAX_INTERNAL_BATCH_BODY_BYTES = 262_144;

/**
 * Hard limit on /internal/tenants/portfolio body size (bytes).
 *
 * Larger than the batch cap because portfolio uploads carry up to 10K domains
 * per request (tenant-Scalable-Architecture-Design.md §4.1). 10K × ~30 chars +
 * JSON framing ≈ 350 KB; 512 KB gives headroom for longer FQDNs without
 * forcing Tenant's portal to chunk uploads.
 */
export const MAX_TENANT_PORTFOLIO_BODY_BYTES = 524_288;

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

/** Per-IP daily cap for unauthenticated callers, beneath the GLOBAL_DAILY_TOOL_LIMIT
 *  ceiling — stops one source consuming a disproportionate share of the global free
 *  budget while staying under the per-minute/hour limits (FIND-02). */
export const FREE_IP_DAILY_LIMIT = 1_000;

/**
 * Sliding-window thresholds for the fuzzing detector. Single source of truth —
 * the audit test in test/audits/fuzzing-config.audit.test.ts asserts these are
 * not duplicated elsewhere.
 *
 * Defaults are deliberately conservative for v1 rollout (×3 the values in
 * docs/plans/2026-05-07-fuzzing-detection-tdd-plan.md) so prod stays silent
 * for one week of baseline collection before lowering.
 */
export const FUZZ_THRESHOLDS = {
	windowSeconds: 60,
	unknown_tool: 30,
	unknown_method: 15,
	zod_arg: 60,
	auth_fail: 90,
} as const;

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
 *
 * Note on brand_audit_* daily caps: partner=200, enterprise=500 is intentional
 * even though partner > enterprise in the generic TIER_DAILY_LIMITS hierarchy.
 * Brand audits are multi-minute operations metered on a MONTHLY budget
 * (BRAND_AUDIT_QUOTAS: partner=200/month, enterprise=500/month). The daily
 * cap mirrors the monthly budget so a customer can't burn their entire
 * monthly quota in one day — the daily ≤ monthly invariant matters more
 * than the cross-tier daily ordering for these specific tools.
 */
export const TIER_TOOL_DAILY_LIMITS: Partial<Record<McpApiKeyTier, Record<string, number>>> = {
	partner: {
		scan_domain: 2_500_000,
		scan: 2_500_000,
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
		check_subdomailing: 500_000,
		explain_finding: 500_000,
		discover_brand_domains: 50_000,
		brand_audit_single: 200,
		brand_audit_batch_start: 200,
		brand_audit_status: 10_000,
		brand_audit_get_report: 10_000,
		list_brand_audit_watches: 100,
		register_brand_audit_watch: 100,
		delete_brand_audit_watch: 100,
	},
	developer: {
		brand_audit_single: 50,
		brand_audit_batch_start: 50,
		brand_audit_status: 5_000,
		brand_audit_get_report: 5_000,
		list_brand_audit_watches: 20,
		register_brand_audit_watch: 20,
		delete_brand_audit_watch: 20,
	},
	enterprise: {
		brand_audit_single: 500,
		brand_audit_batch_start: 500,
		brand_audit_status: 25_000,
		brand_audit_get_report: 25_000,
		list_brand_audit_watches: 100,
		register_brand_audit_watch: 100,
		delete_brand_audit_watch: 100,
	},
	agent: {
		brand_audit_single: 0,
		brand_audit_batch_start: 0,
		brand_audit_status: 0,
		brand_audit_get_report: 0,
		list_brand_audit_watches: 0,
		register_brand_audit_watch: 0,
		delete_brand_audit_watch: 0,
	},
};

export const FREE_TOOL_DAILY_LIMITS: Record<string, number> = {
	scan_domain: 25,
	scan: 25,
	batch_scan: 1,
	compare_domains: 1,
	check_spf: 25,
	check_dmarc: 25,
	check_dkim: 25,
	check_mx: 25,
	check_ns: 25,
	check_ssl: 25,
	check_dnssec: 25,
	check_mta_sts: 25,
	check_caa: 25,
	check_bimi: 25,
	check_tlsrpt: 25,
	check_lookalikes: 5,
	explain_finding: 50,
	compare_baseline: 10,
	check_shadow_domains: 5,
	check_txt_hygiene: 25,
	check_http_security: 25,
	check_dane: 25,
	check_dane_https: 25,
	check_svcb_https: 25,
	check_mx_reputation: 5,
	check_srv: 25,
	check_zone_hygiene: 25,
	check_subdomailing: 25,
	generate_fix_plan: 10,
	generate_spf_record: 25,
	generate_dmarc_record: 25,
	generate_dkim_config: 25,
	generate_mta_sts_policy: 25,
	get_benchmark: 10,
	get_provider_insights: 10,
	assess_spoofability: 10,
	check_resolver_consistency: 10,
	map_supply_chain: 5,
	analyze_drift: 5,
	validate_fix: 25,
	generate_rollout_plan: 10,
	resolve_spf_chain: 15,
	discover_subdomains: 5,
	map_compliance: 5,
	simulate_attack_paths: 3,
	check_dbl: 5,
	check_rbl: 5,
	cymru_asn: 5,
	rdap_lookup: 5,
	check_package_trust: 5,
	check_realtime_threat_feed: 5,
	check_nsec_walkability: 10,
	check_dnssec_chain: 10,
	check_fast_flux: 3,
	check_subdomain_takeover: 25,
	check_authoritative_dns_infra: 25,
	check_root_server_set: 25,
	discover_brand_domains: 1,
	brand_audit_single: 0,
	brand_audit_batch_start: 0,
	brand_audit_status: 0,
	brand_audit_get_report: 0,
	list_brand_audit_watches: 0,
	register_brand_audit_watch: 0,
	delete_brand_audit_watch: 0,
	scan_buckets_start: 5,
	scan_buckets_status: 25,
	scan_buckets_findings: 25,
};

/** Free-tier daily cap on cache-bypassing (force_refresh) requests. Far below the
 *  per-tool quota so cache-busting cannot amplify backend load (FIND-06). */
export const FORCE_REFRESH_DAILY_LIMIT = 5;

/** Tools intentionally governed by per-IP rate limits only (no per-tool free-tier quota). Audited by test/audits/tool-quota-coverage.audit.test.ts. */
export const INTENTIONALLY_UNLIMITED_TOOLS: ReadonlySet<string> = new Set<string>([]);

/**
 * Per-tier concurrent tool execution limits (per-isolate, best-effort fairness).
 * Prevents any single authenticated user from monopolizing worker capacity.
 */
export const TIER_CONCURRENT_LIMITS: Record<McpApiKeyTier, number> = {
	free: 3,
	agent: 5,
	developer: 10,
	enterprise: 25,
	partner: 50,
	owner: Infinity,
};

// ---------------------------------------------------------------------------
// Trial API key defaults
// ---------------------------------------------------------------------------

/** Default trial duration in days. */
export const TRIAL_DEFAULT_EXPIRES_DAYS = 14;

/** Default maximum tool invocations per trial key. */
export const TRIAL_DEFAULT_MAX_USES = 1000;

/** Default tier for trial keys. Maps to existing tier quotas + concurrency limits. */
export const TRIAL_DEFAULT_TIER: McpApiKeyTier = 'developer';

/** TTL (seconds) for tier-cache entries resolved from trial keys. Shorter than normal 300s to detect expiry/exhaustion sooner. */
export const TRIAL_KEY_CACHE_TTL = 60;

// ---------------------------------------------------------------------------
// Runtime-configurable limit parsers (env var overrides, no redeploy needed)
// ---------------------------------------------------------------------------

/** Default scan-level timeout (ms). 15s leaves ~20% headroom over the
 * production-observed scan_domain p50 (12.5s, last 7d analytics). The prior
 * 12s value was below p50 — roughly half of cold scans were running into the
 * timeout and returning partial results. Operator can override up to 30s via
 * `SCAN_TIMEOUT_MS` env var (`parseScanTimeout` clamps to [5000, 30000]).
 * Wall-clock; bundled Worker CPU ceiling is 30s, so this is comfortably under. */
export const SCAN_TIMEOUT_MS = 15_000;

/** Default per-check timeout (ms). */
export const PER_CHECK_TIMEOUT_MS = 8_000;

/** TTL for the best-effort cross-isolate per-IP advisory lock. */
export const IP_LOCK_TTL_MS = 500;

/** Single-retry delay when advisory lock is held by another isolate. */
export const IP_LOCK_RETRY_MS = 200;

/** Helper: parse an env var as a clamped integer, returning defaultVal on invalid/out-of-range input. */
function parseClampedInt(envValue: string | undefined, defaultVal: number, min: number, max: number): number {
	if (!envValue) return defaultVal;
	const parsed = Number(envValue);
	if (!Number.isFinite(parsed) || parsed < min) return defaultVal;
	return Math.min(parsed, max);
}

/**
 * Parse DNS_TIMEOUT_MS override, clamping to [1000, 10000].
 * Returns DNS_TIMEOUT_MS when absent or invalid.
 */
export function parseDnsTimeout(envValue?: string): number {
	return parseClampedInt(envValue, DNS_TIMEOUT_MS, 1000, 10000);
}

/**
 * Parse INFLIGHT_CLEANUP_MS override, clamping to [5000, 120000].
 * Returns INFLIGHT_CLEANUP_MS when absent or invalid.
 */
export function parseInflightCleanup(envValue?: string): number {
	return parseClampedInt(envValue, INFLIGHT_CLEANUP_MS, 5000, 120000);
}

/**
 * Parse GLOBAL_DAILY_TOOL_LIMIT override, clamping to [10000, 5000000].
 * Returns GLOBAL_DAILY_TOOL_LIMIT when absent or invalid.
 */
export function parseGlobalDailyLimit(envValue?: string): number {
	return parseClampedInt(envValue, GLOBAL_DAILY_TOOL_LIMIT, 10000, 5000000);
}

/**
 * Parse SCAN_TIMEOUT_MS override, clamping to [5000, 30000].
 * Returns SCAN_TIMEOUT_MS when absent or invalid.
 */
export function parseScanTimeout(envValue?: string): number {
	return parseClampedInt(envValue, SCAN_TIMEOUT_MS, 5000, 30000);
}

/**
 * Parse PER_CHECK_TIMEOUT_MS override, clamping to [2000, 15000].
 * Returns 8000 when absent or invalid.
 */
export function parsePerCheckTimeout(envValue?: string): number {
	return parseClampedInt(envValue, PER_CHECK_TIMEOUT_MS, 2000, 15000);
}

// ─── OAuth 2.1 (Phase 0 — shared constants) ─────────────────────────────────
export const OAUTH_CODE_TTL_SECONDS = 60; // KV minimum TTL is 60s; auth codes are short-lived
export const OAUTH_CLIENT_TTL_SECONDS = 60 * 60 * 24 * 365; // 1 year, refreshed on use
export const OAUTH_JWT_TTL_SECONDS = 60 * 60 * 24 * 90; // 90 days
export const OAUTH_JWT_CLOCK_SKEW_SECONDS = 30;
export const OAUTH_CONSENT_RATE_LIMIT = 5;
export const OAUTH_CONSENT_RATE_WINDOW_SECONDS = 60 * 15;
// HS256 security floor — RFC 7518 §3.2 requires a key at least as long as the hash
// output (256 bits = 32 bytes). Treated as a hard gate at the route layer (503 if
// shorter) AND at signing time (500 server_error from token.ts as defense in depth).
export const OAUTH_SIGNING_SECRET_MIN_BYTES = 32;
export function isValidOAuthSigningSecret(s: string | undefined): boolean {
	return typeof s === 'string' && s.length >= OAUTH_SIGNING_SECRET_MIN_BYTES;
}
export const OAUTH_SCOPES_SUPPORTED = ['mcp'] as const;
export const OAUTH_GRANT_TYPES_SUPPORTED = ['authorization_code'] as const;
export const OAUTH_RESPONSE_TYPES_SUPPORTED = ['code'] as const;
export const OAUTH_TOKEN_AUTH_METHODS_SUPPORTED = ['none'] as const;
export const OAUTH_CODE_CHALLENGE_METHODS_SUPPORTED = ['S256'] as const;
export const OAUTH_REDIRECT_URI_ALLOWLIST: RegExp[] = [
	/^https:\/\/claude\.ai(\/.*)?$/,
	/^https:\/\/[^/]+\.anthropic\.com(\/.*)?$/,
	/^http:\/\/localhost(:\d+)?(\/.*)?$/,
	/^http:\/\/127\.0\.0\.1(:\d+)?(\/.*)?$/,
];
export const OAUTH_KV_PREFIX = 'oauth:' as const;

/**
 * Parse a comma-separated IP allowlist string. Trims whitespace, filters empty entries.
 * Returns `[]` for undefined / empty / whitespace-only input, which callers should treat
 * as "no gate" (backward-compatible with installations where the env var is unset).
 */
export function parseOwnerAllowIps(value: string | undefined): string[] {
	if (!value) return [];
	const list = value
		.split(',')
		.map((s) => s.trim())
		.filter(Boolean);
	return list;
}
