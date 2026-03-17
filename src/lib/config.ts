// SPDX-License-Identifier: BUSL-1.1

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
};
