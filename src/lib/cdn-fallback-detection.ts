// SPDX-License-Identifier: BUSL-1.1

/**
 * Heuristic Cloudflare CDN attribution fallback.
 *
 * Header-based CDN detection (see check-http-security.ts) cannot identify
 * Cloudflare from inside a Cloudflare Worker: CF's outbound `fetch()` layer
 * rewrites `server: cloudflare` on every response and injects `cf-ray` for
 * tracing, regardless of the origin. v3.3.11 removed CF detection entirely
 * to fix the resulting 100% false-positive rate.
 *
 * This module restores attribution by combining three independent signals
 * that the scanner CAN observe authentically; ANY 2 of 3 must match:
 *
 *   A. NS records — all nameservers under `*.ns.cloudflare.com`
 *   B. A records — at least one IP in Cloudflare's published edge ranges
 *   C. TLS cert issuer — issuer string matches Cloudflare's CA family
 *      (eg. `Cloudflare Inc ECC CA-3`, `Cloudflare Origin SSL ECC Issuer ECC`)
 *
 * The original v3.3.15 gate (A+B only) is preserved as a deprecated wrapper
 * (`detectCloudflareViaNsAndIp`). The new v3.3.17 entry point
 * (`detectCloudflareFallback`) accepts an optional `certIssuer` and applies
 * the 2-of-3 rule.
 *
 * Why 2-of-3 (not OR)? A single signal in isolation is ambiguous:
 *   - Signal A alone → DNS-only customer; origin could be anywhere.
 *   - Signal B alone → transit/proxy path; not necessarily a CF customer.
 *   - Signal C alone → CA was used for a cert; says nothing about delivery.
 * Requiring two corroborating origin-set signals keeps false-positive risk
 * low while catching real CF customers who use external DNS (signals B+C).
 *
 * When matched, the attribution is flagged `confidence: 'heuristic'` so
 * consumers can distinguish it from header-based hits (`confidence` absent →
 * high-confidence vendor signal).
 *
 * The published IPv4 ranges are snapshotted from cloudflare.com/ips/. If
 * Cloudflare publishes a new range, the `CLOUDFLARE_IPV4_RANGES` snapshot
 * test in `test/cdn-fallback-detection.spec.ts` will force a deliberate
 * update.
 */

/**
 * Cloudflare's published IPv4 edge ranges (snapshot from `cloudflare.com/ips/`).
 * Sorted to match the order in the published list to make diffs reviewable.
 */
export const CLOUDFLARE_IPV4_RANGES: readonly string[] = [
	'103.21.244.0/22',
	'103.22.200.0/22',
	'103.31.4.0/22',
	'104.16.0.0/13',
	'104.24.0.0/14',
	'108.162.192.0/18',
	'131.0.72.0/22',
	'141.101.64.0/18',
	'162.158.0.0/15',
	'172.64.0.0/13',
	'173.245.48.0/20',
	'188.114.96.0/20',
	'190.93.240.0/20',
	'197.234.240.0/22',
	'198.41.128.0/17',
];

/** Convert a dotted-quad IPv4 string to its uint32 value, or null on malformed input. */
function ipToUint32(ip: string): number | null {
	const parts = ip.split('.');
	if (parts.length !== 4) return null;
	const nums: number[] = [];
	for (const p of parts) {
		if (p.length === 0 || p.length > 3) return null;
		if (!/^\d+$/.test(p)) return null;
		const n = Number(p);
		if (!Number.isInteger(n) || n < 0 || n > 255) return null;
		nums.push(n);
	}
	return ((nums[0] << 24) | (nums[1] << 16) | (nums[2] << 8) | nums[3]) >>> 0;
}

/** Whether a given IPv4 string falls inside a CIDR block. False on malformed input. */
function cidrContains(cidr: string, ip: string): boolean {
	const [base, bits] = cidr.split('/');
	const baseInt = ipToUint32(base);
	const ipInt = ipToUint32(ip);
	if (baseInt === null || ipInt === null) return false;
	const bitsNum = Number(bits);
	if (!Number.isInteger(bitsNum) || bitsNum < 0 || bitsNum > 32) return false;
	const mask = bitsNum === 0 ? 0 : (~0 << (32 - bitsNum)) >>> 0;
	return (baseInt & mask) === (ipInt & mask);
}

/** Whether an IPv4 string falls in any published Cloudflare edge range. */
export function isIpInCloudflareRange(ip: string): boolean {
	for (const cidr of CLOUDFLARE_IPV4_RANGES) {
		if (cidrContains(cidr, ip)) return true;
	}
	return false;
}

/**
 * Cloudflare's published IPv6 edge ranges (snapshot from `cloudflare.com/ips-v6`), in
 * published order. Kept beside the IPv4 list so there is ONE home for Cloudflare's ranges.
 */
export const CLOUDFLARE_IPV6_RANGES: readonly string[] = [
	'2400:cb00::/32',
	'2606:4700::/32',
	'2803:f800::/32',
	'2405:b500::/32',
	'2405:8100::/32',
	'2a06:98c0::/29',
	'2c0f:f248::/32',
];

/** Expand an IPv6 literal to its eight 16-bit groups, or null on malformed input
 * (zone ids and embedded-IPv4 forms are rejected — neither can be a Cloudflare edge literal). */
function ipv6ToGroups(ip: string): number[] | null {
	if (!ip.includes(':') || ip.includes('%') || ip.includes('.')) return null;
	const halves = ip.toLowerCase().split('::');
	if (halves.length > 2) return null;
	const parseHalf = (half: string): number[] | null => {
		if (half === '') return [];
		const groups: number[] = [];
		for (const token of half.split(':')) {
			if (!/^[0-9a-f]{1,4}$/.test(token)) return null;
			groups.push(Number.parseInt(token, 16));
		}
		return groups;
	};
	const left = parseHalf(halves[0]);
	const right = parseHalf(halves[1] ?? '');
	if (!left || !right) return null;
	if (halves.length === 1) return left.length === 8 ? left : null;
	if (left.length + right.length >= 8) return null;
	return [...left, ...Array<number>(8 - left.length - right.length).fill(0), ...right];
}

function ipv6CidrContains(cidr: string, groups: number[]): boolean {
	const [base, bits] = cidr.split('/');
	const baseGroups = ipv6ToGroups(base);
	const bitsNum = Number(bits);
	if (!baseGroups || !Number.isInteger(bitsNum) || bitsNum < 0 || bitsNum > 128) return false;
	for (let index = 0, remaining = bitsNum; remaining > 0; index += 1, remaining -= 16) {
		const mask = remaining >= 16 ? 0xffff : (0xffff << (16 - remaining)) & 0xffff;
		if ((baseGroups[index] & mask) !== (groups[index] & mask)) return false;
	}
	return true;
}

/**
 * Whether an IPv4 OR IPv6 literal falls in any published Cloudflare range. Used where the
 * question is "is this address on Cloudflare's network" rather than CDN attribution — e.g. the
 * authoritative-DNS probe, whose Workers TCP sockets to Cloudflare IP ranges are blocked by
 * platform policy (#1131). `isIpInCloudflareRange` stays IPv4-only for the attribution heuristic.
 */
export function isIpInCloudflareNetwork(ip: string): boolean {
	if (isIpInCloudflareRange(ip)) return true;
	const groups = ipv6ToGroups(ip);
	if (!groups) return false;
	return CLOUDFLARE_IPV6_RANGES.some((cidr) => ipv6CidrContains(cidr, groups));
}

const CF_NS_PATTERN = /\.ns\.cloudflare\.com\.?$/i;

/**
 * Pattern for TLS cert issuer strings issued by Cloudflare's CA family.
 * Covers the common forms observed in the wild:
 *   - `C=US, O=Cloudflare, Inc., CN=Cloudflare Inc ECC CA-3`
 *   - `CN=Cloudflare Origin SSL ECC Issuer ECC, O=Cloudflare, Inc., ...`
 *   - `O=Cloudflare, Inc., ...` (some certs have only the O attribute)
 * Case-insensitive. Any occurrence of "Cloudflare" anywhere in the issuer
 * string counts as a match — there is no Cloudflare-issued cert whose
 * issuer string omits the word.
 */
const CF_CERT_ISSUER_PATTERN = /cloudflare/i;

export interface CloudflareHeuristicResult {
	provider: 'Cloudflare';
	confidence: 'heuristic';
}

/**
 * 2-of-3-signal Cloudflare attribution heuristic.
 *
 * Signals:
 *   A. `nsHosts` — every NS host under `*.ns.cloudflare.com`
 *   B. `aRecords` — at least one IP in a published Cloudflare edge range
 *   C. `certIssuer` — issuer string matches `/cloudflare/i`
 *
 * Returns an attribution iff at least TWO of the three signals are present.
 * Returns null otherwise. Each signal is treated as either present (1) or
 * absent (0); empty inputs count as absent (do not short-circuit).
 *
 * Backward-compat: when `certIssuer` is null/undefined, signal C is absent
 * and the function reduces to the original v3.3.15 NS+IP requirement.
 */
export function detectCloudflareFallback(opts: {
	nsHosts: string[];
	aRecords: string[];
	certIssuer?: string | null;
}): CloudflareHeuristicResult | null {
	const { nsHosts, aRecords, certIssuer } = opts;

	// Signal A: every NS on CF (empty list ⇒ absent, NOT vacuously true).
	const signalA = nsHosts.length > 0 && nsHosts.every((host) => CF_NS_PATTERN.test(host));

	// Signal B: at least one A in published CF range.
	const signalB = aRecords.length > 0 && aRecords.some((ip) => isIpInCloudflareRange(ip));

	// Signal C: cert issuer mentions Cloudflare.
	const signalC = typeof certIssuer === 'string' && CF_CERT_ISSUER_PATTERN.test(certIssuer);

	const signalCount = (signalA ? 1 : 0) + (signalB ? 1 : 0) + (signalC ? 1 : 0);
	if (signalCount < 2) return null;

	return { provider: 'Cloudflare', confidence: 'heuristic' };
}

/**
 * Deprecated v3.3.15 entry point — strict NS+IP-only attribution.
 *
 * Kept as a thin wrapper for downstream consumers that bound to the
 * original contract. New code should call {@link detectCloudflareFallback}
 * directly and pass `certIssuer` when available.
 *
 * @deprecated Use {@link detectCloudflareFallback} (2-of-3 signals incl.
 *             optional `certIssuer`). This wrapper preserves the strict
 *             NS+IP-only gate: BOTH NS-all-on-CF AND at-least-one-A-in-CF
 *             must hold; cert issuer is ignored.
 */
export function detectCloudflareViaNsAndIp(opts: {
	nsHosts: string[];
	aRecords: string[];
}): CloudflareHeuristicResult | null {
	const { nsHosts, aRecords } = opts;
	if (nsHosts.length === 0 || aRecords.length === 0) return null;

	const allNsOnCloudflare = nsHosts.every((host) => CF_NS_PATTERN.test(host));
	if (!allNsOnCloudflare) return null;

	const anyARecordInRange = aRecords.some((ip) => isIpInCloudflareRange(ip));
	if (!anyARecordInRange) return null;

	return { provider: 'Cloudflare', confidence: 'heuristic' };
}
