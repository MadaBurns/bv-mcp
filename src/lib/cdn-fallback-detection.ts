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
 * This module restores attribution by combining two corroborating signals
 * that the scanner CAN observe authentically:
 *
 *   1. NS records — all nameservers under `*.ns.cloudflare.com`
 *   2. A records — at least one IP in Cloudflare's published edge ranges
 *
 * BOTH must match to attribute. The combined check rules out the two
 * common false positives: DNS-only customers (NS on CF, origin elsewhere)
 * and transit-only paths (origin on CF IPs but NS elsewhere — eg. a
 * partial migration). When matched, the attribution is flagged
 * `confidence: 'heuristic'` so consumers can distinguish it from
 * header-based hits (`confidence` absent → high-confidence vendor signal).
 *
 * The published IPv4 ranges are snapshotted from cloudflare.com/ips/.
 * If Cloudflare publishes a new range, the `CLOUDFLARE_IPV4_RANGES`
 * snapshot test in `test/cdn-fallback-detection.spec.ts` will force a
 * deliberate update.
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

const CF_NS_PATTERN = /\.ns\.cloudflare\.com\.?$/i;

export interface CloudflareHeuristicResult {
	provider: 'Cloudflare';
	confidence: 'heuristic';
}

/**
 * Returns a Cloudflare attribution iff BOTH signals match:
 *   - every NS host is under `*.ns.cloudflare.com`
 *   - at least one A record is in a published Cloudflare edge range
 *
 * Returns null otherwise. Empty NS or empty A list always returns null.
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
