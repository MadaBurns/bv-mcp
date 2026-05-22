/**
 * Provider-sprawl helper for brand-audit classifier.
 *
 * Normalizes raw nameserver hostnames into logical DNS provider identities so
 * the classifier can distinguish true single-provider deployments (e.g. AWS
 * Route 53 fragmenting across `awsdns-*.com/.net/.co.uk`) from genuine
 * multi-provider sprawl (e.g. UltraDNS + an in-house authoritative cluster).
 *
 * Pure string ops — safe under the Cloudflare Workers runtime.
 */

interface ProviderRule {
	readonly test: RegExp;
	readonly name: string;
}

// Order matters: first match wins. Most-specific patterns precede generic ones.
const PROVIDER_RULES: readonly ProviderRule[] = [
	{ test: /\bawsdns-\d+\.(?:com|net|org|co\.uk)$/i, name: 'AWS Route 53' },
	{ test: /\bultradns\.(?:net|com|org|biz)$/i, name: 'UltraDNS (Vercara)' },
	{ test: /\.ns\.cloudflare\.com$/i, name: 'Cloudflare' },
	{ test: /\bcloudflare\.com$/i, name: 'Cloudflare' },
	{ test: /\bnsone\.net$/i, name: 'NS1' },
	{ test: /\bakam\.net$/i, name: 'Akamai' },
	{ test: /\bakamaitech\.net$/i, name: 'Akamai' },
	{ test: /\bakamaiedge\.net$/i, name: 'Akamai' },
	{ test: /\bmarkmonitor\.com$/i, name: 'MarkMonitor' },
	{ test: /\bgoogle\.com$/i, name: 'Google (in-house)' },
	{ test: /\bapple\.com$/i, name: 'Apple (in-house)' },
];

/**
 * Normalize a single nameserver hostname into a logical provider identity.
 * Falls back to the apex-2 label (e.g. `weirdhost.example`) for unknown
 * providers and returns `'unknown'` for empty/degenerate input.
 */
export function normalizeProvider(ns: string): string {
	const host = (ns ?? '').trim().replace(/\.$/, '').toLowerCase();
	if (!host) return 'unknown';
	for (const rule of PROVIDER_RULES) {
		if (rule.test.test(host)) return rule.name;
	}
	const labels = host.split('.').filter(Boolean);
	if (labels.length < 2) return 'unknown';
	return labels.slice(-2).join('.');
}

/**
 * Group a list of nameserver hostnames by their logical provider, returning a
 * `{ providerName: count }` map. Duplicates within the input are deduplicated
 * before counting.
 */
export function groupByProvider(nameservers: readonly string[]): Record<string, number> {
	const seen = new Set<string>();
	const counts: Record<string, number> = {};
	for (const ns of nameservers) {
		const key = (ns ?? '').trim().replace(/\.$/, '').toLowerCase();
		if (!key || seen.has(key)) continue;
		seen.add(key);
		const provider = normalizeProvider(ns);
		counts[provider] = (counts[provider] ?? 0) + 1;
	}
	return counts;
}

/**
 * Return `true` when the nameserver list resolves to two or more distinct
 * logical providers (true sprawl), `false` when a single provider covers the
 * whole list or input is empty/single-NS.
 */
export function isMultiProvider(nameservers: readonly string[]): boolean {
	if (!nameservers || nameservers.length < 2) return false;
	return Object.keys(groupByProvider(nameservers)).length > 1;
}
