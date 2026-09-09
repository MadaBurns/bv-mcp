// SPDX-License-Identifier: BUSL-1.1

export interface RegistrarIdentity {
	name?: string | null;
	ianaId?: string | null;
}

const CORPORATE_SUFFIX_RE = /\b(incorporated|inc|llc|ltd|limited|corp|corporation|company|co|gmbh|plc|ag|bv|nv|sas|sarl|sa|sl)\b\.?$/;
const UNKNOWN_REGISTRAR_NAMES = new Set([
	'unknown',
	'redacted',
	'redacted for privacy',
	'not found',
	'notfound',
	'registrar lookup failed',
	'registrar unavailable',
	'registrar redacted by registry',
	'registrar not found in registry',
]);

/**
 * Registrar-family detector entries.
 *
 * - `patterns` run against the normalized identifier (lowercased, punctuation
 *   stripped, corporate suffixes removed) produced by `normalizeRegistrarIdentity`.
 *   Use anchored regexes to avoid substring false-positives.
 * - `rawPatterns` run against the raw lowercased input (no normalization).
 *   Use sparingly — only for cases where normalization deletes the signal,
 *   e.g. a registrar's bare website host whose URL strip removes the signal.
 */
const KNOWN_REGISTRAR_FAMILIES: Array<{ family: string; patterns: RegExp[]; rawPatterns?: RegExp[] }> = [
	{ family: 'markmonitor', patterns: [/^markmonitor(?:\b|$)/] },
	{ family: 'com laude', patterns: [/(?:^|\b)com\s+laude(?:\b|$)/, /^nom\s*iq(?:\b|$)/] },
	{ family: 'safenames', patterns: [/^safenames(?:\b|$)/] },
	{
		// This corporate-domains registrar operates many regional subsidiaries
		// (US, Canada, UK, a Malaysian digital-brand-services arm, an Australian
		// Pty Ltd, etc.) all sharing infrastructure. Collapse every regional
		// brand string into a single family so the off-primary-registrar
		// inference does not flag its ccTLD registrations as shadowIt.
		// Regression source: 2026-05 registrar-family fixture verification of
		// regional-alpha.example.com / regional-beta.example.com / regional-gamma.example.com.
		// The WHOIS name patterns below are neutral technical data (like the
		// MarkMonitor / GoDaddy entries beside them) and must stay as observed.
		family: 'corporate domains registrar',
		patterns: [
			/^csc\s+corporate\s+domains(?:\b|$)/,
			/^csc\s+corp\s+domains(?:\b|$)/,
			/^csc\s+digital\s+brand\s+services?(?:\b|$)/,
			/^csc\s+global(?:\b|$)/,
			// Matches the registrar's legal-entity name with any trailing regional qualifier
			// (e.g. "Aust Pty"); corporate suffixes like Ltd/LLC are already
			// stripped by normalizeRegistrarIdentity before this regex runs.
			/^corporation\s+service\s+company(?:\b|$)/,
			/^corporation\s+service$/,
		],
		// The registrar's website host appears verbatim in some WHOIS responses; the URL strip
		// in normalizeRegistrarIdentity would delete it, so match against raw.
		rawPatterns: [/(?:^|\b)cscglobal\.com(?:\b|$)/],
	},
	{ family: 'cloudflare', patterns: [/^cloudflare(?:\b|$)/] },
	{ family: 'tucows', patterns: [/^tucows(?:\b|$)/] },
	{ family: 'godaddy', patterns: [/^godaddy(?:\b|$)/] },
	{ family: 'namecheap', patterns: [/^namecheap(?:\b|$)/] },
	{ family: 'network solutions', patterns: [/^network solutions(?:\b|$)/, /^networksolutions(?:\b|$)/] },
	{ family: 'gandi', patterns: [/^gandi(?:\b|$)/] },
];

export function normalizeRegistrarIdentity(raw: string | null | undefined): string | null {
	if (!raw) return null;
	let normalized = raw
		.toLowerCase()
		.trim()
		.replace(/^name\s*:\s*/, '')
		.replace(/https?:\/\/\S+/g, ' ')
		.replace(/&/g, ' and ')
		.replace(/[.,'"‘’“”()]/g, ' ')
		.replace(/\s+/g, ' ')
		.trim();

	while (CORPORATE_SUFFIX_RE.test(normalized)) {
		normalized = normalized.replace(CORPORATE_SUFFIX_RE, '').replace(/\s+/g, ' ').trim();
	}

	if (UNKNOWN_REGISTRAR_NAMES.has(normalized)) return null;
	return normalized || null;
}

function normalizeIanaId(value: string | null | undefined): string | null {
	if (!value) return null;
	const normalized = value.trim();
	return normalized.length > 0 ? normalized : null;
}

function knownFamily(normalizedName: string | null, rawLowerName: string | null): string | null {
	if (!normalizedName && !rawLowerName) return null;
	for (const { family, patterns, rawPatterns } of KNOWN_REGISTRAR_FAMILIES) {
		if (normalizedName && patterns.some((pattern) => pattern.test(normalizedName))) return family;
		if (rawLowerName && rawPatterns?.some((pattern) => pattern.test(rawLowerName))) return family;
	}
	return null;
}

function rawLower(raw: string | null | undefined): string | null {
	if (!raw) return null;
	const trimmed = raw.toLowerCase().trim();
	return trimmed.length > 0 ? trimmed : null;
}

export function sameRegistrarFamily(left: RegistrarIdentity, right: RegistrarIdentity): boolean {
	const leftIanaId = normalizeIanaId(left.ianaId);
	const rightIanaId = normalizeIanaId(right.ianaId);
	if (leftIanaId && rightIanaId && leftIanaId === rightIanaId) return true;

	const leftName = normalizeRegistrarIdentity(left.name);
	const rightName = normalizeRegistrarIdentity(right.name);
	const leftRaw = rawLower(left.name);
	const rightRaw = rawLower(right.name);

	const leftFamily = knownFamily(leftName, leftRaw);
	const rightFamily = knownFamily(rightName, rightRaw);
	if (leftFamily && leftFamily === rightFamily) return true;

	if (!leftName || !rightName) return false;
	if (leftName === rightName) return true;

	return false;
}

/**
 * Classify a raw registrar name string into a canonical family identifier.
 *
 * Wraps the private `knownFamily()` detector with the same normalization
 * (`normalizeRegistrarIdentity` + raw-lowercase) used by `sameRegistrarFamily`.
 * Returns `null` when the input is empty, redacted, or doesn't match any
 * `KNOWN_REGISTRAR_FAMILIES` entry.
 *
 * Used by the registrar-portfolio aggregator to bucket discovered apexes by
 * registrar family for the registrar-complement view.
 */
export function classifyRegistrarFamily(name: string | null | undefined): string | null {
	const normalized = normalizeRegistrarIdentity(name);
	const raw = rawLower(name);
	return knownFamily(normalized, raw);
}
