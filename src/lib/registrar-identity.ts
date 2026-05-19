// SPDX-License-Identifier: BUSL-1.1

export interface RegistrarIdentity {
	name?: string | null;
	ianaId?: string | null;
}

const CORPORATE_SUFFIX_RE = /\b(incorporated|inc|llc|ltd|limited|corp|corporation|company|co|gmbh|plc|ag|bv|nv|sas|sarl|sa|sl)\b\.?$/;
const UNKNOWN_REGISTRAR_NAMES = new Set(['unknown', 'redacted', 'redacted for privacy', 'not found', 'notfound']);

const KNOWN_REGISTRAR_FAMILIES: Array<{ family: string; patterns: RegExp[] }> = [
	{ family: 'markmonitor', patterns: [/^markmonitor(?:\b|$)/] },
	{ family: 'com laude', patterns: [/(?:^|\b)com\s+laude(?:\b|$)/, /^nom\s*iq(?:\b|$)/] },
	{ family: 'safenames', patterns: [/^safenames(?:\b|$)/] },
	{ family: 'csc corporate domains', patterns: [/^csc corporate domains$/, /^corporation service company$/] },
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

function knownFamily(normalizedName: string | null): string | null {
	if (!normalizedName) return null;
	for (const { family, patterns } of KNOWN_REGISTRAR_FAMILIES) {
		if (patterns.some((pattern) => pattern.test(normalizedName))) return family;
	}
	return null;
}

export function sameRegistrarFamily(left: RegistrarIdentity, right: RegistrarIdentity): boolean {
	const leftIanaId = normalizeIanaId(left.ianaId);
	const rightIanaId = normalizeIanaId(right.ianaId);
	if (leftIanaId && rightIanaId) return leftIanaId === rightIanaId;

	const leftName = normalizeRegistrarIdentity(left.name);
	const rightName = normalizeRegistrarIdentity(right.name);
	if (!leftName || !rightName) return false;
	if (leftName === rightName) return true;

	const leftFamily = knownFamily(leftName);
	const rightFamily = knownFamily(rightName);
	return !!leftFamily && leftFamily === rightFamily;
}
