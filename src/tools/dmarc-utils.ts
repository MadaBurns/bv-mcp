// SPDX-License-Identifier: BUSL-1.1

/** Parse DMARC tag-value pairs from a DMARC record string. */
export function parseDmarcTags(record: string): Map<string, string> {
	const tags = new Map<string, string>();
	const parts = record.split(';');
	for (const part of parts) {
		const trimmed = part.trim();
		const eqIndex = trimmed.indexOf('=');
		if (eqIndex > 0) {
			const key = trimmed.substring(0, eqIndex).trim().toLowerCase();
			const value = trimmed.substring(eqIndex + 1).trim().toLowerCase();
			tags.set(key, value);
		}
	}
	return tags;
}

/** Extract the domain part from a mailto: URI, stripping optional size suffix. */
export function extractDomainFromMailto(uri: string): string | null {
	const trimmed = uri.trim().toLowerCase();
	if (!trimmed.startsWith('mailto:')) return null;
	let email = trimmed.substring(7).trim();
	email = email.replace(/![0-9]+[kmgt]?$/i, '');
	const atIndex = email.lastIndexOf('@');
	if (atIndex < 0) return null;
	return email.substring(atIndex + 1);
}

/**
 * Validate DMARC URI format (must be mailto: scheme).
 * Strips the optional RFC 7489 §6.2 size limit suffix before checking.
 */
export function isValidDmarcUri(uri: string): boolean {
	const trimmed = uri.trim().toLowerCase();
	if (!trimmed.startsWith('mailto:')) {
		return false;
	}
	let email = trimmed.substring(7).trim();
	email = email.replace(/![0-9]+[kmgt]?$/i, '');
	return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

/** Detect known third-party DMARC aggregator services. */
export function detectThirdPartyAggregators(uris: string[]): string[] {
	const knownAggregators = [
		'dmarcian.com',
		'agari.com',
		'valimail.com',
		'returnpath.com',
		'postmarkapp.com',
		'dmarcanalyzer.com',
		'mimecast.com',
		'proofpoint.com',
		'250ok.com',
		'easydmarc.com',
		'sendmarc.com',
		'ondmarc.com',
		'dmarcdigest.com',
		'dmarcly.com',
		'powerdmarc.com',
		'redsift.com',
	];

	const detected: string[] = [];
	for (const uri of uris) {
		const lower = uri.toLowerCase();
		for (const aggregator of knownAggregators) {
			if (lower.includes(aggregator) && !detected.includes(aggregator)) {
				detected.push(aggregator);
			}
		}
	}
	return detected;
}
