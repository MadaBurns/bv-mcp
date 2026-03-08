import { queryTxtRecords } from '../lib/dns';
import { createFinding } from '../lib/scoring';
import type { Finding } from '../lib/scoring';

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

/**
 * Check cross-domain RUA authorization per RFC 7489 §7.1.
 * When rua= points to a third-party domain, verify authorization TXT records.
 */
export async function checkRuaAuthorization(domain: string, ruaUris: string[]): Promise<Finding[]> {
	const findings: Finding[] = [];
	const checkedDomains = new Set<string>();

	for (const uri of ruaUris) {
		const targetDomain = extractDomainFromMailto(uri);
		if (!targetDomain || targetDomain === domain || checkedDomains.has(targetDomain)) continue;
		checkedDomains.add(targetDomain);

		try {
			const authRecords = await queryTxtRecords(`${domain}._report._dmarc.${targetDomain}`);
			const hasAuth = authRecords.some((record) => record.toLowerCase().startsWith('v=dmarc1'));
			if (!hasAuth) {
				findings.push(
					createFinding(
						'dmarc',
						'Third-party aggregate reporting not authorized',
						'medium',
						`Aggregate reports sent to ${targetDomain} will be silently discarded. The authorization record ${domain}._report._dmarc.${targetDomain} must contain a TXT record with "v=DMARC1" (RFC 7489 §7.1).`,
					),
				);
			}
		} catch {
			// DNS query failed — don't produce a finding for transient errors.
		}
	}

	return findings;
}