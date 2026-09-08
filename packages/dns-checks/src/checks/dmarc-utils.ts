// SPDX-License-Identifier: BUSL-1.1

/**
 * DMARC utility functions.
 * Pure functions for parsing DMARC tags, validating URIs,
 * detecting aggregators, and checking RUA authorization.
 *
 * Copyright (c) 2023-2026 BLACKVEIL Security
 * Licensed under BUSL-1.1
 */

import type { DNSQueryFunction, Finding } from '../types';
import { createFinding } from '../check-utils';

/** Parse DMARC tag-value pairs from a DMARC record string. */
export function parseDmarcTags(record: string): Map<string, string> {
	const tags = new Map<string, string>();
	const parts = record.split(';');
	for (const part of parts) {
		const trimmed = part.trim();
		const eqIndex = trimmed.indexOf('=');
		if (eqIndex > 0) {
			const key = trimmed.substring(0, eqIndex).trim().toLowerCase();
			const value = trimmed
				.substring(eqIndex + 1)
				.trim()
				.toLowerCase();
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

/** Discover the Organizational Domain with the bounded RFC 9989 §4.10 DNS tree walk. */
export async function discoverDmarcOrganizationalDomain(domain: string, queryDNS: DNSQueryFunction, timeout?: number): Promise<string> {
	const original = domain.toLowerCase().replace(/\.$/, '');
	const labels = original.split('.');
	let current = labels;
	let selected = original;
	while (current.length > 0) {
		const name = current.join('.');
		const records = (await queryDNS(`_dmarc.${name}`, 'TXT', { timeout })).filter((record) => /^v=DMARC1(?:\s*;|\s*$)/i.test(record));
		if (records.length === 1) {
			const tags = parseDmarcTags(records[0]);
			if (['none', 'quarantine', 'reject'].includes(tags.get('p') ?? '')) {
				if (tags.get('psd') === 'n') return name;
				if (tags.get('psd') === 'y') {
					return name === original ? original : labels.slice(-(current.length + 1)).join('.');
				}
				selected = name;
			}
		}
		current = current.length >= 8 ? current.slice(-7) : current.slice(1);
	}
	return selected;
}

/**
 * Check cross-domain RUA authorization per RFC 9990 §4 ("Verifying External
 * Destinations"), which obsoleted RFC 7489 §7.1 in May 2026.
 * When rua= points to a third-party domain, verify authorization TXT records.
 *
 * The finding this emits is rendered verbatim on the PUBLIC security-report page and
 * names a real third party, so its wording is evidence-bounded on purpose: the DNS
 * fact (the authorization record is absent) is deterministic and ours to assert, but
 * whether reports are actually dropped depends on each receiver's enforcement of
 * external destination verification — which we cannot observe. Say "may", not "will".
 */
export async function checkRuaAuthorization(
	domain: string,
	ruaUris: string[],
	queryDNS: DNSQueryFunction,
	timeout?: number,
): Promise<Finding[]> {
	const findings: Finding[] = [];
	const checkedDomains = new Set<string>();
	const policyDomain = domain.toLowerCase().replace(/\.$/, '');
	// Per-check memo shares ancestor lookups across destinations and both walks.
	const queries = new Map<string, Promise<string[]>>();
	const memoDNS: DNSQueryFunction = (name, type, options) => {
		const key = `${name}:${type}`;
		let pending = queries.get(key);
		if (!pending) {
			pending = queryDNS(name, type, options);
			queries.set(key, pending);
		}
		return pending;
	};
	let policyOrg: Promise<string> | undefined;

	for (const uri of ruaUris) {
		const targetDomain = extractDomainFromMailto(uri);
		if (!targetDomain || targetDomain === policyDomain || checkedDomains.has(targetDomain)) continue;
		checkedDomains.add(targetDomain);

		try {
			policyOrg ??= discoverDmarcOrganizationalDomain(policyDomain, memoDNS, timeout);
			const [sourceOrg, targetOrg] = await Promise.all([policyOrg, discoverDmarcOrganizationalDomain(targetDomain, memoDNS, timeout)]);
			if (sourceOrg === targetOrg) continue;
			const authRecords = await memoDNS(`${policyDomain}._report._dmarc.${targetDomain}`, 'TXT', { timeout });
			const hasAuth = authRecords.some((record) => /^v=DMARC1(?:\s*;|\s*$)/i.test(record));
			if (!hasAuth) {
				findings.push(
					createFinding(
						'dmarc',
						'Third-party aggregate reporting not authorized',
						'medium',
						`Aggregate reports sent to ${targetDomain} may be discarded by receivers that enforce external destination verification. The authorization record ${policyDomain}._report._dmarc.${targetDomain} must contain a TXT record with "v=DMARC1" (RFC 9990 §4, which obsoletes RFC 7489 §7.1).`,
					),
				);
			}
		} catch {
			findings.push(
				createFinding(
					'dmarc',
					'Aggregate reporting authorization not assessed',
					'info',
					`Could not establish external reporting authorization for ${targetDomain} because a DNS lookup failed. Authorization is unknown; retry the check.`,
					{
						component: 'rua_authorization',
						assessment: 'not_assessed',
						inconclusive: true,
						errorKind: 'dns_error',
						confidence: 'heuristic',
					},
				),
			);
		}
	}

	return findings;
}
