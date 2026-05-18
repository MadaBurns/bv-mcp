// SPDX-License-Identifier: BUSL-1.1

import { parse } from 'tldts';

function parseDomain(domain: string) {
	return parse(domain, { allowPrivateDomains: true });
}

/**
 * Return the PSL-aware registrable domain for a hostname.
 *
 * Private suffixes are enabled so tenant hosts such as `tenant.github.io` and
 * `service.appspot.com` are treated as registrable domains.
 */
export function getRegistrableDomain(domain: string): string | null {
	if (!domain) return null;
	return parseDomain(domain).domain ?? null;
}

/**
 * Determine the effective TLD for a domain using the Public Suffix List.
 *
 * Returns `null` if the input is empty, single-label, or is itself a public
 * suffix (i.e., there is no registrable label to the left).
 */
export function getEffectiveTld(domain: string): string | null {
	if (!domain) return null;

	const parsed = parseDomain(domain);
	if (!parsed.domain) return null;
	return parsed.publicSuffix ?? null;
}

/**
 * Extract the registrable brand name from a domain.
 *
 * The brand name is the label immediately to the left of the effective TLD.
 * Subdomains further to the left are stripped.
 *
 * @example
 * extractBrandName('tewhatuora.govt.nz') // => 'tewhatuora'
 * extractBrandName('sub.example.co.nz')  // => 'example'
 * extractBrandName('blackveil.nz')       // => 'blackveil'
 * extractBrandName('co.nz')              // => null (bare TLD suffix)
 * extractBrandName('com')                // => null (single label)
 */
export function extractBrandName(domain: string): string | null {
	if (!domain) return null;
	return parseDomain(domain).domainWithoutSuffix ?? null;
}
