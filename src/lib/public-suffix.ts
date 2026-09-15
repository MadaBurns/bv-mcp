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

/**
 * True when `domain` is itself an ICANN public suffix (eTLD) — e.g. `govt.nz`,
 * `co.nz`, `nz`, `com` — rather than a registrable name under one.
 *
 * ICANN-only (`allowPrivateDomains: false`) is deliberate and NOT the same
 * question {@link getRegistrableDomain} answers: that helper enables private
 * suffixes so tenant hosts are treated as registrable, so it ALSO returns
 * `null` for a private-suffix apex like `github.io` — a name CertSpotter
 * accepts and answers. Only a true ICANN eTLD is refused with the
 * `not_allowed_by_plan` code (#1004).
 *
 * Measured 2026-09-14: `govt.nz` / `co.nz` / `nz` / `com` → true;
 * `blackveilsecurity.com` / `github.io` / `tenant.github.io` → false.
 */
export function isPublicSuffixApex(domain: string): boolean {
	if (!domain) return false;
	return parse(domain, { allowPrivateDomains: false }).domain === null;
}
