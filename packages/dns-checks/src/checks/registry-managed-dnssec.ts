// SPDX-License-Identifier: BUSL-1.1

/**
 * Registry-managed DNSSEC detection.
 *
 * Some ccTLD registries auto-sign all child zones with DNSSEC. In that case the
 * chain of trust was established by the registry, not the domain owner — the zone
 * is still cryptographically protected, but the owner did not independently deploy
 * DNSSEC. `checkDNSSEC` flags this (a moderate deduction) when the zone validates.
 *
 * Two detection paths: a deterministic TLD seed list (no DNS), and an NS-overlap
 * fallback (domain NS == parent-zone NS ⇒ registry operates the zone).
 *
 * Copyright (c) 2023-2026 BlackVeil Security Ltd. Licensed under BSL 1.1.
 */

import type { DNSQueryFunction } from '../types';

/**
 * TLD zones known to automatically sign all child domains with DNSSEC.
 * Format: lowercase, leading dot, most-specific first within each group.
 */
export const REGISTRY_MANAGED_DNSSEC_TLDS = [
	// Tanzania — TZNIC signs all .tz zones
	'.go.tz', '.ac.tz', '.co.tz', '.ne.tz', '.or.tz', '.tz',
	// Sri Lanka — LKNIC signs all .lk zones
	'.gov.lk', '.ac.lk', '.edu.lk', '.net.lk', '.org.lk', '.lk',
	// Cambodia — MPTC signs .kh zones
	'.gov.kh', '.edu.kh', '.kh',
	// Bangladesh — BTCL signs .bd zones
	'.gov.bd', '.edu.bd', '.ac.bd', '.bd',
] as const;

/** True if the domain ends with a known registry-managed-DNSSEC TLD (longest match wins by listing order). */
export function isInRegistryManagedTLD(domain: string): boolean {
	const lower = domain.toLowerCase();
	return REGISTRY_MANAGED_DNSSEC_TLDS.some((tld) => lower.endsWith(tld));
}

/** Parent zone = domain with its left-most label removed; null if already a TLD. */
function getParentZone(domain: string): string | null {
	const labels = domain.toLowerCase().replace(/\.$/, '').split('.').filter(Boolean);
	return labels.length >= 3 ? labels.slice(1).join('.') : null;
}

/**
 * Determine whether the validated DNSSEC chain is registry-managed.
 * Returns false (no deduction) when indeterminate — fail-safe, never over-penalize.
 */
export async function isRegistryManagedDnssec(
	domain: string,
	queryDNS: DNSQueryFunction,
	timeout: number,
): Promise<boolean> {
	// Fast path: deterministic TLD seed list (no DNS).
	if (isInRegistryManagedTLD(domain)) return true;

	// Fallback: NS overlap — if the domain's NS set overlaps the parent zone's NS,
	// the registry operates the zone (and thus signs it).
	const parentZone = getParentZone(domain);
	if (!parentZone) return false;

	try {
		const [domainNS, parentNS] = await Promise.all([
			queryDNS(domain, 'NS', { timeout }),
			queryDNS(parentZone, 'NS', { timeout }),
		]);
		if (domainNS.length === 0 || parentNS.length === 0) return false;
		const normalize = (ns: string) => ns.toLowerCase().replace(/\.$/, '');
		const domainNSSet = new Set(domainNS.map(normalize));
		return parentNS.some((ns) => domainNSSet.has(normalize(ns)));
	} catch {
		return false; // fail-safe: indeterminate → no deduction
	}
}
