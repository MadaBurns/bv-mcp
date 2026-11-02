// SPDX-License-Identifier: BUSL-1.1

/** Ownership attribution: host normalisation and NS-host predicates. Split verbatim from `../ownership-attribution` (SQ-539). */

import { extractBrandName, getRegistrableDomain } from '../public-suffix';

export function normHost(h: string): string {
	return h.trim().toLowerCase().replace(/\.$/, '');
}

/**
 * True when `nsHost` is the seed apex itself or a subdomain of it.
 *
 * The dot-boundary check on the `endsWith` branch is load-bearing: without
 * it, a lookalike like `evilbnz.co.nz` (or an NS host under it,
 * `ns1.evilbnz.co.nz`) would satisfy a bare `hostname.endsWith(seedApex)`
 * check against seed `bnz.co.nz`, because the substring `bnz.co.nz` appears
 * inside `evilbnz.co.nz` with no label separator in front of it. Requiring
 * the character immediately before the apex to be `.` (or an exact match)
 * closes that off.
 */
export function isInBailiwick(nsHost: string, seedApex: string): boolean {
	const host = normHost(nsHost);
	const apex = normHost(seedApex);
	if (!host || !apex) return false;
	return host === apex || host.endsWith('.' + apex);
}

/**
 * KNOB (#1040) — namespaces under a DNS/hosting provider's OWN registered apex
 * where the provider's product assigns every CUSTOMER's nameserver hostnames.
 *
 * An NS host in one of these namespaces is in-bailiwick to the provider's apex
 * by construction, but names a provider-customer relationship, not ownership:
 * when a brand-protection scan is run against the provider's own domain (seed
 * `cloudflare.com`), any of the provider's millions of customers — including a
 * deliberate typosquat of the provider's own brand (`cloaudflare.com` on
 * `lara.ns.cloudflare.com` / `arch.ns.cloudflare.com`, live 2026-09-17) —
 * would otherwise read as `owned_by_seed` and have its severity clamped to
 * info. The provider's own dedicated/branded NS (`ns3.cloudflare.com` …
 * `ns7.cloudflare.com`) sit OUTSIDE the customer namespace and keep full
 * in-bailiwick weight.
 *
 * Membership bar (mirrors `SHARED_NS_APEXES`' posture): only providers whose
 * customer-NS pool is MEASURED to nest under their own registered apex, in a
 * namespace disjoint from their own branded NS set. Cite the measurement.
 * This is deliberately NOT the shared-NS-overlap question — Cloudflare stays
 * ownership-bearing for literal hostname overlap (#939); this list only stops
 * the suffix-only in-bailiwick arm from firing on pool hosts.
 */
export const PROVIDER_CUSTOMER_NS_NAMESPACES: readonly string[] = [
	// Cloudflare assigns every customer zone an NS pair `<name>.ns.cloudflare.com`
	// drawn from a large pool (measured 2026-09-17, #1040 repro); Cloudflare's own
	// zones delegate to `ns3`–`ns7.cloudflare.com`, outside this namespace.
	'ns.cloudflare.com',
];

/**
 * True when `nsHost` sits inside a known provider customer-NS namespace
 * ({@link PROVIDER_CUSTOMER_NS_NAMESPACES}) — i.e. it is a hostname the
 * provider hands to arbitrary customers, so its being in-bailiwick to the
 * provider's apex carries no ownership signal (#1040).
 */
export function isProviderCustomerNsHost(nsHost: string): boolean {
	const host = normHost(nsHost);
	if (!host) return false;
	return PROVIDER_CUSTOMER_NS_NAMESPACES.some((namespace) => host === namespace || host.endsWith('.' + namespace));
}

/**
 * True when `candidateDomain` is an EXACT-LABEL TLD variant of the seed: it is
 * itself a registrable domain, its brand label equals the seed's, and it is not
 * the seed's own apex (`anz.co.nz` / `xero.com.au` for seed `anz.com` / `xero.com`).
 *
 * THE SHAPE OF A REGIONAL ESTATE, AND ONE A SQUATTER DOES NOT BUY — the rule
 * step 5d ({@link seedLabelCohortMatch}) already relies on, extracted here
 * (SQ-36) so the pooled-platform arm of `classifyOwnership()` can apply the SAME
 * bar rather than a second, drifting copy. A character edit (`bnz.co.nz` for
 * `anz.com`, `ltmcguiness.com` for `ltmcguinness.co.nz`) is NOT the exact label,
 * and edited names are what squatters register — so this predicate separates
 * "the organisation's other TLD" from "a typosquat", without ever asserting
 * which of the two it is: it only decides which arms may look further.
 */
export function isExactLabelTldVariant(candidateDomain: string, seedDomain: string): boolean {
	const seed = normHost(seedDomain);
	const seedLabel = extractBrandName(seed);
	const seedApex = getRegistrableDomain(seed);
	if (!seedLabel || !seedApex) return false;
	const candidate = normHost(candidateDomain);
	return candidate !== seedApex && getRegistrableDomain(candidate) === candidate && extractBrandName(candidate) === seedLabel;
}
