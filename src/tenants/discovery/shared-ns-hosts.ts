// SPDX-License-Identifier: BUSL-1.1

/**
 * Shared-tenant NS hosts — apex domains of nameserver providers that assign
 * the *same* NS hostnames to many unrelated customers.
 *
 * NS overlap is normally a strong ownership signal: two zones delegating to
 * the exact same nameserver hostnames typically share a DNS account. But
 * parking services and some shared-hosting / registrar-default platforms
 * publish the same `ns1.X.com` / `ns2.X.com` pair across thousands of
 * unrelated zones, so an overlap there is operational plumbing, not
 * ownership evidence.
 *
 * Hyperscale managed-DNS providers (Cloudflare, Route 53, Google Cloud DNS)
 * are deliberately NOT in this set — they assign *unique* NS hostnames per
 * account/zone, so an overlap there still implies same-account ownership.
 *
 * The ns-correlator drops shared-NS entries whose apex matches this set
 * from its `confidence` math; if ALL shared NS land here, the candidate is
 * skipped entirely (no signal contribution).
 *
 * Ref: v2.14.0 audit, leakage risk LR-2 (defense-in-depth at the correlator
 * layer; the orchestrator's corroboration gate already filters single-signal
 * NS, this covers two-signal scenarios where parking-NS would otherwise
 * inflate combined confidence).
 */

import { registeredApex } from './infrastructure-providers';

/**
 * Apex-form (2-label) domains of NS providers that assign shared NS
 * hostnames across many unrelated customers. Add conservatively — false
 * negatives (missing a provider) just mean the existing orchestrator gate
 * handles it; false positives (suppressing a real Cloudflare-style signal)
 * would erase legitimate ownership evidence.
 */
export const SHARED_NS_APEXES: ReadonlySet<string> = new Set([
	// Parking services
	'sedoparking.com',
	'parkingcrew.com',
	'parkingcrew.net',
	'bodis.com',
	'cashparking.com',
	'dan.com',
	'above.com',
	'internettraffic.com',
	'dnsowl.com',
	'parklogic.com',
	// GoDaddy default / parked / shared
	'domaincontrol.com',
	'secureserver.net',
	// Namecheap registrar-default
	'registrar-servers.com',
]);

/**
 * True if `nsHost` (a nameserver hostname like `ns1.sedoparking.com`) is
 * served by a shared-tenant NS provider — i.e. its registered apex appears
 * in SHARED_NS_APEXES.
 */
export function isSharedNsHost(nsHost: string): boolean {
	if (!nsHost) return false;
	const apex = registeredApex(nsHost);
	return SHARED_NS_APEXES.has(apex);
}
