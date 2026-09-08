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
 * TWO CLASSES OF SHARED PROVIDER (#929, 2026-09-09). `classifyOwnership()`
 * (`src/lib/ownership-attribution.ts`) credits a COMPLETE NS-set match on a
 * shared provider as medium ownership evidence — but that is only true where
 * the provider draws hostnames per zone from a large POOL (Akamai: six from
 * ~128 `a*-*.akam.net` hosts, so an identical 6/6 set means one account).
 * A platform that hands EVERY tenant the same set — one.com's `ns01`/`ns02`,
 * a parking service's `ns1`/`ns2`, a registrar default — makes a complete
 * match the DEFAULT relationship between two unrelated customers, and a
 * squatter who hosts a lookalike on the same platform would earn the seed's
 * `owned_by_seed` (and its `info` severity ceiling) for free. Measured live
 * 2026-09-09: `net-agents.dk`, `net-agent.dk` and `net-agents.com` all
 * delegate to `ns01.one.com` / `ns02.one.com`, and were attributed to each
 * other at confidence 1.00. So membership here is split: every apex in
 * `SHARED_NS_APEXES` is excluded from the dedicated-NS arm, and ONLY the
 * `POOLED_SHARED_NS_APEXES` subset may earn the complete-match arm. The
 * default for a new shared platform is therefore the safe one — add it to
 * `SHARED_NS_APEXES` and it can never attribute; promote it to the pooled
 * subset only with evidence that its complete sets are per-account.
 *
 * Ref: v2.14.0 audit, leakage risk LR-2 (defense-in-depth at the correlator
 * layer; the orchestrator's corroboration gate already filters single-signal
 * NS, this covers two-signal scenarios where parking-NS would otherwise
 * inflate combined confidence).
 */

import { registeredApex } from './infrastructure-providers';

/**
 * Apex-form (2-label) domains of NS providers that assign shared NS
 * hostnames across many unrelated customers.
 *
 * Membership bar (rewritten 2026-09-09, #929): list a provider when two
 * UNRELATED tenants can be observed sharing NS hostnames. The cost of a
 * missing entry is a manufacturable `owned_by_seed` — a squatter hosting a
 * lookalike on the seed's platform earns the seed's severity ceiling — which
 * is worse than the cost of an extra entry (an ownership lead that must be
 * corroborated some other way). Verify with two tenants over DoH before
 * adding; record the measurement in the entry's comment. Providers not yet
 * verified either way are tracked in the follow-up issue linked from PR #937.
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
	// one.com shared hosting — every tenant delegates to the identical
	// `ns01.one.com` / `ns02.one.com` pair (#929; verified live 2026-09-09 on
	// net-agents.dk, net-agent.dk, net-agents.com). NOT pooled: a complete
	// 2/2 match is what any two one.com customers look like.
	'one.com',
	// Akamai — assigns NS hostnames from a shared pool reused across unrelated
	// customer zones (2026-07-26 correctness-defects design §3.3, verified
	// live: bnz.co.nz shares a9-65.akam.net with anz.co.nz and a3-67.akam.net
	// with westpac.co.nz). Overlap on an Akamai hostname alone is NOT
	// ownership evidence; only a complete NS-set match is (see
	// `classifyOwnership()` in `src/lib/ownership-attribution.ts`) — which is
	// why it is ALSO in `POOLED_SHARED_NS_APEXES` below.
	'akam.net',
]);

/**
 * The subset of `SHARED_NS_APEXES` whose hostnames are assigned PER ZONE from
 * a pool large enough that an identical COMPLETE set implies one account
 * (#929). Only these may satisfy `classifyOwnership()`'s
 * `ns_shared_provider_complete` arm; every other shared apex hands each
 * tenant the same set, so a complete match there is not evidence.
 *
 * Membership is an evidence decision, not a convenience: promote an apex here
 * only after measuring that unrelated tenants receive DIFFERENT complete sets
 * (the Akamai measurement is in the `SHARED_NS_APEXES` comment above). The
 * `shared-ns-hosts` audit pins that this set stays a subset of the shared set.
 */
export const POOLED_SHARED_NS_APEXES: ReadonlySet<string> = new Set(['akam.net']);

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

/**
 * True if `nsHost` is served by a POOLED shared-tenant provider — one whose
 * complete NS set is per-account evidence (see `POOLED_SHARED_NS_APEXES`).
 * Always implies `isSharedNsHost(nsHost)`.
 */
export function isPooledSharedNsHost(nsHost: string): boolean {
	if (!nsHost) return false;
	const apex = registeredApex(nsHost);
	return POOLED_SHARED_NS_APEXES.has(apex);
}
