// SPDX-License-Identifier: BUSL-1.1

/**
 * Ownership-attribution primitive (P2, 2026-07-26 correctness-defects design §4).
 *
 * Classifies a registered candidate domain's ownership relative to a seed
 * domain. This is the single gate that decides whether a shadow-domain or
 * lookalike finding may exceed `info` severity — see
 * `docs/superpowers/specs/2026-07-26-bv-mcp-correctness-defects-design.md`
 * §4 (P2) and §5 (D4).
 *
 * Pure function, no DNS I/O: callers gather NS records and registration
 * state themselves (via `resolveRegistration()` from `./registration-state`,
 * or an existing NS probe) and pass them in — mirroring the injectable-
 * dependency pattern already used by `correlateNs`
 * (`src/tenants/discovery/ns-correlator.ts`'s `NsCorrelationOptions.dnsQuery`).
 * This keeps `src/lib/` free of a dependency on `src/tenants/discovery/`:
 * the shared-NS-apex predicate is passed in as `isSharedNsHost` rather than
 * imported directly.
 *
 * LOAD-BEARING SAFETY PROPERTY (controller amendment 2, do not weaken):
 * severity gating keys ONLY on `verdict === 'owned_by_seed'` vs everything
 * else. The `third_party` / `unattributed` distinction changes report
 * wording, never severity — a misclassification between those two can never
 * produce a false high-severity finding. `capAttributionSeverity()` below
 * enforces this: it treats `third_party` and `unattributed` identically.
 *
 * DEMOTE, NEVER DELETE (controller amendment 1, binding ruling from the
 * human partner): `passesAttributionGuard()` is a CLASSIFIER of corroboration
 * confidence, not a suppressor. The campaign's own seed brand in this slice's
 * fixture corpus (`bnz`) is 3 characters — the same length class as the
 * impersonator the guard was sized against (`hnz`) — so a guard that OMITS
 * findings on failure would delete real measurements about the customer's
 * OWN assets, which is worse than the false-positive it exists to prevent.
 * `capAttributionSeverity()` is the safe API surface for callers: it always
 * returns a concrete, truthy value (a `Severity` or the `'unbounded'`
 * sentinel) — there is no `null`/`undefined` return that a caller could
 * mistake for "omit this finding". A real measurement must never be
 * suppressed; only its severity is capped and its wording kept neutral.
 */

import type { Severity } from '@blackveil/dns-checks/scoring';
import { getRegistrableDomain } from './public-suffix';
import type { RegistrationState } from './registration-state';
import { UNKNOWN_REASON_PHRASES } from './registration-state';

/** Final attribution verdict. */
export type OwnershipVerdict = 'owned_by_seed' | 'third_party' | 'unattributed';

export type OwnershipStrength = 'strong' | 'medium' | 'weak' | 'none';

export type OwnershipSignal =
	| 'ns_in_bailiwick'
	| 'ns_set_match'
	| 'ns_shared_provider_complete'
	| 'soa_in_bailiwick'
	| 'spf_include_seed'
	| 'http_redirect_seed'
	| 'distinct_infrastructure';

export interface OwnershipAssessment {
	verdict: OwnershipVerdict;
	strength: OwnershipStrength;
	signals: OwnershipSignal[];
	/** Human-readable, safe to surface in a report — never implies ownership beyond `verdict`. */
	rationale: string;
}

export interface ClassifyOwnershipInput {
	seedDomain: string;
	/** The seed's own NS hostnames. */
	seedNs: string[];
	candidateDomain: string;
	registration: RegistrationState;
	/**
	 * Injected shared-NS-apex predicate (`isSharedNsHost` from
	 * `src/tenants/discovery/shared-ns-hosts.ts`). Required so this module
	 * never imports from `src/tenants/discovery/` (see file header).
	 */
	isSharedNsHost: (nsHost: string) => boolean;
	/**
	 * Additional strong signals. Not gathered by any caller in this slice
	 * (neither tool parses SPF `include:` targets, SOA RNAME, or HTTP
	 * redirect targets today) — accepted here so a future slice can wire a
	 * real probe without touching this function's precedence logic again.
	 */
	soaInBailiwick?: boolean;
	spfIncludesSeedApex?: boolean;
	httpRedirectToSeedApex?: boolean;
}

/** Minimum ratio of dedicated (non-shared-provider) NS hosts shared with the seed to count as strong evidence. */
const DEDICATED_NS_MATCH_RATIO = 0.5;
/** Minimum absolute count of dedicated shared NS hosts, alongside the ratio above. */
const DEDICATED_NS_MATCH_MIN_COUNT = 2;

/** Minimum brand-label length below which a non-owned candidate needs corroboration to be scored at full confidence (D4). */
export const MIN_ATTRIBUTION_LABEL_LENGTH = 5;

function normHost(h: string): string {
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
 * Classify a candidate's ownership relative to a seed domain.
 *
 * Precedence (design doc §4 P2, corrected per §3.3):
 *  1. Non-registered / registration-unknown → `unattributed` (attribution is moot).
 *  2. NS in-bailiwick to the seed apex → `owned_by_seed`, strong.
 *  3. SOA RNAME in-bailiwick (caller-supplied) → `owned_by_seed`, strong.
 *  4. SPF include / HTTP redirect to seed apex (caller-supplied) → `owned_by_seed`, strong.
 *  5. NS set match on hosts NOT flagged shared, >=50% AND >=2 shared → `owned_by_seed`, strong.
 *  6. Complete (100%) NS set match where every shared host is on a SHARED provider → `owned_by_seed`, medium.
 *  7. Partial overlap confined to shared-provider hosts → not evidence (falls through silently —
 *     this is the ANZ/Westpac 1/6-Akamai trap: a single shared-provider NS host in common is
 *     operational plumbing, not ownership evidence).
 *  8. Registered with its own resolvable NS, no ownership signal → `third_party`.
 *  9. Everything else (no NS info at all) → `unattributed`.
 */
export function classifyOwnership(input: ClassifyOwnershipInput): OwnershipAssessment {
	const { registration, candidateDomain } = input;

	if (registration.state === 'unregistered') {
		return {
			verdict: 'unattributed',
			strength: 'none',
			signals: [],
			rationale: `${candidateDomain} is not registered — there is nothing to attribute.`,
		};
	}
	if (registration.state === 'unknown') {
		// Amendment (3): render the human-readable phrase from
		// UNKNOWN_REASON_PHRASES, never the raw UnknownReason token — internal
		// enum values like 'empty_noerror' are meaningless in a customer-facing
		// report about a named organisation.
		return {
			verdict: 'unattributed',
			strength: 'none',
			signals: [],
			rationale: `${candidateDomain}'s registration status could not be determined — ${UNKNOWN_REASON_PHRASES[registration.reason]}.`,
		};
	}

	const seedApex = getRegistrableDomain(input.seedDomain) ?? normHost(input.seedDomain);
	const candidateNs = registration.ns.map(normHost).filter(Boolean);
	const seedNs = input.seedNs.map(normHost).filter(Boolean);

	const inBailiwickNs = candidateNs.filter((ns) => isInBailiwick(ns, seedApex));
	if (inBailiwickNs.length > 0) {
		return {
			verdict: 'owned_by_seed',
			strength: 'strong',
			signals: ['ns_in_bailiwick'],
			rationale: `${candidateDomain}'s nameserver(s) ${inBailiwickNs.join(', ')} are delegated under ${seedApex}.`,
		};
	}

	if (input.soaInBailiwick) {
		return {
			verdict: 'owned_by_seed',
			strength: 'strong',
			signals: ['soa_in_bailiwick'],
			rationale: `${candidateDomain}'s SOA responsible party is in-bailiwick to ${seedApex}.`,
		};
	}
	if (input.spfIncludesSeedApex || input.httpRedirectToSeedApex) {
		const signal: OwnershipSignal = input.spfIncludesSeedApex ? 'spf_include_seed' : 'http_redirect_seed';
		return {
			verdict: 'owned_by_seed',
			strength: 'strong',
			signals: [signal],
			rationale:
				signal === 'spf_include_seed'
					? `${candidateDomain}'s SPF record includes a policy rooted at ${seedApex}.`
					: `${candidateDomain}'s HTTP root redirects to ${seedApex}.`,
		};
	}

	const sharedNs = candidateNs.filter((ns) => seedNs.includes(ns));
	const dedicatedShared = sharedNs.filter((ns) => !input.isSharedNsHost(ns));
	const seedTotal = seedNs.length;

	if (
		seedTotal > 0 &&
		dedicatedShared.length >= DEDICATED_NS_MATCH_MIN_COUNT &&
		dedicatedShared.length / seedTotal >= DEDICATED_NS_MATCH_RATIO
	) {
		return {
			verdict: 'owned_by_seed',
			strength: 'strong',
			signals: ['ns_set_match'],
			rationale: `${candidateDomain} shares ${dedicatedShared.length}/${seedTotal} dedicated nameservers with ${seedApex}.`,
		};
	}

	if (seedTotal > 0 && sharedNs.length === seedTotal && sharedNs.every((ns) => input.isSharedNsHost(ns))) {
		return {
			verdict: 'owned_by_seed',
			strength: 'medium',
			signals: ['ns_shared_provider_complete'],
			rationale: `${candidateDomain} matches the complete ${seedTotal}/${seedTotal} nameserver set on a shared provider. A full match is evidence; a partial match on the same provider would not be.`,
		};
	}

	if (candidateNs.length > 0) {
		return {
			verdict: 'third_party',
			strength: 'none',
			signals: ['distinct_infrastructure'],
			rationale: `${candidateDomain} is registered with its own nameservers, distinct from ${seedApex} — no ownership signal links it to this organisation.`,
		};
	}

	return {
		verdict: 'unattributed',
		strength: 'none',
		signals: [],
		rationale: `No ownership or third-party signal could be established for ${candidateDomain}.`,
	};
}

/**
 * D4 corroboration classifier: does a non-owned candidate's brand-label
 * match meet the confidence bar to stand on its own?
 *
 * `owned_by_seed` always passes — it is the strongest available
 * corroborating brand signal by construction. Any other verdict needs
 * EITHER a brand label at least `MIN_ATTRIBUTION_LABEL_LENGTH` characters
 * long, OR an explicit corroborating signal supplied by the caller
 * (MX/SPF overlap with the primary domain is the one wired in this slice —
 * cert-SAN and page-content corroboration are not, since neither tool
 * fetches them today). Below the threshold with no corroboration, a short
 * brand label (e.g. `bnz`, 3 characters) collides with too much unrelated
 * global DNS for a bare label match to mean anything on its own — see spec
 * §5 D4.
 *
 * THIS FUNCTION IS A CLASSIFIER, NOT A SUPPRESSION GATE. A caller MUST NOT
 * branch a `false` result into omitting a finding — do that and a real
 * measurement about the customer's own short-labelled brand (this
 * campaign's seed, `bnz`, is itself 3 characters) silently vanishes from the
 * report. Use `capAttributionSeverity()` instead: its return type has no
 * value that means "no finding", only a severity ceiling.
 */
export function passesAttributionGuard(verdict: OwnershipVerdict, brandLabel: string, corroborated: boolean): boolean {
	if (verdict === 'owned_by_seed') return true;
	return brandLabel.length >= MIN_ATTRIBUTION_LABEL_LENGTH || corroborated;
}

/**
 * Severity ceiling a non-owned candidate's finding may not exceed —
 * `'unbounded'` when no cap applies, or the literal `Severity` value
 * (currently always `'info'`) the caller must clamp down to otherwise.
 *
 * DEMOTE, NEVER DELETE: unlike a boolean gate, this type has no falsy /
 * null / undefined member, so there is no value a caller could mistake for
 * "omit this finding" — every return is a concrete instruction to either
 * leave the computed severity alone (`'unbounded'`) or clamp it
 * (`'info'`). The finding itself is ALWAYS emitted by the caller; only its
 * severity and wording change. See the file-header note on controller
 * amendment 1 for the incident this fixes (a length-5 guard, sized against
 * the impersonator `hnz`, would otherwise have deleted findings about this
 * campaign's own 3-character seed brand `bnz`).
 *
 * Per the load-bearing safety property (amendment 2), `third_party` and
 * `unattributed` are treated identically here — only `owned_by_seed` is
 * ever exempt from the cap.
 */
export function capAttributionSeverity(verdict: OwnershipVerdict, brandLabel: string, corroborated: boolean): Severity | 'unbounded' {
	return passesAttributionGuard(verdict, brandLabel, corroborated) ? 'unbounded' : 'info';
}
