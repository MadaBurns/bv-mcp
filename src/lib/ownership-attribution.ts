// SPDX-License-Identifier: BUSL-1.1

/**
 * Ownership-attribution primitive (P2, 2026-07-26 correctness-defects design §4).
 *
 * Classifies a registered candidate domain's ownership relative to a seed
 * domain. `capAttributionSeverity()` below is the single gate that decides
 * whether a shadow-domain or lookalike finding may exceed `info` severity —
 * see `docs/superpowers/specs/2026-07-26-bv-mcp-correctness-defects-design.md`
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
 * produce a false high-severity finding. `capAttributionSeverity()` enforces
 * this and takes `verdict` ALONE — no other input can move the ceiling.
 *
 * DEMOTE, NEVER DELETE (controller amendment 1, binding ruling from the
 * human partner): `attributionConfidence()` is a CLASSIFIER of wording
 * confidence, not a severity gate and not a suppressor — see fix-round F1/F3
 * below for why it must never be consulted for the severity ceiling.
 * `capAttributionSeverity()` is the ONLY exported severity-decision surface:
 * it always returns a concrete, truthy value (a `Severity` or the
 * `'unbounded'` sentinel) — there is no `null`/`undefined` return a caller
 * could mistake for "omit this finding". A real measurement must never be
 * suppressed; only its severity is capped and its wording kept neutral.
 *
 * FIX ROUND 1 (2026-07-27, post-review): the first implementation had
 * `capAttributionSeverity()` consult the D4 label-length/corroboration guard
 * BEFORE the ownership verdict, so any non-owned candidate with a brand
 * label >= `MIN_ATTRIBUTION_LABEL_LENGTH` characters (e.g. `westpac`, a
 * competing bank) came back `'unbounded'` — the exact defect this slice
 * exists to fix, on the safety-critical function. Corrected:
 * `capAttributionSeverity()` now takes ONLY `verdict` and gates on ownership
 * FIRST. The label-length/corroboration guard (`attributionConfidence()`,
 * renamed from `passesAttributionGuard()`) still exists but now governs
 * WORDING/CONFIDENCE prose only — it is never consulted for severity, and
 * its non-boolean `'corroborated' | 'uncorroborated'` return shape (renamed
 * from a raw boolean) makes it read as a confidence classifier rather than
 * a permission gate a caller might branch into a suppression.
 *
 * TASK 7c (2026-07-27, two rulings amending the P2 signal table — see
 * `.superpowers/sdd/2026-07-26-slice4-ownership-attribution/task-7c-brief.md`):
 * Ruling A — the candidate-side signals (formerly `soaInBailiwick`,
 * `spfIncludesSeedApex`, `httpRedirectToSeedApex` on `ClassifyOwnershipInput`)
 * are attacker-influenceable and NEVER independently verdict-bearing. Ruling B
 * — an in-bailiwick NS observation is ownership-bearing only when it comes
 * from an actually-resolved NS answer set; see `classifyOwnership()`'s
 * precedence-table JSDoc and `resolveRegistrationUncached()` in
 * `./registration-state`.
 *
 * OWNERSHIP-ATTRIBUTION FOLLOWUPS, ITEM 2 (2026-07-27, "delete them" ruling):
 * the three candidate-side fields above were accepted on
 * `ClassifyOwnershipInput` but never read anywhere in `classifyOwnership()`'s
 * body — no caller ever populated them either (`check-lookalikes.ts` and
 * `check-shadow-domains.ts` only ever pass `seedNs`/`candidateNs`-derived
 * `registration`). Ruling A's "never verdict-bearing" rule made them
 * permanently inert; keeping accept-but-ignore fields that are themselves
 * attacker-influenceable is a pure footgun (a future caller could wire a real
 * probe expecting them to matter and never notice they're silently ignored,
 * or a "cleanup" could accidentally start reading them). DELETED rather than
 * left present-but-unused — see the `OWNERSHIP RULE` note on
 * `ClassifyOwnershipInput` below for the rule a future author re-wiring a
 * real SOA/SPF/redirect probe must re-derive.
 *
 * AMENDMENT — SEED-AUTHORISED CONVERGENCE (2026-09-04, #864, regression of
 * #263; reworked after PR #897 review). Ruling A's seed-side-only rule has a
 * blind spot #864 measured live: a same-entity domain on a DIFFERENT DNS
 * platform (`amazon.com` on Route 53, `amazon.com.au` on Amazon's internal
 * `amzndns.*`) shares no nameserver with the seed, and the #263 RDAP
 * registrant tier is structurally blind for the pair — Verisign's `.com`
 * RDAP is thin and auDA's `.com.au` RDAP publishes no registrant entity
 * (observed 2026-09-04). So the candidate was counted as an impersonation-
 * capable third party.
 *
 * Ruling A is NOT weakened: the verdict below still rests on a record ONLY
 * THE SEED CAN PUBLISH. The candidate-side half is a cheap PRE-FILTER, never
 * evidence. The two halves of `assessSeedAuthorisedConvergence()`:
 *
 *   1. PRE-FILTER (candidate-side, attacker-free, zero cost): every real MX
 *      exchange of the candidate sits inside the seed apex. Copying the
 *      seed's MX string is free for a SENDING squatter — a phishing sender
 *      never wanted the receive channel — so this half carries NO weight; it
 *      only decides which candidates are worth the seed-side lookups.
 *   2. VERDICT (seed-side): the candidate's DMARC record sends aggregate/
 *      forensic reports to a mailbox whose domain sits inside the seed apex,
 *      AND the seed has published the RFC 7489 §7.1 external-destination
 *      authorisation `<candidate>._report._dmarc.<receiver-domain>` TXT
 *      `v=DMARC1`. The DMARC record itself is candidate-published (free to
 *      forge); the authorisation record lives in the RECEIVER's zone, under
 *      the seed apex, and only its owner can publish it — a squatter cannot.
 *      A wildcard grant (`*._report._dmarc.<receiver>`, detected with a
 *      canary label) is a seed choice to accept reports about ANY domain, so
 *      it is evidence-only, never verdict-bearing.
 *
 * Live (DoH, 2026-09-04): `_dmarc.amazon.com.au` → CNAME `_dmarc.amazon.com`,
 * `rua=mailto:report<at>dmarc.amazon.com` (mailbox spelled out to keep the
 * secret scanner quiet); `amazon.com.au._report._dmarc.dmarc.
 * amazon.com` TXT `v=DMARC1` EXISTS; a random label under the same
 * `_report._dmarc` is NXDOMAIN (not a wildcard) and `amzndns.com` — which
 * reports to the same mailbox — has NO such record: a per-domain grant.
 *
 * REJECTED on the same live records: SOA MNAME (unverified free text in a
 * self-hosted zone — the first #897 revision used it and was correctly
 * blocked), SOA RNAME (Route 53 templates `awsdns-hostmaster.amazon.com` into
 * every tenant zone), the NS-platform chain (`amzndns.com` and public
 * `awsdns-33.com` carry the same RNAME), seed SPF (`spf1/2/3.amazon.com` name
 * no candidate), SPF `include:` / HTTP redirect (free-text, deleted
 * 2026-07-27).
 *
 * CT SAN co-listing is a third class of rejection, neither attacker-forgeable
 * free text nor a coverage-measured absence: co-listing on a certificate that
 * includes the seed proves only a common certificate BUYER, which may be a
 * shared platform, not common ownership (a CA validates each name against
 * whoever ordered the cert, e.g. a vendor the seed delegated to). Measured
 * (SQ-302, 2026-10-04, #1188, #1189): a 2025 Amazon Trust Services cert lists
 * 25 `csxd.<customer>` names across 23 registrable domains, co-listing
 * `blackrock.com` with unrelated organisations; a 2015 shared Cloudflare cert
 * carries 37 names across 19 domains. Issuer exclusion, fan-out caps and
 * `san_recursive` mutual inclusion each fail as discriminators (the same
 * shared cert answers both directions). The older "0 of 3300" figure was a
 * crt.sh search artifact — `name_value` lists only query-matched names — and
 * is not evidence either way. Re-measured on CURRENT certificates (SQ-337,
 * 2026-10-17, 8,697 unexpired certs sampled from two CT logs): shared
 * platform certs pairing a customer with an unrelated CDN/host domain occur at
 * 2-5 registrable domains (e.g. `<hex>.sni.cloudflaressl.com` + one customer,
 * still issued with 2027 expiry; `mybluehost.me` temporary domains), while
 * same-owner certs span 2-8 — so no fan-out cap separates them, and the
 * signal was declined even as wording-only corroboration.
 * The signal is fetched by `discover_brand_domains`
 * at weight 0.1 and is deliberately not an input here.
 *
 * Residual, stated not hidden: a seed that is itself a DMARC report-
 * processing PROVIDER (Agari/Valimail-shaped) publishes authorisation records
 * for every customer, so a customer whose MX also sits inside that seed's
 * apex would attribute — the same provider-class residual the NS
 * in-bailiwick arm already carries for DNS providers. Strength is `medium`
 * and `evidence[]` names every record so a consumer can audit the match.
 *
 * AMENDMENT — SHARED-PLATFORM NS PAIRS (2026-09-09, #929, the mirror image of
 * #263/#864). The seed-side NS arms assumed that any nameserver NOT on a
 * known shared provider is "dedicated", and that a COMPLETE match on a
 * shared provider is medium evidence. Both assumptions fail on a platform
 * that hands EVERY tenant the identical set: `net-agents.dk`, `net-agent.dk`
 * and `net-agents.com` all delegate to `ns01.one.com` / `ns02.one.com`
 * (one.com shared hosting, DoH 2026-09-09) and were attributed to each other
 * at `strong` / confidence 1.00 on `ns_set_match` — a test that would also
 * attribute every other one.com customer, and that a squatter satisfies by
 * hosting the lookalike at one.com (earning the `info` ceiling the D4 gate
 * reserves for the seed's own domains). Ruling A's bar applies to NS too: a
 * verdict rests only on what the SEED alone can publish, and a
 * platform-assigned NS set is not that.
 *
 * Fix: (1) one.com joins `SHARED_NS_APEXES`, so its hosts never count as
 * dedicated; (2) the complete-match arm (step 4) now requires the injected
 * `isPooledSharedNsHost` predicate to accept EVERY matched host — only a
 * provider that draws hostnames per zone from a large pool (Akamai) makes an
 * identical complete set per-account evidence. The predicate is optional and
 * DEFAULTS CLOSED (nothing is pooled): a caller that omits it can never
 * credit a platform. (3) An overlap confined to shared-provider hosts that
 * does not earn step 4 now carries the `ns_shared_platform` signal and a
 * rationale naming the platform hosts: identical whole sets on a non-pooled
 * platform → `unattributed` (nothing distinct was observed, so the report
 * must not say "registered to a different organisation" about what may be
 * the customer's own alias), any other platform-confined overlap →
 * `third_party`. Same `info` ceiling either way; step 5b (the seed-published
 * DMARC grant) keeps precedence. (4) The dedicated
 * arm's rationale no longer says "dedicated"; it says the hosts are on no
 * known shared-tenant provider, which is what was actually checked.
 */

import { UNKNOWN_REASON_PHRASES } from './registration-state';
import { getRegistrableDomain } from './public-suffix';
import {
	DEDICATED_NS_MATCH_MIN_COUNT,
	DEDICATED_NS_MATCH_RATIO,
	type ClassifyOwnershipInput,
	type OwnershipAssessment,
} from './ownership/types';
import { isInBailiwick, isProviderCustomerNsHost, isExactLabelTldVariant, normHost } from './ownership/hosts';
import { assessSeedAuthorisedConvergence, seedInfrastructureMatch, seedLabelCohortMatch } from './ownership/seed-matching';

// Re-exports: every name this module exported before the SQ-539 split stays importable from this path.
export type {
	ClassifyOwnershipInput,
	DmarcReportAuthorisation,
	LabelCohortMember,
	OwnershipAssessment,
	OwnershipEvidence,
	OwnershipSignal,
	OwnershipStrength,
	OwnershipVerdict,
} from './ownership/types';
export { MIN_ATTRIBUTION_LABEL_LENGTH, MIN_LABEL_COHORT_SIBLINGS, SEED_LABEL_COHORT_SHARED_NS_MIN } from './ownership/types';
export { isExactLabelTldVariant, isInBailiwick, isProviderCustomerNsHost, PROVIDER_CUSTOMER_NS_NAMESPACES } from './ownership/hosts';
export {
	DMARC_REPORT_PROCESSOR_APEXES,
	isDmarcReportProcessorApex,
	mxRoutedIntoSeed,
	parseDmarcReportReceivers,
	seedInfrastructureMatch,
	seedLabelCohortMatch,
} from './ownership/seed-matching';
export type { AttributionConfidence, NonOwnedGateOptions } from './ownership/gate';
export { attributionConfidence, buildNonOwnedGateFinding, buildOwnershipGateMetadata, capAttributionSeverity } from './ownership/gate';

/**
 * Classify a candidate's ownership relative to a seed domain.
 *
 * Precedence (design doc §4 P2, corrected per §3.3, and per Ruling A
 * 2026-07-27 task-7c — see the OWNERSHIP RULE note on
 * `ClassifyOwnershipInput`'s candidate-side fields):
 *  1. Non-registered / registration-unknown → `unattributed` (attribution is moot).
 *     RegistrationState is a discriminated union: only the `registered` arm
 *     carries an `ns` field at all, so an in-bailiwick match is structurally
 *     unreachable for `unregistered`/`unknown` (Ruling B) — this precedence
 *     step returns before `registration.ns` is ever read.
 *  2. NS in-bailiwick to the seed apex → `owned_by_seed`, strong — EXCEPT
 *     (#1040) hosts in a known provider customer-NS namespace
 *     ({@link PROVIDER_CUSTOMER_NS_NAMESPACES}) or flagged by the injected
 *     shared-tenant predicate, which name a provider-customer relationship,
 *     not ownership, and fall through to the set-comparison arms. Because
 *     `registration.ns` is only ever populated from an ACTUALLY-RESOLVED NS
 *     answer set (see `resolveRegistrationUncached()` in
 *     `./registration-state`), a lame delegation — attacker sets NS =
 *     `ns1.bnz.co.nz` in the candidate's own parent-zone delegation, but the
 *     seed's server never actually serves that zone — SERVFAILs at
 *     resolution and never reaches this arm with a matching host (Ruling B:
 *     "in-bailiwick NS requires resolution evidence").
 *  3. NS set match on hosts NOT flagged shared, >=50% AND >=2 shared → `owned_by_seed`, strong.
 *  4. Complete (100%) NS set match where every shared host is on a POOLED shared provider
 *     (`isPooledSharedNsHost`, #929 — Akamai; defaults closed) → `owned_by_seed`, medium.
 *  5. Any other overlap confined to shared-provider hosts → not evidence. A partial overlap is
 *     the ANZ/Westpac 1/6-Akamai trap (a single pooled host in common is operational plumbing);
 *     a complete match on a NON-pooled platform (one.com `ns01`/`ns02`, #929) is what every
 *     tenant of that platform looks like. Falls through to 5b; if 5b declines: the candidate's
 *     WHOLE set is platform hosts the seed uses → `unattributed` (nothing distinct observed),
 *     any other platform-confined overlap → `third_party` — both carrying `ns_shared_platform`.
 *     (SQ-36) The MIRROR of that whole-set case on a POOLED platform: the seed's whole set is on
 *     one pooled provider and every candidate host is either on that same provider or inside the
 *     candidate's OWN registrable domain. A pooled provider assigns hostnames per zone, so
 *     NON-identity there is the provider's doing, and a self-referential nameserver names no
 *     operator — nothing distinct was observed → `unattributed`, `ns_shared_platform`. Consulted
 *     before the arms above, and like them it can never yield `owned_by_seed`.
 *  5b. (#864) SEED-AUTHORISED convergence — pre-filter: every real MX exchange inside the seed
 *     apex (attacker-free, no weight); verdict: the seed publishes the RFC 7489 §7.1 DMARC
 *     report authorisation `<candidate>._report._dmarc.<receiver-under-seed>` → `owned_by_seed`,
 *     medium, with `evidence`. Requires the caller to have supplied `candidateMx` +
 *     `dmarcReportAuthorisation`. A wildcard grant is evidence-only. If the pre-filter holds but
 *     the seed-side probe REJECTED, the verdict is `unmeasured`, not `third_party`.
 *  5c. (#974) The candidate's A set AND real MX set are each identical to the seed's
 *     ({@link seedInfrastructureMatch}) → `unattributed` with `seed_infrastructure_match` —
 *     never `owned_by_seed` (candidate-published, copyable). Replaces only a `third_party` outcome
 *     (step 5's platform-partial arm, step 6); step 5's whole-platform `unattributed` is kept.
 *  5d. (#974 reopened) The candidate is an exact-label TLD variant on the seed's A set, and 2+ other
 *     exact-label variants share its identical A, NS and MX sets on non-platform NS — or, when the
 *     cohort has {@link SEED_LABEL_COHORT_SHARED_NS_MIN}+ members (siblings plus the candidate), on a
 *     shared-tenant platform NS too (#974 large-cohort exception) —
 *     ({@link seedLabelCohortMatch}) → `unattributed` with `seed_label_cohort`. Same posture as 5c,
 *     consulted only when 5c declined.
 *  6. Registered with its own resolvable NS, no ownership signal → `third_party`.
 *  7. Everything else (no NS info at all) → `unattributed`.
 *
 * The #864 inputs (`candidateMx`, `dmarcReportAuthorisation`) are consulted
 * ONLY at step 5b, strictly after every seed-side NS arm; the verdict there
 * rests on the seed-published authorisation record alone. SPF `include:`,
 * HTTP redirect and SOA fields remain excluded (see the OWNERSHIP RULE note
 * on `ClassifyOwnershipInput`).
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

	const normalisedSeedDomain = normHost(input.seedDomain);
	const seedApex = getRegistrableDomain(normalisedSeedDomain) ?? normalisedSeedDomain;
	const candidateNs = registration.ns.map(normHost).filter(Boolean);
	const seedNs = input.seedNs.map(normHost).filter(Boolean);

	// #1040 — an in-bailiwick host is ownership evidence only when the seed
	// organisation actually operates it as ITS OWN infrastructure. Two classes
	// of in-bailiwick host name a provider-customer relationship instead and
	// are excluded before the short-circuit: (a) hosts inside a known provider
	// customer-NS namespace (`lara.ns.cloudflare.com` under seed
	// `cloudflare.com` — every Cloudflare customer, typosquats included,
	// carries one); (b) hosts the injected shared-tenant predicate flags
	// (reachable only when the seed apex IS a shared-NS provider's apex, e.g.
	// seed `one.com` vs a customer on `ns01.one.com`). Excluded hosts fall
	// through to the set-comparison arms below, which judge them on literal
	// overlap like any other shared-platform host.
	const inBailiwickNs = candidateNs.filter(
		(ns) => isInBailiwick(ns, seedApex) && !isProviderCustomerNsHost(ns) && !input.isSharedNsHost(ns),
	);
	if (inBailiwickNs.length > 0) {
		return {
			verdict: 'owned_by_seed',
			strength: 'strong',
			signals: ['ns_in_bailiwick'],
			rationale: `${candidateDomain}'s nameserver(s) ${inBailiwickNs.join(', ')} are delegated under ${seedApex}.`,
		};
	}

	// #864 — the seed-authorised convergence arm needs only the seed APEX (like
	// the NS in-bailiwick arm above), so it is computed here and may still yield
	// a positive verdict under a degraded seed NS lookup; it is APPLIED only
	// after the seed-side set-comparison arms below, which keep precedence.
	const convergence = assessSeedAuthorisedConvergence(input, candidateDomain, seedApex);

	// #832 — degraded comparison inputs. The seed's NS lookup did not resolve,
	// so every arm below would be comparing against an UNFETCHED set: the
	// ns_set_match / shared-provider arms cannot fire (seedNs is empty), and
	// the third_party arm would publish "no ownership signal links it" about
	// signals nobody fetched — the exact non-answer-becomes-record defect this
	// verdict exists to prevent. Only the in-bailiwick arm above (which needs
	// the seed APEX, not its NS answer) may still produce a verdict.
	if (input.seedNsUnresolved) {
		if (convergence?.verdict === 'owned_by_seed') return convergence;
		return {
			verdict: 'unmeasured',
			strength: 'none',
			signals: [],
			rationale: `Ownership of ${candidateDomain} was not assessed in this run: the nameserver lookup for ${seedApex} did not resolve, so ${candidateDomain}'s nameservers could not be compared against it. This is a measurement gap, not evidence of third-party registration — re-run to attribute.`,
		};
	}

	// Ruling A (2026-07-27, task-7c): candidate-side declarations (SOA RNAME,
	// SPF include, HTTP redirect target — see the OWNERSHIP RULE note on
	// `ClassifyOwnershipInput`) are never consulted here, and no such inputs
	// even exist on this type any more (deleted 2026-07-27, ownership-
	// attribution followups item 2) — they can never independently (or
	// combined) establish `owned_by_seed`. Only seed-side signals (this arm
	// and the two below) may do that.

	const sharedNs = candidateNs.filter((ns) => seedNs.includes(ns));
	const dedicatedShared = sharedNs.filter((ns) => !input.isSharedNsHost(ns));
	const seedTotal = seedNs.length;
	// #929 — defaults CLOSED: with no predicate injected, no shared provider is
	// pooled and the complete-match arm below is unreachable.
	const isPooled = input.isPooledSharedNsHost ?? (() => false);

	if (
		seedTotal > 0 &&
		dedicatedShared.length >= DEDICATED_NS_MATCH_MIN_COUNT &&
		dedicatedShared.length / seedTotal >= DEDICATED_NS_MATCH_RATIO
	) {
		// #929 — "dedicated" was the old word here. What is actually checked is
		// that none of the matched hosts sits on a KNOWN shared-tenant provider;
		// say that, not more.
		return {
			verdict: 'owned_by_seed',
			strength: 'strong',
			signals: ['ns_set_match'],
			rationale: `${candidateDomain} shares ${dedicatedShared.length}/${seedTotal} nameservers with ${seedApex} (${dedicatedShared.join(', ')}), none on a known shared-tenant provider.`,
		};
	}

	// #1039 — step 3b: an EXACT nameserver-set match that MIXES dedicated and
	// shared-provider hosts, which fell between the two arms either side of it.
	// Step 3 above declines because the off-platform hosts are a minority of the
	// set (barclays.co.uk carries all nine of barclays.com's hosts, but only the
	// three `ns*.barcap.com` are on no known shared provider — 3/9 = 33%, under
	// `DEDICATED_NS_MATCH_RATIO`); step 4 below declines because its
	// every-matched-host-is-shared test is false on those same three. Control
	// then reached the distinct-infrastructure arm, which publishes "no
	// ownership signal links it" about a byte-identical set — literally false.
	//
	// Both guards are load-bearing, because `owned_by_seed` does not merely lift
	// the severity cap: the lookalike surfaces drop the threat finding entirely
	// for an owned candidate, so a false positive here silently suppresses a
	// threat.
	//  - EXACT set equality, not overlap: a candidate carrying the seed's set
	//    PLUS its own host, or all but one of it, is a different shape and keeps
	//    its `third_party` verdict.
	//  - at least `DEDICATED_NS_MATCH_MIN_COUNT` DISTINCT matched hosts on no
	//    known shared-tenant provider. ⚠️ That is 2, NOT 1, and must not be
	//    "simplified" to 1: across 1,819 measured seed/candidate pairs the two
	//    bars behave identically (30 flips either way, none of them a genuine
	//    impersonation), so the stricter bar costs nothing measured and closes
	//    three shapes a squatter can buy with a self-service account — two
	//    `domaincontrol.com` hosts plus one unlisted host, two
	//    `registrar-servers.com` hosts plus one, and six `akam.net` plus one.
	//    Known residual under BOTH bars: a seed split across azure-dns (listed,
	//    but a small pool) plus a two-host unlisted provider. It was unobserved
	//    across those 1,819 pairs, so it is recorded here rather than paid for
	//    with a wider guard.
	const candidateNsUnique = [...new Set(candidateNs)];
	const seedNsUnique = [...new Set(seedNs)];
	const exactNsSetMatch =
		seedNsUnique.length > 0 &&
		candidateNsUnique.length === seedNsUnique.length &&
		candidateNsUnique.every((ns) => seedNsUnique.includes(ns));
	// Counted DISTINCT: a candidate that lists one off-platform host twice must
	// not reach the two-host bar on its own.
	const dedicatedSharedDistinct = [...new Set(dedicatedShared)];

	if (exactNsSetMatch && dedicatedSharedDistinct.length >= DEDICATED_NS_MATCH_MIN_COUNT) {
		return {
			verdict: 'owned_by_seed',
			strength: 'strong',
			signals: ['ns_set_match'],
			rationale: `${candidateDomain} delegates to exactly ${seedApex}'s complete ${seedNsUnique.length}-nameserver set (${seedNsUnique.join(', ')}), of which ${dedicatedSharedDistinct.length} (${dedicatedSharedDistinct.join(', ')}) are on no known shared-tenant provider — an account-level match on ${seedApex}'s own nameserver set.`,
		};
	}

	if (
		seedTotal > 0 &&
		sharedNs.length === seedTotal &&
		sharedNs.every((ns) => input.isSharedNsHost(ns)) &&
		sharedNs.every((ns) => isPooled(ns))
	) {
		return {
			verdict: 'owned_by_seed',
			strength: 'medium',
			signals: ['ns_shared_provider_complete'],
			rationale: `${candidateDomain} matches the complete ${seedTotal}/${seedTotal} nameserver set on a pooled shared provider (${sharedNs.join(', ')}). A full match is evidence there; a partial match on the same provider would not be.`,
		};
	}

	// #864 — step 5b. Applied only once every seed-side NS arm has declined, so
	// a strong NS match is never displaced by this medium-strength verdict. Also
	// carries the `unmeasured` outcome for an asked-but-unanswered seed probe.
	if (convergence !== null) return convergence;

	// #974 — step 5c. Every arm that could attribute has declined; before either
	// `third_party` arm below claims distinct infrastructure, check whether the
	// candidate in fact points at the SEED's own web and mail hosts. Applied
	// only where a `third_party` would otherwise be returned (the #929
	// whole-platform `unattributed` arm keeps its own, more specific rationale).
	const infraMatch = seedInfrastructureMatch(input);
	// #974 reopened — step 5d, consulted only when 5c declined. Both share the
	// `seedInfraAssessment` slot: they replace the same `third_party` outcomes.
	const cohortMatch = infraMatch === null ? seedLabelCohortMatch(input) : null;
	const seedInfraAssessment: OwnershipAssessment | null =
		infraMatch !== null
			? {
					verdict: 'unattributed',
					strength: 'none',
					signals: ['seed_infrastructure_match'],
					rationale: `${candidateDomain} does not share ${seedApex}'s nameserver set, but resolves to the same web address set (${infraMatch.a.join(', ')}) and the same mail hosts (${infraMatch.mx.join(', ')}) as ${seedApex} — the shape of the organisation's own brand-variant registration hosted by an agency or platform. Those records are self-published and can be copied, so ownership is not established either way.`,
				}
			: cohortMatch !== null
				? {
						verdict: 'unattributed',
						strength: 'none',
						signals: ['seed_label_cohort'],
						rationale: `${candidateDomain} does not share ${seedApex}'s nameserver set, but resolves to the same web address set (${cohortMatch.a.join(', ')}) as ${seedApex}, and ${cohortMatch.siblings.length} other exact-label variants (${cohortMatch.siblings.join(', ')}) share its identical address set, nameservers (${cohortMatch.ns.join(', ')}) and mail hosts (${cohortMatch.mx.length > 0 ? cohortMatch.mx.join(', ') : 'none'}) — the shape of the organisation's own brand-variant portfolio registered through one agency or registrar. Those records are self-published and can be copied, so ownership is not established either way.`,
					}
				: null;

	// #929 MIRROR — THE POOLED HALF (SQ-36; live anz.com / anz.co.nz, 2026-09-17).
	// On a POOLED provider (`POOLED_SHARED_NS_APEXES`, Akamai: six hostnames drawn
	// from ~128) the set is assigned PER ZONE, so two zones of the SAME account are
	// given DIFFERENT hostnames by design — measured: anz.com holds a1-206, a16-67,
	// a28-67, a7-66, a8-67, a9-67.akam.net; anz.co.nz holds a1-6, a12-66, a28-67,
	// a3-66, a6-65, a9-65.akam.net plus ns1/ns2.anz.co.nz. #929 established that an
	// IDENTICAL set on a UNIFORM platform observes nothing about ownership; the
	// mirror is that a NON-identical set on a POOLED platform observes nothing about
	// DISTINCTNESS: the difference is the provider's per-zone assignment, not the
	// candidate's own infrastructure. Without this arm the block below reports the
	// bank's own NZ domain as "registered to a different organisation" — the exact
	// false claim PR #937's review ruled the `third_party` sentence must never make.
	//
	// A nameserver inside the CANDIDATE's own registrable domain (ns1.anz.co.nz) is
	// a SELF-REFERENCE. Anyone who controls the candidate zone can publish one, so
	// under the OWNERSHIP RULE (see `ClassifyOwnershipInput`) it can never be
	// ownership evidence — and for the identical reason it is not DISTINCTNESS
	// evidence either: it names no operator. It is therefore counted as NEITHER
	// here, never as a signal.
	//
	// THE OUTCOME IS `unattributed`, NEVER `owned_by_seed`. A squatter that hosts
	// its lookalike on the seed's pooled provider gains only the neutral wording
	// every unattributed candidate already carries: the `info` ceiling
	// (`capAttributionSeverity()`) and the separate threat observation are
	// untouched. Any candidate host that is neither on the seed's pooled platform
	// nor self-referential — the squatter's own `ns1.attacker.example` — fails the
	// `every()` below and keeps the candidate out of this arm entirely.
	//
	// SCOPED TO EXACT-LABEL TLD VARIANTS ({@link isExactLabelTldVariant}), the bar
	// step 5d already uses. This is what keeps #929's pinned outcome intact: the
	// UNRELATED bnz.co.nz also sits wholly on Akamai and also shares one pooled
	// host with anz.co.nz, and a character-edit label is the squatter's shape — so
	// that pair stays `third_party` on the arm below. Only the brand's own other
	// TLD reaches this one.
	//
	// MEASURED BLAST RADIUS (63 registered seed/candidate pairs across 20 brands'
	// ccTLD estates, DoH 2026-09-17): two rows move. anz.co.nz `third_party` →
	// `unattributed` (the defect). adobe.fr keeps the same verdict and the same
	// signal and only takes its rationale from here instead of the whole-set arm
	// below — it is an exact-label variant whose hosts are a SUBSET of the seed's
	// Akamai set, so both arms describe it correctly. No pair gains `owned_by_seed`.
	const nsApex = (host: string): string => getRegistrableDomain(host) ?? host;
	const seedPooledApexes = new Set(seedNs.filter((ns) => isPooled(ns)).map(nsApex));
	const onSeedPooledPlatform = (ns: string): boolean => isPooled(ns) && seedPooledApexes.has(nsApex(ns));
	const candidateApex = getRegistrableDomain(normHost(candidateDomain)) ?? normHost(candidateDomain);
	if (
		isExactLabelTldVariant(candidateDomain, input.seedDomain) &&
		seedNs.length > 0 &&
		seedNs.every(onSeedPooledPlatform) &&
		candidateNs.length > 0 &&
		candidateNs.some(onSeedPooledPlatform) &&
		candidateNs.every((ns) => onSeedPooledPlatform(ns) || isInBailiwick(ns, candidateApex))
	) {
		const platformNs = candidateNs.filter(onSeedPooledPlatform);
		const selfNs = candidateNs.filter((ns) => !onSeedPooledPlatform(ns));
		const selfClause = selfNs.length > 0 ? `, plus nameserver(s) inside its own domain (${selfNs.join(', ')})` : '';
		return {
			verdict: 'unattributed',
			strength: 'none',
			signals: ['ns_shared_platform'],
			rationale: `${candidateDomain} is delegated to ${[...seedPooledApexes].join(', ')} (${platformNs.join(', ')})${selfClause} — the same DNS platform ${seedApex} uses, and one that assigns every zone its own hostnames from a shared pool, so two zones held by one account do not match there. Nothing distinct from ${seedApex} was observed, and nothing that identifies the registrant either: this is not ownership evidence in either direction.`,
		};
	}

	// #929 — an overlap that exists but is confined to shared-provider hosts.
	// Neither verdict below moves severity (the third_party / unattributed
	// split is wording only — see the file header); the choice is about what
	// was OBSERVED:
	//  - the candidate's WHOLE set is shared-platform hosts the seed also uses
	//    (one.com `ns01`/`ns02`; or a candidate that carries only the platform
	//    half of a seed that ALSO has its own hosts): the hosts are the
	//    platform's, assigned to every tenant, and NO distinct infrastructure
	//    was seen on the candidate. That is `unattributed` — "no ownership or
	//    third-party signal" — not `third_party`, whose report wording
	//    ("registered to a different organisation") would be a false claim
	//    about the customer's own alias hosted on the same platform (PR #937
	//    review, both rounds). The seed's total does NOT enter this test: the
	//    `third_party` sentence below must be literally true of the CANDIDATE.
	//  - anything else (the 1/6 Akamai partial; a one.com pair PLUS the
	//    squatter's own `ns1.attacker.example`): the candidate's REMAINING
	//    nameservers are distinct from the seed's, so `third_party` is what
	//    was measured, worded for the platform overlap rather than as
	//    "distinct infrastructure".
	if (candidateNs.length > 0 && sharedNs.length > 0 && dedicatedShared.length === 0) {
		const candidateWhollyOnPlatform = sharedNs.length === candidateNs.length;
		if (candidateWhollyOnPlatform) {
			return {
				verdict: 'unattributed',
				strength: 'none',
				signals: ['ns_shared_platform'],
				rationale: `${candidateDomain} delegates only to shared-tenant DNS platform hosts that ${seedApex} also uses (${sharedNs.join(', ')}), which that platform assigns to every customer — platform plumbing, not ownership evidence either way.`,
			};
		}
		if (seedInfraAssessment !== null) return seedInfraAssessment;
		return {
			verdict: 'third_party',
			strength: 'none',
			signals: ['ns_shared_platform'],
			rationale: `${candidateDomain} shares ${sharedNs.length}/${seedTotal} nameservers with ${seedApex} (${sharedNs.join(', ')}), all on a shared-tenant DNS platform that assigns the same hostnames to unrelated customers; its remaining nameservers are distinct from ${seedApex}'s — platform plumbing, not ownership evidence.`,
		};
	}

	if (seedInfraAssessment !== null) return seedInfraAssessment;

	if (candidateNs.length > 0) {
		return {
			verdict: 'third_party',
			strength: 'none',
			signals: ['distinct_infrastructure'],
			rationale: `${candidateDomain} is registered with its own nameservers, distinct from ${seedApex} — this nameserver comparison did not establish common ownership.`,
		};
	}

	return {
		verdict: 'unattributed',
		strength: 'none',
		signals: [],
		rationale: `No ownership or third-party signal could be established for ${candidateDomain}.`,
	};
}
