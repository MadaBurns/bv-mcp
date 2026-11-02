// SPDX-License-Identifier: BUSL-1.1

/** Ownership attribution: seed infrastructure, label-cohort and DMARC-authorised convergence matching. Split verbatim from `../ownership-attribution` (SQ-539). */

import { getRegistrableDomain } from '../public-suffix';
import type { RegistrationState } from '../registration-state';
import { isExactLabelTldVariant, isInBailiwick, normHost } from './hosts';
import {
	MIN_LABEL_COHORT_SIBLINGS,
	SEED_LABEL_COHORT_SHARED_NS_MIN,
	type ClassifyOwnershipInput,
	type LabelCohortMember,
	type OwnershipAssessment,
	type OwnershipEvidence,
} from './types';

/**
 * True when the candidate's RESOLVED real MX set is non-empty and EVERY
 * exchange sits at or under the seed apex (#864). This is the PRE-FILTER for
 * step 5b and nothing more: a sending squatter can publish `MX 10 <seed's
 * MX>` in a self-hosted zone for free and forfeits nothing it wanted, so the
 * predicate carries no verdict weight. It exists so the seed-side probe is
 * issued only for candidates that already look like the seed's own mail
 * estate — a clean scan pays nothing.
 *
 * A single exchange OUTSIDE the seed apex disqualifies the set (a squatter
 * listing the seed's MX alongside its own is not shaped like a same-entity
 * domain at all).
 *
 * Consequence: MX must sit inside the seed's OWN bailiwick, so managed-gateway
 * estates (Proofpoint, Google Workspace, M365, Mimecast, Barracuda — MX in the
 * gateway's bailiwick) never pass, even for the seed's own MX (#1192).
 */
export function mxRoutedIntoSeed(candidateMx: readonly string[] | undefined, seedDomain: string): boolean {
	if (!candidateMx || candidateMx.length === 0) return false;
	const normalisedSeed = normHost(seedDomain);
	const seedApex = getRegistrableDomain(normalisedSeed) ?? normalisedSeed;
	return candidateMx.every((mx) => isInBailiwick(mx, seedApex));
}

/**
 * #974 corroborator bar (step 5c of `classifyOwnership()`). Returns the matched
 * sets when BOTH hold, else `null`:
 *
 *  1. the candidate's A set is non-empty and IDENTICAL to the seed's (same
 *     addresses, same count — an overlap is not enough), AND
 *  2. the candidate's real MX set is non-empty and IDENTICAL to the seed's.
 *
 * Neither leg alone is sufficient: a shared-hosting web IP (one server, many
 * tenants) or a multi-tenant mail provider (Google, M365, a host's antispam
 * relay) is exactly what an UNRELATED tenant of the same platform looks like —
 * the #929 lesson for NS, applied to A and MX. Together, exact web+mail
 * identity is what an SMB's agency-hosted defensive cohort looks like
 * (ltmcguinness.{com,net,co,io,ai} on the agency's NS, all on the seed's A and
 * MX), and what no typosquat running its OWN infrastructure looks like.
 *
 * WHY THE OUTCOME IS `unattributed`, NOT `owned_by_seed` (Ruling A, and the
 * #864 review that rejected candidate MX as verdict-bearing, 931f7b81d): both
 * legs are CANDIDATE-published and cost a squatter nothing to copy, and two
 * unrelated tenants of one platform can match both. So the match cannot earn
 * the ownership verdict — which would lift the attribution ceiling and switch
 * off the threat observation for a squatter who copied the records — but it
 * does falsify the `third_party` arm's "distinct infrastructure / no ownership
 * signal" claim, which is the defect. Severity is unaffected (`third_party` and
 * `unattributed` share the `info` ceiling).
 */
export function seedInfrastructureMatch(input: {
	candidateA?: readonly string[];
	seedA?: readonly string[];
	candidateMx?: readonly string[];
	seedMx?: readonly string[];
}): { a: string[]; mx: string[] } | null {
	const a = identicalNonEmptySet(input.candidateA, input.seedA, (v) => v.trim().toLowerCase());
	if (a === null) return null;
	const mx = identicalNonEmptySet(input.candidateMx, input.seedMx, normHost);
	if (mx === null) return null;
	return { a, mx };
}

function identicalNonEmptySet(
	left: readonly string[] | undefined,
	right: readonly string[] | undefined,
	norm: (v: string) => string,
): string[] | null {
	const l = new Set((left ?? []).map(norm).filter(Boolean));
	const r = new Set((right ?? []).map(norm).filter(Boolean));
	if (l.size === 0 || l.size !== r.size) return null;
	for (const v of l) if (!r.has(v)) return null;
	return [...l].sort();
}

/**
 * #974 (reopened) cohort corroborator bar (step 5d of `classifyOwnership()`).
 * Returns the matched cohort when ALL of these hold, else `null`:
 *
 *  0. the candidate is an EXACT-LABEL TLD variant of the seed: it is itself a
 *     registrable domain, its label equals the seed's, and it is not the seed's
 *     own apex (`ltmcguinness.com` for `ltmcguinness.co.nz`);
 *  1. its A set is IDENTICAL to the seed's non-empty A set;
 *  2. at least {@link MIN_LABEL_COHORT_SIBLINGS} OTHER exact-label variants in
 *     `labelCohort` share the candidate's identical A set, identical complete NS
 *     set and identical MX set, so 3+ variants match;
 *  3. no host in that shared NS set is on a shared-tenant platform
 *     (`isSharedNsHost`, i.e. `SHARED_NS_APEXES`) — UNLESS the exact-label
 *     cohort on the seed's A set (siblings plus the candidate) has at least
 *     {@link SEED_LABEL_COHORT_SHARED_NS_MIN} members, in which case the
 *     shared-NS exclusion is waived (#974 live).
 *
 * WHY: the live cohort (`ltmcguinness.{com,net,co,io,ai}`) sits on the seed's
 * A address but on an agency's NS and a hosting provider's antispam MX, so step
 * 5c's A+MX identity with the SEED never holds. The seed's A alone is not enough
 * either: its PTR is a cloud host and the MX is a host's gateway, so it may be a
 * shared hosting IP (#929's lesson for NS, applied to A). What adds the second
 * signal is the cohort: the exact brand label swept across several TLDs, every
 * one on one identical NS/MX estate AND on the seed's own web address. That is
 * how an organisation's agency registers a defensive portfolio.
 *
 * A TYPOSQUAT NEVER QUALIFIES, as candidate or as sibling: a character edit
 * (`ltmcguiness.com`) is not the exact label, and edited names are what
 * squatters buy. Condition 3 keeps unrelated tenants of one platform (Wix,
 * one.com) from forming a cohort by accident — SMALL cohorts. #974's REOPEN
 * evidence (SQ-23) was itself a live miss: `ltmcguinness`'s cohort is on
 * `siteground.net`, a `SHARED_NS_APEXES` platform, and condition 3 as
 * originally written rejected it outright regardless of cohort size. A
 * cohort of 5+ exact-label variants, all on the seed's A and one identical
 * NS/MX estate, is no longer the accidental 2-3-tenant grouping condition 3
 * exists to catch — it is a brand sweep that happens to be hosted on a
 * shared-tenant registrar. Below {@link SEED_LABEL_COHORT_SHARED_NS_MIN}
 * members, shared-NS candidates are rejected exactly as before.
 *
 * WHY `unattributed`, NOT `owned_by_seed`: every compared record is
 * CANDIDATE-published and free to copy, and a squatter's own portfolio also
 * shares one NS/MX estate. So, as with step 5c (Ruling A), the match can only
 * falsify the `third_party` arm's "distinct infrastructure / no ownership signal"
 * claim. It never earns ownership, never lifts the attribution ceiling, and
 * never moves severity — whatever the cohort size.
 */
export function seedLabelCohortMatch(input: {
	seedDomain: string;
	candidateDomain: string;
	registration: RegistrationState;
	isSharedNsHost: (nsHost: string) => boolean;
	candidateA?: readonly string[];
	seedA?: readonly string[];
	candidateMx?: readonly string[];
	labelCohort?: readonly LabelCohortMember[];
}): { a: string[]; ns: string[]; mx: string[]; siblings: string[] } | null {
	if (input.registration.state !== 'registered' || input.candidateMx === undefined || !input.labelCohort?.length) return null;
	const isExactLabelVariant = (domain: string): boolean => isExactLabelTldVariant(domain, input.seedDomain);
	const candidate = normHost(input.candidateDomain);
	if (!isExactLabelVariant(candidate)) return null;

	const a = identicalNonEmptySet(input.candidateA, input.seedA, (v) => v.trim().toLowerCase());
	if (a === null) return null;
	const ns = [...new Set(input.registration.ns.map(normHost).filter(Boolean))].sort();
	if (ns.length === 0) return null;
	const mx = [...new Set(input.candidateMx.map(normHost).filter(Boolean))].sort();

	const siblings = input.labelCohort
		.filter(
			(member) =>
				normHost(member.domain) !== candidate &&
				isExactLabelVariant(member.domain) &&
				identicalNonEmptySet(member.a, a, (v) => v.trim().toLowerCase()) !== null &&
				identicalNonEmptySet(member.ns, ns, normHost) !== null &&
				identicalSet(member.mx, mx),
		)
		.map((member) => normHost(member.domain))
		.sort();

	// #974 — condition 3 (no shared-tenant NS host) is waived only for a
	// large-enough cohort: siblings.length + 1 counts the candidate itself.
	// Below SEED_LABEL_COHORT_SHARED_NS_MIN, a shared-platform NS set behaves
	// exactly as before — the #929 guard against an accidental small grouping
	// of unrelated platform tenants stays in force.
	if (ns.some((host) => input.isSharedNsHost(host)) && siblings.length + 1 < SEED_LABEL_COHORT_SHARED_NS_MIN) return null;

	return siblings.length >= MIN_LABEL_COHORT_SIBLINGS ? { a, ns, mx, siblings } : null;
}

/** Set identity that, unlike {@link identicalNonEmptySet}, treats two measured-empty sets as identical. */
function identicalSet(left: readonly string[], right: readonly string[]): boolean {
	return right.length === 0 ? left.map(normHost).filter(Boolean).length === 0 : identicalNonEmptySet(left, right, normHost) !== null;
}

/**
 * Extract the domain part of every `rua=` / `ruf=` `mailto:` destination in a
 * DMARC record (RFC 7489 §6.3), lowercased, deduplicated, in order of first
 * appearance. Size suffixes (`!10m`) and non-mailto URIs are dropped. Pure;
 * exported for direct unit testing and for `probeDmarcReportAuthorisation()`.
 */
export function parseDmarcReportReceivers(dmarcRecord: string): string[] {
	const out: string[] = [];
	for (const rawTag of dmarcRecord.split(';')) {
		const eq = rawTag.indexOf('=');
		if (eq === -1) continue;
		const key = rawTag.slice(0, eq).trim().toLowerCase();
		if (key !== 'rua' && key !== 'ruf') continue;
		for (const uri of rawTag.slice(eq + 1).split(',')) {
			const trimmed = uri.trim();
			if (!/^mailto:/i.test(trimmed)) continue;
			const mailbox = trimmed.slice('mailto:'.length).split('!')[0];
			const at = mailbox.lastIndexOf('@');
			if (at === -1) continue;
			const domain = normHost(mailbox.slice(at + 1));
			if (domain && !out.includes(domain)) out.push(domain);
		}
	}
	return out;
}

/**
 * Registrable apexes of DMARC report-PROCESSING services — organisations that
 * publish the RFC 7489 §7.1 `<domain>._report._dmarc.<receiver>` grant for
 * EVERY customer domain as a matter of business, so a grant under one of
 * these apexes says "customer", never "same owner". When the SEED apex is one
 * of these, step 5b declines (evidence-only) — the same defence
 * `SHARED_NS_APEXES` / `isSharedNsHost` gives the NS arms. Consulted for the
 * seed apex only, so an entry here can only ever WITHHOLD an attribution.
 * Add conservatively; a missing processor merely leaves the provider-class
 * residual documented in the file header.
 */
export const DMARC_REPORT_PROCESSOR_APEXES: ReadonlySet<string> = new Set([
	'agari.com',
	'valimail.com',
	'dmarcian.com',
	'ondmarc.com',
	'redsift.com',
	'proofpoint.com',
	'dmarcanalyzer.com',
	'mimecast.com',
	'easydmarc.com',
	'powerdmarc.com',
	'dmarcly.com',
	'sendmarc.com',
	'fraudmarc.com',
	'uriports.com',
	'mailhardener.com',
	'postmarkapp.com',
	'mxtoolbox.com',
	'dmarcdigests.com',
]);

/** True when `apex` (already a registrable domain) is a known DMARC report-processing service — see {@link DMARC_REPORT_PROCESSOR_APEXES}. */
export function isDmarcReportProcessorApex(apex: string): boolean {
	const host = normHost(apex);
	if (!host) return false;
	return DMARC_REPORT_PROCESSOR_APEXES.has(getRegistrableDomain(host) ?? host);
}

/**
 * Step 5b of `classifyOwnership()` — the #864 seed-authorised convergence
 * arm. Returns `null` when the arm has nothing to say (pre-filter unmet,
 * inputs absent, or no seed-published grant), an `owned_by_seed` assessment
 * when the seed has published the per-domain RFC 7489 §7.1 authorisation, or
 * an `unmeasured` assessment when the pre-filter held but the seed-side probe
 * rejected. Never returns `third_party`: declining is the caller's job, from
 * seed-side NS evidence.
 */
export function assessSeedAuthorisedConvergence(
	input: ClassifyOwnershipInput,
	candidateDomain: string,
	seedApex: string,
): OwnershipAssessment | null {
	if (!mxRoutedIntoSeed(input.candidateMx, seedApex)) return null;
	const auth = input.dmarcReportAuthorisation;
	if (auth === undefined) return null;
	// A seed that is itself a DMARC report PROCESSOR publishes the §7.1 grant
	// for every customer, so the grant carries no ownership information there
	// (mirrors `isSharedNsHost` for the NS arms). Evidence-only: decline.
	if (isDmarcReportProcessorApex(seedApex)) return null;

	const mx = (input.candidateMx ?? []).map(normHost).filter(Boolean);
	const mxEvidence: OwnershipEvidence[] = mx.map((value) => ({ record: 'MX' as const, value, inSeedBailiwick: true }));

	// ONLY a SEED-zone lookup failure is a measurement gap. `candidate_unresolved`
	// (the attacker-controlled `_dmarc.<candidate>` lookup rejected) falls
	// through below with every other non-grant status — see the status docs.
	if (auth.status === 'unresolved') {
		return {
			verdict: 'unmeasured',
			strength: 'none',
			signals: ['mx_in_bailiwick'],
			rationale: `${candidateDomain} routes its mail to ${mx.join(', ')} inside ${seedApex}, but the lookup that would show whether ${seedApex} has authorised DMARC reporting for it did not resolve this run. This is a measurement gap, not evidence of third-party registration — re-run to attribute.`,
			evidence: mxEvidence,
		};
	}
	if (auth.status !== 'authorised' || !auth.receiverDomain || !auth.authorisationRecord) return null;

	const receiver = normHost(auth.receiverDomain);
	const record = normHost(auth.authorisationRecord);
	// Defence in depth: the probe already filtered receivers to the seed apex,
	// but the verdict must never rest on a grant published OUTSIDE it.
	if (!isInBailiwick(receiver, seedApex) || !isInBailiwick(record, seedApex)) return null;

	return {
		verdict: 'owned_by_seed',
		strength: 'medium',
		signals: ['mx_in_bailiwick', 'dmarc_report_authorised_by_seed'],
		rationale: `${seedApex} has published a DMARC external-report authorisation for ${candidateDomain} (${record} = v=DMARC1, RFC 7489 §7.1) — a record only the owner of ${receiver} can create — and ${candidateDomain} routes its mail to ${mx.join(', ')} inside ${seedApex}.`,
		evidence: [
			...mxEvidence,
			{ record: 'DMARC.RUA', value: receiver, inSeedBailiwick: true },
			{ record: 'DMARC.REPORT_AUTHORISATION', value: record, inSeedBailiwick: true },
		],
	};
}
