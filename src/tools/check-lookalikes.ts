// SPDX-License-Identifier: BUSL-1.1

/**
 * Lookalike domain detection tool.
 * Generates typosquat/lookalike domain permutations and checks for
 * active DNS registrations and mail infrastructure.
 * Standalone check — not included in scan_domain due to query volume.
 */

import { queryDnsRecords, queryMxRecords } from '../lib/dns';
import type { QueryDnsOptions } from '../lib/dns-types';
import { callReconScan, isReconHit } from '../lib/recon-binding';
import { safeFetch } from '../lib/safe-fetch';
import type { ReconBinding, BindingDegradationSink, ReconScanResult } from '../lib/recon-binding';
import type { CheckResult, Finding } from '../lib/scoring';
import { buildCheckResult, createFinding } from '../lib/scoring';
import { generateCognitiveLookalikes, generateCombosquats, generateLookalikes } from './lookalike-analysis';
import { FALLBACK_RDAP_SERVERS, extractRegistrantOrg, findEntityByRole, isRedactedRegistrantOrg } from './check-rdap-lookup';
import { evaluateDefensiveRegistration, type DefensiveReason } from '../lib/brand-defensive-registration';
import { calibrateLookalikeSeverity, isDisposableMxHost, type LookalikeSeverity, type LookalikeSignals } from './lookalike-severity';
import {
	buildNonOwnedGateFinding,
	capAttributionSeverity,
	classifyOwnership,
	type OwnershipAssessment,
	type OwnershipVerdict,
} from '../lib/ownership-attribution';
import { isSharedNsHost } from '../tenants/discovery/shared-ns-hosts';
import { extractBrandName } from '../lib/public-suffix';

/**
 * TASK 7B TWO-AXIS SPLIT (human-partner ruling, 2026-07-27).
 *
 * This tool reports on TWO independent axes, and every finding it emits
 * declares which one it belongs to via `metadata.findingAxis`:
 *
 *  - `'attribution'` — WHO owns the candidate. Governed by
 *    `classifyOwnership()` + `capAttributionSeverity()`: every non-
 *    `owned_by_seed` verdict is capped at `info` with neutral wording
 *    (D4's load-bearing safety property — the scanner never claims someone
 *    else's domain is the customer's, and never demands the customer act on
 *    a domain it does not control). UNCHANGED by this task.
 *
 *  - `'threat_observation'` — WHAT the candidate is doing. Carries the #264
 *    calibrated severity from `calibrateLookalikeSeverity()`. Task 7 computed
 *    that severity and then capped it away, which made `highCount`, the HIGH
 *    summary finding, and every sub-100 `lookalikes` category score
 *    unreachable — a live typosquat with active MX on a disposable provider
 *    scored 100/passed. These findings assert NOTHING about ownership (they
 *    say explicitly that the domain does not appear to belong to the scanned
 *    organisation) and demand no action ON that domain; only defensive
 *    options on the scanned organisation's own side are suggested.
 *
 *  - `'scan_status'` — the RUN itself, not any candidate: the "no active
 *    lookalike domains detected" notices and the timeout notice. Always
 *    `info`. Split out in fix round 1 (F2) because forcing these into
 *    `'threat_observation'` made the threat-axis invariants below unstateable.
 *
 * INVARIANTS (true of this file, pinned by `test/check-lookalikes.spec.ts`, and
 * what Task 8's cross-cutting audit will key on):
 *   1. every finding carries one of the three literals;
 *   2. every `'scan_status'` finding is `info`;
 *   3. no `'threat_observation'` finding carries `ownershipVerdict ===
 *      'owned_by_seed'` — a threat observation is never about a domain the
 *      scanned organisation owns;
 *   4. every `'threat_observation'` finding names the candidate it observed via
 *      `lookalikeDomain` (per candidate, INCLUDING the named-candidate recon CT
 *      corroboration) or `lookalikeDomains` (the aggregate summary). Bare
 *      `domain` metadata (scoped to the scanned domain, not a candidate) only
 *      ever appears on the demoted `'scan_status'` finding emitted when recon
 *      names no specific candidate — never on a `'threat_observation'` finding.
 *
 * The axis marker is STRUCTURAL, not prose: downstream consumers (and Task
 * 8's cross-cutting audit) key on the exact literals, never on wording.
 */
export type LookalikeFindingAxis = 'attribution' | 'threat_observation' | 'scan_status';

/** Default and minimum batch sizes for adaptive batching */
export const INITIAL_BATCH_SIZE = 10;
export const MIN_BATCH_SIZE = 3;
export const BACKOFF_DELAY_MS = 500;
export const FAILURE_THRESHOLD = 2;

/** Maximum wall-clock time for the entire lookalike check (ms). */
const LOOKALIKE_TIMEOUT_MS = 20_000;

/** Canary label used for wildcard detection on parent domains */
export const WILDCARD_CANARY_LABEL = '_bv-wc-probe';

/** Lean DNS options for Phase 1 existence checks — fast, no retries, no secondary confirmation. */
export const PHASE1_DNS_OPTS: QueryDnsOptions = {
	timeoutMs: 2000,
	retries: 0,
	skipSecondaryConfirmation: true,
};

interface LookalikeResult {
	domain: string;
	hasA: boolean;
	hasMX: boolean;
	/** MX exchange hosts (lowercased, trailing-dot-stripped) — empty when no real MX. */
	mxExchanges: string[];
}

/** Budgets for the Defect L enrichment probes. Both are intentionally tight so 12 candidates × (RDAP + HEAD) stays under LOOKALIKE_TIMEOUT_MS. */
const RDAP_PROBE_TIMEOUT_MS = 2500;
const WEB_PROBE_TIMEOUT_MS = 2500;

/**
 * Cap on the number of medium/high-severity lookalikes for which we attempt
 * the same-entity (shared-registrant) RDAP correlation. RDAP registrant data
 * is already harvested from the single enrichment fetch per candidate
 * ({@link probeRdap}), so the cost is bounded by the enrichment set; this cap
 * is a defensive ceiling so a pathological permutation explosion can't widen
 * the RDAP fan-out beyond the lookalike check's wall-clock budget. Ordered by
 * severity (high before medium) so the most damaging false-positives are
 * corrected first when the cap binds.
 */
const SAME_ENTITY_RDAP_CAP = 10;

/**
 * IANA registrar IDs of BRAND-PROTECTION registrars — corporate registrars
 * that do not sell to the general public. Getting a domain registered through
 * one requires a corporate account and a contract; you cannot buy a name at
 * CSC or MarkMonitor the way you can at a retail registrar.
 *
 * WHY THIS IS DIFFERENT FROM THE REGISTRANT-ORG FIELD (and therefore why it is
 * allowed to corroborate ownership at all). Ruling A / F2 bars the registrant
 * org from influencing attribution because it is free text the REGISTRANT
 * types — forgeable with one form field, and collision-prone because half the
 * internet sits behind the same privacy services. The IANA registrar ID is
 * neither: it is assigned by ICANN and published by the REGISTRY as part of
 * the delegation record. A registrant cannot set it, and cannot move a domain
 * into a corporate registrar's accreditation without that registrar's consent.
 *
 * It is still NOT proof of common ownership — many brands share CSC — which is
 * why {@link isBrandHeldRegistration} requires the candidate's INFRASTRUCTURE
 * to be defensively shaped as well, and why nothing here can ever produce an
 * `owned_by_seed` verdict (that remains seed-side NS evidence only).
 *
 * RETAIL REGISTRARS MUST NEVER BE ADDED. GoDaddy (146), Namecheap (1068) and
 * friends are shared by millions of unrelated registrants, so a shared-retail-
 * registrar match carries no identity information whatsoever. A control test
 * pins that GoDaddy is not treated as evidence.
 */
const BRAND_PROTECTION_REGISTRAR_IANA_IDS: ReadonlySet<string> = new Set([
	'299', // CSC Corporate Domains, Inc.
	'292', // MarkMonitor Inc.
	'470', // Com Laude (Nom-IQ Ltd)
	'447', // SafeNames Ltd
	'1600', // Brandsight, Inc.
	'106', // Ascio Technologies (corporate channel)
	'1316', // Nameshield SAS
	'1495', // EBRAND Services
	'151', // Gandi SAS — corporate/enterprise channel
	'1479', // In2net / brand-protection channel
]);

/**
 * Human phrasing for a {@link DefensiveReason} token. Internal enum values are
 * meaningless in a customer-facing report about a named organisation — the
 * same rule `UNKNOWN_REASON_PHRASES` exists for in `registration-state.ts`.
 *
 * WORDING CONSTRAINT: none of these may contain `missing`, `required`,
 * `not found`, or the `no <...> record` shape. `scoreIndicatesMissingControl()`
 * in the vendored scoring package matches finding TEXT, and a match on a
 * high-severity finding ZEROES the whole category score — the one way a
 * wording change in this file could move a number. Pinned by a boundary test.
 */
export const DEFENSIVE_REASON_PHRASES: Record<DefensiveReason, string> = {
	'redirect-to-target': 'its web root redirects back to the scanned domain',
	'parked-ns': 'its nameservers are at a domain-parking provider',
	'no-mx': 'it carries no active mail service',
};

/**
 * Check whether an MX record represents real mail infrastructure.
 *
 * RFC 7505 defines the canonical null MX as priority-0 with exchange `.` (root),
 * meaning "this domain does not accept mail". A legacy convention used by some
 * operators is `0 localhost.` (or `0 localhost`), which has the same intent —
 * mail is null-routed to the sender's own localhost and is functionally rejected.
 * Both patterns must be excluded from the "has mail infrastructure" signal to
 * avoid false-positive HIGH typosquat findings on domains that have applied the
 * recommended anti-spoofing posture.
 */
function isRealMxRecord(data: string): boolean {
	const trimmed = data.trim().toLowerCase();
	// Format from queryDnsRecords is "<priority> <target>", possibly with trailing dot.
	const match = trimmed.match(/^(\d+)[\s\t]+(.*?)\.?$/);
	if (!match) return true;
	const [, priority, target] = match;
	if (priority !== '0') return true;
	return target !== '' && target !== 'localhost';
}

/**
 * Extract the lowercase exchange host from an MX record `"<priority> <target>"`.
 * Returns `null` when the record fails to parse or is a null MX. Used to feed
 * the disposable-MX detector in {@link calibrateLookalikeSeverity}.
 */
function extractMxExchange(raw: string): string | null {
	const trimmed = raw.trim().toLowerCase();
	const match = trimmed.match(/^(\d+)[\s\t]+(.*?)\.?$/);
	if (!match) return null;
	const [, , target] = match;
	if (target === '' || target === 'localhost') return null;
	return target;
}

/**
 * Check a single lookalike domain for DNS and MX records.
 * Filters out null MX records (RFC 7505) to avoid false positives.
 */
async function probeLookalike(domain: string): Promise<LookalikeResult> {
	const [aRecords, mxRecords] = await Promise.allSettled([queryDnsRecords(domain, 'A'), queryDnsRecords(domain, 'MX')]);

	const realMxRecords = mxRecords.status === 'fulfilled' ? mxRecords.value.filter(isRealMxRecord) : [];
	const mxExchanges = realMxRecords.map(extractMxExchange).filter((host): host is string => host !== null);

	return {
		domain,
		hasA: aRecords.status === 'fulfilled' && aRecords.value.length > 0,
		hasMX: realMxRecords.length > 0,
		mxExchanges,
	};
}

/**
 * Count the number of labels (dot-separated segments) in a domain.
 */
function labelCount(domain: string): number {
	return domain.split('.').length;
}

/**
 * Extract the parent domain from a dot-insertion permutation.
 * E.g., "blackve.ilsecurity.com" → "ilsecurity.com"
 */
function getParentDomain(domain: string): string {
	const parts = domain.split('.');
	return parts.slice(1).join('.');
}

/**
 * Detect wildcard DNS on a set of parent domains by probing a canary subdomain.
 * Returns a Set of parent domains that have wildcard A records.
 */
async function detectWildcardParents(parentDomains: string[]): Promise<Set<string>> {
	const wildcardParents = new Set<string>();
	const probes = parentDomains.map(async (parent) => {
		try {
			const canary = `${WILDCARD_CANARY_LABEL}.${parent}`;
			const records = await queryDnsRecords(canary, 'A');
			if (records.length > 0) {
				wildcardParents.add(parent);
			}
		} catch {
			// Query failed — not a wildcard
		}
	});
	await Promise.allSettled(probes);
	return wildcardParents;
}

/**
 * Phase 1: Fast NS existence check for all domains in parallel.
 * Returns only domains that have NS records (i.e., are registered),
 * along with their normalized NS record data for ownership comparison.
 */
async function filterByNsExistence(domains: string[]): Promise<{ registered: string[]; nsMap: Map<string, Set<string>> }> {
	const nsMap = new Map<string, Set<string>>();
	const results = await Promise.allSettled(
		domains.map(async (domain) => {
			const ns = await queryDnsRecords(domain, 'NS', PHASE1_DNS_OPTS);
			if (ns.length > 0) {
				nsMap.set(domain, normalizeNsSet(ns));
			}
			return { domain, hasNs: ns.length > 0 };
		}),
	);
	const registered = results
		.filter((r): r is PromiseFulfilledResult<{ domain: string; hasNs: boolean }> => r.status === 'fulfilled' && r.value.hasNs)
		.map((r) => r.value.domain);
	return { registered, nsMap };
}

/**
 * Normalize a set of NS record values for comparison.
 * Strips trailing dots, lowercases, and returns a Set.
 */
function normalizeNsSet(nsRecords: string[]): Set<string> {
	return new Set(nsRecords.map((ns) => ns.replace(/\.$/, '').toLowerCase()));
}

/**
 * Query NS records for the primary domain to use for ownership comparison.
 * Returns an empty set if the query fails.
 */
async function queryPrimaryNs(domain: string): Promise<Set<string>> {
	try {
		const ns = await queryDnsRecords(domain, 'NS', PHASE1_DNS_OPTS);
		return normalizeNsSet(ns);
	} catch {
		return new Set<string>();
	}
}

/**
 * Query MX records for the primary domain — the D4 (2026-07-26
 * correctness-defects design) MX-overlap corroboration signal for
 * `attributionConfidence()`. Fail-soft: an empty set just means the guard
 * falls back to "no corroboration" rather than throwing.
 */
async function queryPrimaryMx(domain: string): Promise<Set<string>> {
	try {
		const mx = await queryMxRecords(domain, PHASE1_DNS_OPTS);
		return new Set(mx.map((r) => r.exchange.toLowerCase().replace(/\.$/, '')));
	} catch {
		return new Set<string>();
	}
}

/**
 * AXIS 1 (attribution) ONLY — Task 7b. This caps what the report may CLAIM
 * about ownership; it does not and must not cap what the report may say was
 * OBSERVED. The observed-threat severity now travels on a separate finding
 * built by {@link buildThreatObservationFinding}, so capping here no longer
 * makes `highCount`, the HIGH summary finding, and every sub-100 `lookalikes`
 * category score unreachable (the defect the opus review found in Task 7).
 *
 * D4 severity ceiling for a lookalike finding, mirroring `applyOwnershipGate()`
 * in `check-shadow-domains.ts` — see that file's JSDoc for the full rationale;
 * this is the same pattern reused for a second tool so the two stay
 * consistent for downstream consumers. The neutral-wording sentence and
 * metadata shape live in `buildNonOwnedGateFinding()`
 * (`src/lib/ownership-attribution.ts`), shared with `check-shadow-domains.ts`
 * (fix round 2, F1) — the two tools had already drifted apart within this
 * slice when each hand-rolled its own copy.
 *
 * `owned_by_seed` findings pass through unclamped — `checkLookalikesCore`'s
 * main loop already emits its own dedicated "likely owned by same entity"
 * finding for that verdict before this function is ever reached, so in
 * practice every call here receives a non-owned verdict. The passthrough
 * branch exists anyway so the invariant is explicit and enforced at this
 * chokepoint rather than merely assumed by the caller.
 *
 * DEMOTE, NEVER DELETE (binding ruling): this returns a `Finding`, never
 * `null`/`undefined` — a real measurement (an active registration with
 * MX/A records) is never suppressed, only its severity capped and its
 * wording made neutral. `attributionConfidence()` governs WORDING/CONFIDENCE
 * ONLY; it can never move the ceiling, which `capAttributionSeverity()`
 * derives from `ownership.verdict` alone.
 */
function applyOwnershipGate(finding: Finding, ownership: OwnershipAssessment, brand: string, corroborated: boolean): Finding {
	const ceiling = capAttributionSeverity(ownership.verdict);
	if (ceiling === 'unbounded') return finding;

	// `calibrateLookalikeSeverity()` never returns `'info'`, so unlike
	// `check-shadow-domains.ts` there is no local info-severity branch here —
	// every candidate reaching this point goes through the shared non-owned
	// rewrite. `postureNoun` MUST match `check-shadow-domains.ts`'s value
	// byte-for-byte (parity pinned by `test/ownership-attribution.spec.ts`).
	return buildNonOwnedGateFinding(finding, ownership, brand, corroborated, ceiling, {
		category: 'lookalikes',
		domainMetadataKey: 'lookalikeDomain',
		postureNoun: 'DNS/mail posture',
	});
}

/**
 * AXIS 2 — build the observed-threat finding for a NON-OWNED candidate
 * (Task 7b). Carries the #264 calibrated severity verbatim; the attribution
 * finding built by {@link applyOwnershipGate} carries the `info` cap.
 *
 * WORDING CONTRACT (customer-facing, legal-sensitive — BlackVeil names real
 * third-party organisations in reports). The text:
 *  - states only what was OBSERVED (MX/A presence, registration recency,
 *    disposable MX, absent web content) — no claim of intent.
 *    "Impersonation-shaped" / "consistent with pre-phishing staging" is the
 *    ceiling; the words "malicious"/"attacker" are deliberately absent;
 *  - says EXPLICITLY that the domain does not appear to belong to the scanned
 *    organisation, so no reader can mistake this for an ownership claim;
 *  - never uses "your", "shadow domain", or any ownership/control framing;
 *  - demands no action ON the observed domain. Only defensive options that
 *    need no access to it (monitor, block at the gateway, report for
 *    takedown) are offered.
 *
 * Pinned by `test/check-lookalikes.spec.ts`'s Task 7b block, which asserts
 * both the positive wording and the banned-framing negatives on title AND
 * detail (a split surface — right severity, ownership-framed prose — is the
 * failure mode that bit Task 6's first review pass).
 */
function buildThreatObservationFinding(
	candidateDomain: string,
	seedDomain: string,
	severity: LookalikeSeverity,
	signals: LookalikeSignals,
	ownership: OwnershipAssessment,
	corroboratorReasons: string,
	sharedRegistrantOrg: string | undefined,
	/**
	 * True when {@link isBrandHeldRegistration} corroborated that the candidate
	 * is the scanned organisation's OWN defensive registration. Changes the
	 * closing REMEDIATION sentence only — the observation and its calibrated
	 * severity are emitted unchanged, per the F1 ruling that an attribution
	 * signal may annotate the threat axis but never switch it off or discount
	 * it. Telling a customer to report their own domain for takedown is not a
	 * severity question; it is simply wrong advice.
	 */
	brandHeld = false,
): Finding {
	const infraPhrase = signals.hasMX
		? `active mail infrastructure (MX records), so it is capable of sending mail that resembles ${seedDomain}`
		: 'web infrastructure (A records) and no active mail infrastructure';
	const observed = corroboratorReasons ? `${infraPhrase}; also observed: ${corroboratorReasons}` : infraPhrase;
	// FIX ROUND 1 (F1): when the #263 correlation found a shared registrant-org
	// string, it is RECORDED here — as an unverified observation — but it does
	// NOT reduce the severity and does not suppress this finding. An org string
	// anyone can type into a registrar form earns a sentence, not a discount.
	const registrantNote = sharedRegistrantOrg
		? ` Its RDAP registrant-organisation string matches the one published for ${seedDomain} ("${sharedRegistrantOrg}"); that field is self-declared, unverified by the registry, and frequently a shared privacy-service placeholder, so it is recorded but does not reduce what was observed here.`
		: '';
	// The attribution clause and the closing remediation clause both assume the
	// candidate is an outside party's. When the registration record corroborates
	// that it is the scanned organisation's OWN defensive registration, both are
	// replaced — the observation itself and its calibrated severity are
	// untouched, so nothing here moves a score.
	const attributionClause = brandHeld
		? `the registry publishes the same brand-protection registrar for it as for ${seedDomain}, so it is most likely the scanned organisation's own defensive registration`
		: `${candidateDomain} does not appear to belong to the scanned organisation, this finding claims no control over it, and no change to it is requested`;
	const remediationClause = brandHeld
		? `Because this looks like your own defensive registration, treat it as portfolio hygiene rather than a threat: confirm it against your domain portfolio, and keep it parked with mail explicitly disabled so it cannot be used to send. Do NOT report it for takedown without confirming ownership first.`
		: `Defensive options that need no access to ${candidateDomain}: monitor it, block or quarantine mail bearing that name at the gateway, and report it to its registrar or a takedown provider.`;
	return createFinding(
		'lookalikes',
		`Impersonation-shaped ${signals.hasMX ? 'infrastructure' : 'web infrastructure'} observed: ${candidateDomain}`,
		severity,
		`${candidateDomain} is a confusable variant of ${seedDomain} and was observed with ${observed}. This is an infrastructure observation only: ${attributionClause}.${registrantNote} ${remediationClause}`,
		{
			...(brandHeld ? { brandHeldRegistration: true } : {}),
			lookalikeDomain: candidateDomain,
			hasA: signals.hasA,
			hasMX: signals.hasMX,
			registrationDays: signals.registrationDays,
			mxOnDisposable: signals.mxOnDisposable,
			hasWebContent: signals.hasWebContent,
			findingAxis: 'threat_observation' satisfies LookalikeFindingAxis,
			// The verdict travels on EVERY classified finding, threat axis
			// included, so a consumer can read "high observed threat, NOT owned by
			// the customer" off a single object rather than correlating two.
			ownershipVerdict: ownership.verdict,
			...(sharedRegistrantOrg ? { sharedRegistrantOrg } : {}),
		},
	);
}

/**
 * Run permutation probes with adaptive batch sizing and backoff.
 * Starts at INITIAL_BATCH_SIZE, halves on repeated failures (floor at MIN_BATCH_SIZE),
 * recovers on clean batches.
 */
async function probeWithAdaptiveBatching(permutations: string[]): Promise<PromiseSettledResult<LookalikeResult>[]> {
	const allResults: PromiseSettledResult<LookalikeResult>[] = [];
	let batchSize = INITIAL_BATCH_SIZE;
	let delayMs = 0;

	for (let i = 0; i < permutations.length; i += batchSize) {
		if (delayMs > 0) {
			await new Promise((resolve) => setTimeout(resolve, delayMs));
		}

		const batch = permutations.slice(i, i + batchSize);
		const batchResults = await Promise.allSettled(batch.map((d) => probeLookalike(d)));
		allResults.push(...batchResults);

		// Count failures in this batch
		const failures = batchResults.filter((r) => r.status === 'rejected').length;
		if (failures > FAILURE_THRESHOLD) {
			// Back off: halve batch size (floor to MIN_BATCH_SIZE) and add delay
			batchSize = Math.max(MIN_BATCH_SIZE, Math.floor(batchSize / 2));
			delayMs = BACKOFF_DELAY_MS;
		} else if (delayMs > 0 && failures === 0) {
			// Recover: if a clean batch after backoff, try increasing again
			batchSize = Math.min(INITIAL_BATCH_SIZE, batchSize + 2);
			delayMs = 0;
		}
	}

	return allResults;
}

/**
 * Detect registered lookalike/typosquat domains with DNS or mail infrastructure.
 * Generates domain permutations and checks for active registrations using adaptive batching.
 * Filters out false positives from wildcard DNS on parent domains and null MX records.
 */
/**
 * Extract a specific candidate domain bv-recon's CT_LOOKALIKE hit names, if
 * any (fix round 1, F1). The check response schema's only extension point
 * for this is the passthrough `metadata` bag (`ReconScanResponseSchema` in
 * `../lib/recon-binding`); a `matchedDomain` string there is treated as the
 * named candidate. Defensively normalised (trim/lowercase/strip trailing
 * dot); rejected outright — returns `null` rather than the seed — when it is
 * empty or equal to the SEED domain itself, so a recon response that merely
 * echoes the query target can never satisfy the threat-observation naming
 * invariant without actually naming a distinct candidate.
 */
export function extractReconMatchedDomain(reconResult: ReconScanResult, seedDomain: string): string | null {
	const raw = reconResult.metadata?.matchedDomain;
	if (typeof raw !== 'string') return null;
	const normalized = raw.trim().toLowerCase().replace(/\.$/, '');
	const seedNormalized = seedDomain.trim().toLowerCase().replace(/\.$/, '');
	if (normalized === '' || normalized === seedNormalized) return null;
	return normalized;
}

export async function checkLookalikes(
	domain: string,
	reconOptions: { reconBinding?: ReconBinding; reconAuthToken?: string; onBindingDegradation?: BindingDegradationSink } = {},
): Promise<CheckResult> {
	return Promise.race([
		checkLookalikesCore(domain, reconOptions),
		new Promise<never>((_, reject) => setTimeout(() => reject(new Error('Lookalike check timed out')), LOOKALIKE_TIMEOUT_MS)),
	]).catch(() => {
		const result = buildCheckResult('lookalikes', [
			createFinding(
				'lookalikes',
				'Lookalike check incomplete',
				'info',
				'Lookalike check did not complete within the time limit. Results may be incomplete — try again shortly.',
				{ findingAxis: 'scan_status' satisfies LookalikeFindingAxis },
			),
		]);
		// Mark as partial so callers can skip caching
		result.partial = true;
		return result;
	});
}

async function checkLookalikesCore(
	domain: string,
	reconOptions: { reconBinding?: ReconBinding; reconAuthToken?: string; onBindingDegradation?: BindingDegradationSink } = {},
): Promise<CheckResult> {
	const findings: Finding[] = [];
	// THREE disjoint candidate lanes, deduped into one set that flows through the
	// same NS-existence → probe → enrich → severity pipeline:
	//
	//  - `generateLookalikes` — MOTOR errors (keyboard adjacency, omission,
	//    duplication, dot insertion, TLD swap, homoglyph): a slip of the finger
	//    by someone who knows the correct spelling.
	//  - `generateCognitiveLookalikes` — COGNITIVE errors: the spelling a large
	//    population believes IS correct (`sketchers`, `berenstein`), typed
	//    deliberately and repeatedly. The motor set cannot reach these except by
	//    coincidence, so before this lane existed they were simply never probed.
	//  - `generateCombosquats` — brand + lure affix, which defeats edit distance
	//    entirely.
	//
	// Each lane carries its OWN cap, so adding one can never evict another's
	// candidates through a shared truncation.
	const permutations = [
		...new Set([...generateLookalikes(domain), ...generateCognitiveLookalikes(domain), ...generateCombosquats(domain)]),
	];

	if (permutations.length === 0) {
		findings.push(
			createFinding(
				'lookalikes',
				'No active lookalike domains detected',
				'info',
				`No lookalike domain permutations could be generated for ${domain}.`,
				{ findingAxis: 'scan_status' satisfies LookalikeFindingAxis },
			),
		);
		return buildCheckResult('lookalikes', findings);
	}

	// Identify dot-insertion permutations (they have more labels than the original domain)
	const originalLabelCount = labelCount(domain);
	const dotInsertionParents = new Map<string, string[]>(); // parent → [permutations]
	const nonDotInsertionPerms: string[] = [];

	for (const perm of permutations) {
		if (labelCount(perm) > originalLabelCount) {
			const parent = getParentDomain(perm);
			const existing = dotInsertionParents.get(parent);
			if (existing) {
				existing.push(perm);
			} else {
				dotInsertionParents.set(parent, [perm]);
			}
		} else {
			nonDotInsertionPerms.push(perm);
		}
	}

	// Detect wildcard DNS on parent domains of dot-insertion permutations
	const wildcardParents = dotInsertionParents.size > 0 ? await detectWildcardParents([...dotInsertionParents.keys()]) : new Set<string>();

	// Filter out permutations whose parent has wildcard DNS
	const filteredDotInsertionPerms: string[] = [];
	for (const [parent, perms] of dotInsertionParents) {
		if (!wildcardParents.has(parent)) {
			filteredDotInsertionPerms.push(...perms);
		}
	}

	const permsToProbe = [...nonDotInsertionPerms, ...filteredDotInsertionPerms];

	// Phase 1: Fast NS existence check — filter out unregistered domains.
	// Also query the primary domain's NS + MX for ownership comparison: NS for
	// the ownership verdict itself, MX for the D4 MX-overlap corroboration
	// signal consulted by `attributionConfidence()` (wording only).
	const [nsResult, primaryNs, primaryMx] = await Promise.all([
		filterByNsExistence(permsToProbe),
		queryPrimaryNs(domain),
		queryPrimaryMx(domain),
	]);
	const { registered: registeredPerms, nsMap: lookalikeNsMap } = nsResult;

	if (registeredPerms.length === 0) {
		findings.push(
			createFinding(
				'lookalikes',
				'No active lookalike domains detected',
				'info',
				`Checked ${permutations.length} domain permutations of ${domain}. No active registrations detected.`,
				{ findingAxis: 'scan_status' satisfies LookalikeFindingAxis },
			),
		);
		return buildCheckResult('lookalikes', findings);
	}

	// D4 (2026-07-26 correctness-defects design) — classify every registered
	// candidate's ownership ONCE, up front, reused across all three same-owner
	// decision points below (the enrichment filter, the main classification
	// loop, and the same-entity RDAP-eligibility filter). Replaces
	// sharesNameservers() (SHARED_NS_THRESHOLD = 1 — a single shared NS host,
	// e.g. a pooled Akamai hostname, was already enough to mark two unrelated
	// organisations as the same owner — an even weaker version of the
	// shadow-domains bug this design also fixes). Every registered candidate
	// here was proven registered via NS (filterByNsExistence only returns
	// domains with NS records), so `registration.ns` is always non-empty.
	const primaryNsList = Array.from(primaryNs);
	const brand = extractBrandName(domain) ?? '';
	const ownershipByDomain = new Map<string, OwnershipAssessment>();
	for (const perm of registeredPerms) {
		const candidateNs = Array.from(lookalikeNsMap.get(perm) ?? []);
		ownershipByDomain.set(
			perm,
			classifyOwnership({
				seedDomain: domain,
				seedNs: primaryNsList,
				candidateDomain: perm,
				registration: { state: 'registered', ns: candidateNs, evidence: candidateNs.length > 0 ? ['ns'] : ['a'] },
				isSharedNsHost,
			}),
		);
	}

	// Phase 2: Detail probe only registered domains
	const probeResults = await probeWithAdaptiveBatching(registeredPerms);
	const results: LookalikeResult[] = [];
	for (const result of probeResults) {
		if (result.status === 'fulfilled') {
			results.push(result.value);
		}
	}

	// Enrichment (Defect L / issue #264): for each non-defensively-registered
	// lookalike with mail or web infrastructure, gather corroborating signals
	// so the calibrator can pick the right severity tier. Lookalikes the
	// ownership verdict already attributes to the same organisation skip
	// enrichment entirely (they short-circuit to info-severity
	// defensive-registration findings in the main loop below).
	const candidatesToEnrich: LookalikeResult[] = results.filter((r) => {
		const sameOwner = ownershipByDomain.get(r.domain)?.verdict === 'owned_by_seed';
		return !sameOwner && (r.hasMX || r.hasA);
	});
	const enrichment = await enrichLookalikes(candidatesToEnrich);

	// Same-entity correlation (issue #263): a flagged lookalike that shares the
	// scan domain's RDAP registrant org is almost certainly the org's own
	// defensive registration / regional subsidiary (e.g. a vendor's regional
	// presence on a DIFFERENT DNS provider, which the ownership verdict above
	// misses). We only fetch the primary's registrant org — and only apply the
	// correlation — when at least one enriched candidate would surface at
	// medium/high severity, so a clean scan pays no RDAP cost. The candidates'
	// own registrant orgs are already in `enrichment` (harvested from the same
	// fetch as registrationDays), so this adds exactly ONE extra RDAP fetch (the
	// primary), not one-per-candidate. The eligible set is capped at
	// SAME_ENTITY_RDAP_CAP, highest-severity first. Fail-soft: if the primary
	// RDAP org is unknown, NO correlation happens.
	//
	// FIX ROUND 1 (review finding F1): a match here NO LONGER suppresses the
	// threat axis — see the emission site below — and every use of it is gated
	// by `isSameEntityOrgMatch()`, which rejects privacy-proxy / redacted /
	// generic strings on BOTH sides.
	const sameEntityCandidates = computeSameEntityCandidates(results, ownershipByDomain, enrichment);
	// ONE RDAP fetch for the seed, reused for BOTH correlations: the registrant
	// org (unverified, wording-only) and the registry-published registrar ID
	// (the brand-held-registration signal). No extra network cost for the second.
	const primaryRegistration = sameEntityCandidates.length > 0 ? await probePrimaryRegistration(domain) : EMPTY_RDAP_PROBE;
	const primaryRegistrantOrg = primaryRegistration.registrantOrg;
	const sameEntityMatches = new Map<string, string>();
	/** Candidates the registration record corroborates as the seed org's own defensive registrations. */
	const brandHeldMatches = new Map<string, { registrarIanaId: string; registrarName: string | null; reason: DefensiveReason }>();
	for (const candidateDomain of sameEntityCandidates) {
		const corroborators = enrichment.get(candidateDomain);
		const candidateOrg = corroborators?.registrantOrg ?? null;
		if (candidateOrg !== null && isSameEntityOrgMatch(primaryRegistrantOrg, candidateOrg)) {
			sameEntityMatches.set(candidateDomain, candidateOrg);
		}
		const probe = results.find((r) => r.domain === candidateDomain);
		// An ABSENT probe is "we never looked", which is NOT "there is no mail" —
		// and the defensive-shape heuristic fires its `no-mx` reason on an empty
		// array. Defaulting to `[]` here would therefore manufacture a defensive
		// verdict out of a missing measurement, the exact
		// unmeasured-signal-compiled-into-an-affirmative-claim trap. Skip instead.
		// (`computeSameEntityCandidates` only ever names domains drawn from
		// `results`, so this is unreachable today — it is a guard against a
		// future caller widening the eligible set, not a live bug fix.)
		if (probe === undefined) continue;
		const brandHeld = isBrandHeldRegistration({
			seedDomain: domain,
			candidateDomain,
			seedRegistrarIanaId: primaryRegistration.registrarIanaId,
			candidateRegistrarIanaId: corroborators?.registrarIanaId ?? null,
			candidateMxExchanges: probe.mxExchanges,
			candidateNsHosts: Array.from(lookalikeNsMap.get(candidateDomain) ?? []),
		});
		if (brandHeld.brandHeld) {
			brandHeldMatches.set(candidateDomain, {
				registrarIanaId: brandHeld.registrarIanaId,
				registrarName: corroborators?.registrarName ?? null,
				reason: brandHeld.reason,
			});
		}
	}

	// Classify results on BOTH axes (Task 7b). The ownership verdict computed
	// above routes through the D4 gate so an ATTRIBUTION claim about a
	// shared-provider/no-signal candidate can never surface above info (see
	// classifyOwnership()'s JSDoc in ../lib/ownership-attribution); the
	// #264-calibrated OBSERVED-threat severity rides a separate finding that
	// asserts nothing about ownership.
	//
	// `highCount` is reachable again as of Task 7b: it counts threat-OBSERVATION
	// highs, which the ownership cap no longer touches. Under Task 7 it could
	// never increment and the summary finding below was dead code.
	let highCount = 0;
	/** The counted candidates, so the aggregate summary can name what it counted (invariant 4). */
	const highDomains: string[] = [];
	/** Their ownership verdicts — always non-owned, since owned candidates never reach the counter. */
	const highVerdicts = new Set<OwnershipVerdict>();
	for (const result of results) {
		const ownership: OwnershipAssessment = ownershipByDomain.get(result.domain) ?? {
			verdict: 'unattributed',
			strength: 'none',
			signals: [],
			rationale: `No ownership signal is available for ${result.domain}.`,
		};
		const sameOwner = ownership.verdict === 'owned_by_seed';

		if (sameOwner) {
			// Structurally owned by the seed — the customer's own domain.
			findings.push(
				createFinding(
					'lookalikes',
					`Lookalike domain likely owned by same entity: ${result.domain}`,
					'info',
					`The domain ${result.domain} is owned by the same organisation as ${domain} (${ownership.rationale}).${result.hasMX ? ' Has active mail infrastructure.' : ''}${result.hasA ? ' Has web presence.' : ''}`,
					{
						lookalikeDomain: result.domain,
						hasA: result.hasA,
						hasMX: result.hasMX,
						ownershipVerdict: ownership.verdict,
						findingAxis: 'attribution' satisfies LookalikeFindingAxis,
					},
				),
			);
			// Task 7b requirement 5: an `owned_by_seed` candidate gets NO
			// threat-observation finding — the customer's own domain is not an
			// impersonation threat to itself. This `continue` (together with the
			// enrichment skip above) is the only thing enforcing that, so the 6(c)
			// test pins it against a disposable-MX fixture that would otherwise
			// calibrate to HIGH.
			continue;
		}

		if (!result.hasMX && !result.hasA) continue;

		const corroborators = enrichment.get(result.domain) ?? {
			registrationDays: null,
			mxOnDisposable: false,
			hasWebContent: true,
			registrantOrg: null,
		};
		const signals: LookalikeSignals = {
			hasA: result.hasA,
			hasMX: result.hasMX,
			registrationDays: corroborators.registrationDays,
			mxOnDisposable: corroborators.mxOnDisposable,
			hasWebContent: corroborators.hasWebContent,
		};
		const severity = calibrateLookalikeSeverity(signals);
		const corroboratorReasons = describeCorroborators(signals);

		// Same-entity correlation (issue #263): the calibrated severity is a
		// threat tier (low/medium/high), but if this lookalike's RDAP registrant
		// org matches the scan domain's, it's PLAUSIBLY the org's own defensive /
		// regional registration. Downgrade to an info finding instead of a
		// threat. Only medium/high candidates are eligible (see
		// computeSameEntityCandidates); LOW web-only matches stay as-is (cheap,
		// low-noise, not worth the fetch).
		//
		// F2 (2026-07-27 fix round 2): a RDAP registrant-org match is
		// DELIBERATELY NOT fed into `classifyOwnership()` as an ownership
		// signal — the org field is self-declared and unverified by most
		// registries (the same attacker-influenceable class as the
		// candidate-side declarations described in the OWNERSHIP RULE note
		// on `ClassifyOwnershipInput`), so it must never be able to
		// silently produce an `owned_by_seed` verdict. Every candidate reaching
		// this branch therefore still carries the STRUCTURAL verdict computed
		// earlier (`third_party` here — `sameOwner` above already filtered out
		// `owned_by_seed`), and the verdict now travels on this finding too
		// (`ownershipVerdict` in metadata) per the same "verdict travels on
		// EVERY classified finding" invariant `check-shadow-domains.ts` states
		// for its own emission sites. The title/prose no longer asserts common
		// ownership outright — it's reworded to state plainly that this is a
		// registrant-organisation SIGNAL, distinct from (and weaker than) the
		// structural NS-based evidence, whose own finding is quoted verbatim.
		const matchedOrg = sameEntityMatches.get(result.domain);
		const brandHeld = brandHeldMatches.get(result.domain);
		if (brandHeld !== undefined) {
			// AXIS 1 — the registration record corroborates that this is the
			// scanned organisation's OWN defensive registration. Emitted INSTEAD
			// of the neutral D4 gate template, which would otherwise state
			// positively that the domain "is registered to a different
			// organisation" — a claim the nameserver evidence alone never
			// supported and which is simply false here.
			//
			// SEVERITY IS `info`, EXACTLY AS `applyOwnershipGate()` WOULD HAVE
			// CAPPED IT. This branch changes what the report SAYS, never what it
			// SCORES: `capAttributionSeverity()` caps every non-`owned_by_seed`
			// attribution finding at `info` regardless, so swapping the prose
			// moves no penalty. Pinned by the boundary test in
			// `test/ownership-attribution.spec.ts`.
			const registrarLabel = brandHeld.registrarName
				? `${brandHeld.registrarName} (IANA ${brandHeld.registrarIanaId})`
				: `IANA registrar ${brandHeld.registrarIanaId}`;
			findings.push(
				createFinding(
					'lookalikes',
					`Confusable domain held at the same brand-protection registrar: ${result.domain}`,
					'info',
					`The domain ${result.domain} is a confusable variant of ${domain}, and the registry publishes the SAME brand-protection registrar for both (${registrarLabel}). Its infrastructure also has the shape of a defensive registration — ${DEFENSIVE_REASON_PHRASES[brandHeld.reason]}. Brand-protection registrars do not sell to the general public and the IANA registrar ID is published by the registry rather than declared by the registrant, so this corroborates that ${result.domain} is held by the scanned organisation itself; it is not proof, since one such registrar serves many brands. Nameserver evidence is separate and did not link the two: ${ownership.rationale} Confirm against your own domain portfolio before treating ${result.domain} as an outside party's.`,
					{
						lookalikeDomain: result.domain,
						hasA: result.hasA,
						hasMX: result.hasMX,
						brandHeldRegistration: true,
						sharedRegistrarIanaId: brandHeld.registrarIanaId,
						defensiveReason: brandHeld.reason,
						// Ruling A holds: registrar evidence never manufactures
						// `owned_by_seed`. The STRUCTURAL verdict travels unchanged.
						ownershipVerdict: ownership.verdict,
						ownershipRationale: ownership.rationale,
						findingAxis: 'attribution' satisfies LookalikeFindingAxis,
					},
				),
			);
		} else if (matchedOrg !== undefined) {
			// AXIS 1 — the registrant-org observation REPLACES the neutral D4 gate
			// template for this candidate (it is strictly more informative), but it
			// is still an attribution statement capped at info.
			findings.push(
				createFinding(
					'lookalikes',
					`Lookalike domain shares registrant organisation with scanned domain: ${result.domain}`,
					'info',
					`The domain ${result.domain} shares the same RDAP registrant organisation as ${domain} ("${matchedOrg}"), which may indicate a defensive registration or regional presence by the same owner. This is a registrant-organisation signal, not structural ownership evidence — RDAP registrant fields are self-declared and not independently verified. Nameserver-based evidence: ${ownership.rationale}${result.hasMX ? ' Has active mail infrastructure.' : ''}${result.hasA ? ' Has web presence.' : ''}`,
					{
						lookalikeDomain: result.domain,
						hasA: result.hasA,
						hasMX: result.hasMX,
						sharedRegistrantOrg: matchedOrg,
						ownershipVerdict: ownership.verdict,
						ownershipRationale: ownership.rationale,
						findingAxis: 'attribution' satisfies LookalikeFindingAxis,
					},
				),
			);
		} else {
			// AXIS 1 — the ownership verdict caps the ATTRIBUTION finding's severity: a candidate
			// with no ownership signal linking it to the scanned organisation can
			// never surface above info, regardless of how threatening its raw
			// infrastructure signals look. `attributionConfidence()` (fed the
			// MX-overlap corroboration signal below) governs WORDING/CONFIDENCE
			// only — see `applyOwnershipGate()`'s JSDoc.
			const mxOverlapsPrimary = result.mxExchanges.some((ex) => primaryMx.has(ex));
			const rawFinding = result.hasMX
				? createFinding(
						'lookalikes',
						`Lookalike domain with mail infrastructure: ${result.domain}`,
						severity,
						`The domain ${result.domain} is registered with active mail servers (MX records), which could be used for phishing or email spoofing targeting ${domain}.${corroboratorReasons ? ` Corroborating signals: ${corroboratorReasons}.` : ''}`,
						{
							lookalikeDomain: result.domain,
							hasA: result.hasA,
							hasMX: result.hasMX,
							registrationDays: signals.registrationDays,
							mxOnDisposable: signals.mxOnDisposable,
							hasWebContent: signals.hasWebContent,
							findingAxis: 'attribution' satisfies LookalikeFindingAxis,
						},
					)
				: createFinding(
						'lookalikes',
						`Lookalike domain registered: ${result.domain}`,
						severity,
						`The domain ${result.domain} is registered (has web presence) but no mail infrastructure detected. It could still be used for phishing websites targeting ${domain}.${corroboratorReasons ? ` Corroborating signals: ${corroboratorReasons}.` : ''}`,
						{
							lookalikeDomain: result.domain,
							hasA: result.hasA,
							hasMX: result.hasMX,
							registrationDays: signals.registrationDays,
							mxOnDisposable: signals.mxOnDisposable,
							hasWebContent: signals.hasWebContent,
							findingAxis: 'attribution' satisfies LookalikeFindingAxis,
						},
					);

			// Attribution pushed FIRST so a consumer scanning for the ownership
			// statement about a candidate finds it ahead of the threat observation.
			findings.push(applyOwnershipGate(rawFinding, ownership, brand, mxOverlapsPrimary));
		}

		// AXIS 2 — the observed threat, at the severity the #264 matrix computed
		// and Task 7 used to discard. Emitted for EVERY non-owned candidate,
		// including one whose RDAP registrant org matched the seed's (fix round 1,
		// F1: that string is unverified and collision-prone, so it may annotate the
		// observation but must never switch the axis off). Only `owned_by_seed`
		// candidates are exempt — they `continue` above.
		findings.push(
			buildThreatObservationFinding(
				result.domain,
				domain,
				severity,
				signals,
				ownership,
				corroboratorReasons,
				matchedOrg,
				brandHeld !== undefined,
			),
		);
		if (result.hasMX && severity === 'high') {
			highCount++;
			highDomains.push(result.domain);
			highVerdicts.add(ownership.verdict);
		}
	}

	// Summary finding for high-severity lookalikes (AXIS 2). Only fires when at
	// least one NON-OWNED candidate reached HIGH under the issue #264 matrix
	// (mail-infra + corroborator). Owned candidates never reach here.
	if (highCount > 0) {
		findings.push(
			createFinding(
				'lookalikes',
				`${highCount} lookalike domain${highCount > 1 ? 's' : ''} with mail capability detected`,
				'high',
				`${highCount} lookalike domain${highCount > 1 ? 's' : ''} of ${domain} ${highCount > 1 ? 'have' : 'has'} active mail infrastructure with corroborating signals consistent with pre-phishing staging. ${highCount > 1 ? 'None of them appear' : 'It does not appear'} to belong to the scanned organisation, and no action on ${highCount > 1 ? 'them' : 'it'} is requested here. Defensive options: monitor ${highCount > 1 ? 'them' : 'it'}, and enforce DMARC p=reject on ${domain} itself so receivers reject mail spoofing that name.`,
				{
					lookalikeDomainCount: highCount,
					lookalikeDomains: highDomains,
					// Present whenever the counted set shares one verdict (the realistic
					// case — a non-owned registered candidate is always `third_party`).
					// Omitted rather than fabricated for a mixed set; either way it can
					// never be `owned_by_seed`, since owned candidates never reach here.
					...(highVerdicts.size === 1 ? { ownershipVerdict: [...highVerdicts][0] } : {}),
					findingAxis: 'threat_observation' satisfies LookalikeFindingAxis,
				},
			),
		);
	}

	// If no active lookalikes found
	if (findings.length === 0) {
		findings.push(
			createFinding(
				'lookalikes',
				'No active lookalike domains detected',
				'info',
				`Checked ${permutations.length} domain permutations of ${domain}. No active registrations with DNS or mail infrastructure detected.`,
				{ findingAxis: 'scan_status' satisfies LookalikeFindingAxis },
			),
		);
	}

	// Recon enrichment: additive-only, fail-soft.
	//
	// FIX ROUND 1, F1 (2026-07-27, post-review): this block used to emit a
	// `medium`-severity `threat_observation` with NO `ownershipVerdict` and
	// `domain: domain` (the SEED, not any candidate) — a live violation of
	// this slice's own load-bearing safety property, caught by the Task 8
	// audit's adversarial review (`ownership-severity-gate.audit.test.ts`).
	// bv-recon's CT_LOOKALIKE check is scoped to the seed's own CT-log
	// neighbourhood; it does not always name a specific confusable domain, so
	// `extractReconMatchedDomain()` below may legitimately return null.
	if (reconOptions.reconBinding) {
		const reconResult = await callReconScan(
			reconOptions.reconBinding,
			reconOptions.reconAuthToken,
			'CT_LOOKALIKE',
			{ domain },
			undefined,
			reconOptions.onBindingDegradation,
		);
		const hit = reconResult && isReconHit(reconResult.status);
		if (hit && reconResult) {
			const matchedDomain = extractReconMatchedDomain(reconResult, domain);
			const detail = reconResult.details ?? `Threat intelligence corroborates CT-observed lookalike signal for ${domain}.`;

			if (matchedDomain) {
				// A named candidate — reuse the SAME ownership assessment the local
				// classification loop above computed when we also generated/probed
				// this permutation ourselves. When bv-recon names a domain outside
				// our own generated permutation set, default to `unattributed`
				// (never `owned_by_seed` — an externally-sourced, unverified match
				// is never sufficient to claim the candidate is the customer's own).
				const reconOwnership: OwnershipAssessment = ownershipByDomain.get(matchedDomain) ?? {
					verdict: 'unattributed',
					strength: 'none',
					signals: [],
					rationale: `No ownership signal is available for ${matchedDomain}.`,
				};
				// Task 7b requirement 5: a candidate already known to be the
				// customer's own domain gets no threat_observation finding — this
				// enrichment is additive-only and adds nothing new for one.
				if (reconOwnership.verdict !== 'owned_by_seed') {
					findings.push(
						createFinding('lookalikes', 'CT-observed lookalike corroboration', 'medium', detail, {
							lookalikeDomain: matchedDomain,
							reconEnriched: true,
							findingAxis: 'threat_observation' satisfies LookalikeFindingAxis,
							ownershipVerdict: reconOwnership.verdict,
						}),
					);
				}
			} else {
				// No specific candidate nameable — never fabricate one. A
				// scan-level notice about the run's own CT signal, not a
				// per-candidate threat claim, so it stays `info`/`scan_status`
				// (DEMOTE, NEVER DELETE: the real signal is still surfaced).
				findings.push(
					createFinding(
						'lookalikes',
						'CT-observed lookalike corroboration (no specific candidate identified)',
						'info',
						`${detail} No specific confusable domain was identified by this signal, so no candidate-level claim is made.`,
						{ domain, reconEnriched: true, findingAxis: 'scan_status' satisfies LookalikeFindingAxis },
					),
				);
			}
		}
	}

	return buildCheckResult('lookalikes', findings);
}

interface LookalikeCorroborators {
	registrationDays: number | null;
	mxOnDisposable: boolean;
	hasWebContent: boolean;
	/**
	 * Normalised RDAP registrant org for this candidate, harvested from the same
	 * single RDAP fetch as {@link registrationDays}. `null` when RDAP failed,
	 * returned no registrant entity, or the org field was empty — in which case
	 * the same-entity correlation fails soft (the calibrated threat severity
	 * stands; a real threat is never suppressed on missing RDAP).
	 */
	registrantOrg: string | null;
	/**
	 * Registry-published IANA registrar ID for this candidate, harvested from
	 * the same single RDAP fetch as everything else here. Feeds
	 * {@link isBrandHeldRegistration}; `null` fails soft to "no evidence".
	 */
	registrarIanaId: string | null;
	/** Registrar display name, for report prose only. */
	registrarName: string | null;
}

/**
 * THE single predicate deciding whether two RDAP registrant-org strings may be
 * treated as the same entity (issue #263). Added in Task 7b fix round 1 for
 * review finding F1.
 *
 * The org field is free text the registrant TYPES and RDAP does not verify it.
 * Raw string equality was therefore both forgeable (one registrar form field)
 * and — far more damaging — trivially collision-prone: seed and candidate
 * sitting behind the SAME privacy service normalise equal for reasons that
 * carry zero identity information. Both sides are gated through
 * `isRedactedRegistrantOrg()`, so a redacted / proxy / generic value can never
 * produce a match.
 *
 * A surviving match is still only a WEAK, unverified signal: it earns a
 * sentence in the report, never a severity discount. The threat-observation
 * finding is emitted at its full calibrated severity regardless.
 *
 * EQUALITY-MATCHING INVARIANT — READ BEFORE CHANGING THE COMPARISON (fix round
 * 2, re-review residual). The final test is STRICT EQUALITY, and
 * `isRedactedRegistrantOrg()` is a pure function of its string. Therefore
 * whenever the two orgs are equal the predicate returns the SAME verdict for
 * both, and checking one side is currently EXACTLY equivalent to checking both.
 * That was verified by execution: mutating this function to gate the candidate
 * side only left the entire suite green, and no end-to-end fixture can
 * discriminate — for a one-sided gate to wrongly match, the two strings would
 * have to differ in redaction status while still being equal, which equality
 * matching makes impossible.
 *
 * The both-sides form is kept as DEFENCE IN DEPTH for the day that comparison
 * stops being equality. ANY change to fuzzy/containment/token-overlap/edit-
 * distance matching MUST (a) keep the gate on BOTH sides — under fuzzy matching
 * a redacted string can match a non-redacted one, so a one-sided gate becomes a
 * real hole — and (b) ship a fixture that discriminates one-sided from
 * two-sided, which only becomes constructible once equality is gone. Until
 * then the semantics are pinned directly by the unit tests on this function in
 * `test/check-lookalikes.spec.ts` (exported for exactly that purpose), not by
 * an end-to-end fixture that cannot tell the two implementations apart.
 */
export function isSameEntityOrgMatch(primaryOrg: string | null, candidateOrg: string | null): boolean {
	if (primaryOrg === null || candidateOrg === null) return false;
	if (isRedactedRegistrantOrg(primaryOrg) || isRedactedRegistrantOrg(candidateOrg)) return false;
	return primaryOrg === candidateOrg;
}

/**
 * Determine which lookalike candidates are eligible for the issue #263
 * same-entity (shared-registrant) downgrade. Eligibility mirrors the
 * classification loop's decision so we never fetch the primary's registrant
 * org speculatively: a candidate qualifies only when `ownershipByDomain`
 * does NOT already attribute it to the seed (`owned_by_seed` — CALL SITE 3
 * of the D4 2026-07-26 correctness-defects design's ownership gate) and has
 * mail/web infra. The result is sorted by calibrated severity, highest first,
 * and capped at {@link SAME_ENTITY_RDAP_CAP} so a permutation explosion can't
 * widen the RDAP fan-out unbounded.
 *
 * LOW-SEVERITY CANDIDATES ARE ELIGIBLE (changed — they used to be excluded as
 * "not worth the RDAP cost"). That exclusion was the mechanical cause of the
 * brand's-own-defensive-registration defect: a defensive registration is
 * PARKED, so it is web-only, aged and mail-less, and therefore calibrates
 * exactly `low`. The tool skipped the one fetch that would have told it who
 * held the domain, then asserted the domain "is registered to a different
 * organisation" and offered to report it for takedown — a positive
 * non-ownership CLAIM derived from evidence it declined to gather.
 *
 * Severity is a THREAT tier, so gating an ATTRIBUTION lookup on it was a
 * category error: the cheapest candidates to dismiss as low-threat are
 * precisely the ones most likely to be the customer's own.
 *
 * COST OF THE WIDENING IS ONE FETCH, MEASURED NOT ASSUMED. Candidate RDAP was
 * never gated on severity — `enrichLookalikes()` already fetches it for every
 * non-owned candidate with mail/web infra. The medium/high gate only decided
 * whether the SEED's single RDAP fetch happened. So widening to `low` adds at
 * most ONE request per scan, on scans that have a registered non-owned
 * candidate at all. `SAME_ENTITY_RDAP_CAP` still bounds the set; severity now
 * only decides ORDER within it, and `owned_by_seed` candidates are still
 * excluded outright, so the shared-NS short-circuit still pays no RDAP cost.
 */
function computeSameEntityCandidates(
	results: LookalikeResult[],
	ownershipByDomain: Map<string, OwnershipAssessment>,
	enrichment: Map<string, LookalikeCorroborators>,
): string[] {
	const SEVERITY_ORDER: Record<LookalikeSeverity, number> = { high: 0, medium: 1, low: 2 };
	const eligible: Array<{ domain: string; severity: LookalikeSeverity }> = [];
	for (const result of results) {
		const sameOwner = ownershipByDomain.get(result.domain)?.verdict === 'owned_by_seed';
		if (sameOwner) continue;
		if (!result.hasMX && !result.hasA) continue;
		const corroborators = enrichment.get(result.domain);
		const severity = calibrateLookalikeSeverity({
			hasA: result.hasA,
			hasMX: result.hasMX,
			registrationDays: corroborators?.registrationDays ?? null,
			mxOnDisposable: corroborators?.mxOnDisposable ?? false,
			hasWebContent: corroborators?.hasWebContent ?? true,
		});
		eligible.push({ domain: result.domain, severity });
	}
	eligible.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
	return eligible.slice(0, SAME_ENTITY_RDAP_CAP).map((e) => e.domain);
}

/**
 * Run the Defect L enrichment probes (RDAP registration age + web HEAD probe)
 * for every candidate in parallel. Failure to enrich is fail-soft: missing
 * RDAP data becomes `registrationDays: null` (treated as "unknown — not recent")
 * and a probe error becomes `hasWebContent: true` to avoid synthesising HIGH
 * out of nothing. `mxOnDisposable` is derived synchronously from the already-
 * parsed MX exchanges, no extra DNS needed.
 */
async function enrichLookalikes(candidates: LookalikeResult[]): Promise<Map<string, LookalikeCorroborators>> {
	const map = new Map<string, LookalikeCorroborators>();
	if (candidates.length === 0) return map;
	await Promise.allSettled(
		candidates.map(async (candidate) => {
			const [rdap, hasWebContent] = await Promise.all([
				probeRdap(candidate.domain),
				candidate.hasA ? probeHasWebContent(candidate.domain) : Promise.resolve(true),
			]);
			const mxOnDisposable = candidate.mxExchanges.some(isDisposableMxHost);
			map.set(candidate.domain, {
				registrationDays: rdap.registrationDays,
				mxOnDisposable,
				hasWebContent,
				registrantOrg: rdap.registrantOrg,
				registrarIanaId: rdap.registrarIanaId,
				registrarName: rdap.registrarName,
			});
		}),
	);
	return map;
}

/** Result of the single lightweight RDAP probe per candidate. */
interface RdapProbeResult {
	/** Age in days since the RDAP `registration` event, or `null` on any failure / missing data. */
	registrationDays: number | null;
	/** Normalised RDAP registrant org, or `null` on any failure / missing data. */
	registrantOrg: string | null;
	/**
	 * Registry-published IANA registrar ID, or `null` on any failure / absence.
	 * Distinct in kind from {@link registrantOrg}: assigned by ICANN, published
	 * by the registry, and not settable by the registrant — see
	 * {@link BRAND_PROTECTION_REGISTRAR_IANA_IDS}.
	 */
	registrarIanaId: string | null;
	/** Registrar display name, for report prose only. Never compared. */
	registrarName: string | null;
}

/** Empty probe result — used for early-outs and the catch path (fail-soft). */
const EMPTY_RDAP_PROBE: RdapProbeResult = { registrationDays: null, registrantOrg: null, registrarIanaId: null, registrarName: null };

/**
 * Pull the registrar's IANA ID and display name out of a parsed RDAP domain
 * response. Local to this file rather than imported because
 * `check-rdap-lookup.ts` keeps its vCard/publicId readers private; only
 * `findEntityByRole` is exported, so the traversal is reused and just the two
 * field reads are done here.
 *
 * Fail-soft in every branch — a non-conforming shape yields nulls, which the
 * brand-held predicate treats as "no evidence" (never as a match).
 */
function extractRegistrar(rdapData: unknown): { ianaId: string | null; name: string | null } {
	if (typeof rdapData !== 'object' || rdapData === null) return { ianaId: null, name: null };
	const entities = (rdapData as { entities?: unknown }).entities;
	if (!Array.isArray(entities)) return { ianaId: null, name: null };
	const registrar = findEntityByRole(entities as Parameters<typeof findEntityByRole>[0], 'registrar');
	if (!registrar) return { ianaId: null, name: null };

	let ianaId: string | null = null;
	const publicIds = (registrar as { publicIds?: unknown }).publicIds;
	if (Array.isArray(publicIds)) {
		for (const publicId of publicIds) {
			if (typeof publicId !== 'object' || publicId === null) continue;
			const { type, identifier } = publicId as { type?: unknown; identifier?: unknown };
			if (typeof type === 'string' && /^IANA Registrar ID$/i.test(type.trim()) && typeof identifier === 'string' && identifier.trim()) {
				ianaId = identifier.trim();
				break;
			}
		}
	}

	let name: string | null = null;
	const vcardArray = (registrar as { vcardArray?: unknown }).vcardArray;
	if (Array.isArray(vcardArray) && vcardArray[0] === 'vcard' && Array.isArray(vcardArray[1])) {
		for (const prop of vcardArray[1] as unknown[]) {
			if (Array.isArray(prop) && prop[0] === 'fn' && typeof prop[3] === 'string' && prop[3].trim()) {
				name = prop[3].trim();
				break;
			}
		}
	}
	return { ianaId, name };
}

/**
 * THE predicate deciding whether a candidate is the scanned organisation's own
 * DEFENSIVE REGISTRATION rather than a third party's domain.
 *
 * Requires BOTH, and neither alone is sufficient:
 *
 *  1. REGISTRATION-RECORD corroboration — the candidate and the seed share an
 *     IANA registrar ID belonging to a brand-protection registrar
 *     ({@link BRAND_PROTECTION_REGISTRAR_IANA_IDS}). A shared RETAIL registrar
 *     is explicitly not evidence: millions of unrelated registrants share one.
 *
 *  2. DEFENSIVE INFRASTRUCTURE SHAPE — `evaluateDefensiveRegistration()`
 *     (`src/lib/brand-defensive-registration.ts`) agrees the candidate is a
 *     typo-close label parked with minimal infrastructure. An attacker who
 *     somehow reached the same corporate registrar but stood up live mail
 *     still fails this leg and gets the full threat treatment.
 *
 * WHAT THIS DELIBERATELY DOES NOT DO: it does not, and must not, produce an
 * `owned_by_seed` ownership verdict. `classifyOwnership()` stays driven by
 * seed-side nameserver evidence alone (Ruling A), and every finding about this
 * candidate keeps carrying its structural `third_party` verdict. What changes
 * is what the report CLAIMS and RECOMMENDS: it stops asserting the domain
 * "is registered to a different organisation" on evidence that never
 * addressed the question, and stops telling the customer to report their own
 * domain for takedown.
 *
 * NULL-GUARD NOTE — VERIFIED BY MUTATION, NOT ASSUMED (the same disclosure
 * `isSameEntityOrgMatch` above makes about its own both-sides gate). The
 * `=== null` guard on the first line is currently REDUNDANT: deleting it left
 * the entire suite green, because two `null` IDs pass the equality check and
 * are then rejected by `BRAND_PROTECTION_REGISTRAR_IANA_IDS.has(null)` anyway.
 * No fixture can discriminate the two implementations while membership is an
 * exact-set test, so none is shipped pretending to.
 *
 * It is kept as DEFENCE IN DEPTH and becomes load-bearing the moment that
 * membership test is relaxed — a name-based or fuzzy registrar comparison, or
 * an "any shared registrar" mode — at which point "both sides published
 * nothing" would read as a match and silently mark every RDAP-less candidate
 * as brand-held. Anyone relaxing it MUST keep this guard and ship a fixture
 * that discriminates it, which only becomes constructible then.
 */
export function isBrandHeldRegistration(input: {
	seedDomain: string;
	candidateDomain: string;
	seedRegistrarIanaId: string | null;
	candidateRegistrarIanaId: string | null;
	candidateMxExchanges: readonly string[];
	candidateNsHosts: readonly string[];
}): { brandHeld: false } | { brandHeld: true; registrarIanaId: string; reason: DefensiveReason } {
	const { seedRegistrarIanaId, candidateRegistrarIanaId } = input;
	if (seedRegistrarIanaId === null || candidateRegistrarIanaId === null) return { brandHeld: false };
	if (seedRegistrarIanaId !== candidateRegistrarIanaId) return { brandHeld: false };
	if (!BRAND_PROTECTION_REGISTRAR_IANA_IDS.has(candidateRegistrarIanaId)) return { brandHeld: false };

	const shape = evaluateDefensiveRegistration({
		candidateDomain: input.candidateDomain,
		targetDomain: input.seedDomain,
		// A concrete array (never `undefined`) — we DID look, via the Phase 2
		// probe, so an empty set means "no mail", not "unknown". The heuristic
		// abstains on `undefined`, which would silently disable this leg.
		mxRecords: input.candidateMxExchanges,
		nsHosts: input.candidateNsHosts,
	});
	if (!shape.defensive || shape.reason === undefined) return { brandHeld: false };
	return { brandHeld: true, registrarIanaId: candidateRegistrarIanaId, reason: shape.reason };
}

/**
 * Lightweight RDAP lookup constrained for use inside the lookalike check.
 * Hits the hardcoded {@link FALLBACK_RDAP_SERVERS} map only (no IANA bootstrap),
 * single fetch, hard 2.5s timeout, no retries. From that single response it
 * derives BOTH the registration age (issue #264 corroborator) AND the registrant
 * org (issue #263 same-entity correlation) — no extra fetch for the org signal.
 * Any failure / missing data yields `null` for the affected field, which the
 * calibrator treats as "unknown" (never elevates severity) and the same-entity
 * check treats as "no match" (never suppresses a real threat).
 */
async function probeRdap(domain: string): Promise<RdapProbeResult> {
	const labels = domain.split('.');
	const tld = labels[labels.length - 1]?.toLowerCase();
	if (!tld) return EMPTY_RDAP_PROBE;
	const serverUrl = FALLBACK_RDAP_SERVERS[tld];
	if (!serverUrl) return EMPTY_RDAP_PROBE;
	try {
		const baseUrl = serverUrl.endsWith('/') ? serverUrl : `${serverUrl}/`;
		const rdapUrl = `${baseUrl}domain/${domain}`;
		// The RDAP host comes from the FALLBACK_RDAP_SERVERS map — not statically
		// trusted as a class (the sibling fetchRdapResponse path derives the same
		// host from the network-sourced IANA bootstrap), so route through safeFetch
		// for parity: validateOutboundUrl() re-validates the destination host (SSRF
		// gate) and manual redirect stops the worker chasing a server-supplied
		// Location. safeFetch throws on a blocked host (matching native fetch error
		// semantics); the surrounding try/catch degrades it to EMPTY_RDAP_PROBE
		// exactly like any other probe failure (fail-soft, never throws out of the tool).
		const resp = await safeFetch(rdapUrl, {
			redirect: 'manual',
			signal: AbortSignal.timeout(RDAP_PROBE_TIMEOUT_MS),
			headers: { Accept: 'application/rdap+json, application/json' },
		});
		if (!resp.ok) {
			void resp.body?.cancel();
			return EMPTY_RDAP_PROBE;
		}
		const data = (await resp.json()) as { events?: Array<{ eventAction?: string; eventDate?: string }> };
		const registration = Array.isArray(data.events) ? data.events.find((e) => e.eventAction === 'registration') : undefined;
		let registrationDays: number | null = null;
		if (registration?.eventDate) {
			const creationTime = new Date(registration.eventDate).getTime();
			if (Number.isFinite(creationTime)) {
				registrationDays = Math.floor((Date.now() - creationTime) / (1000 * 60 * 60 * 24));
			}
		}
		const registrar = extractRegistrar(data);
		return {
			registrationDays,
			registrantOrg: extractRegistrantOrg(data),
			registrarIanaId: registrar.ianaId,
			registrarName: registrar.name,
		};
	} catch {
		return EMPTY_RDAP_PROBE;
	}
}

/**
 * Fetch the scan domain's own registration record — registrant org for the
 * same-entity correlation (issue #263) AND the registry-published registrar ID
 * for {@link isBrandHeldRegistration}. ONE fetch serves both; reuses
 * {@link probeRdap} and fails soft to {@link EMPTY_RDAP_PROBE}.
 */
async function probePrimaryRegistration(domain: string): Promise<RdapProbeResult> {
	return probeRdap(domain);
}

/**
 * HEAD probe the candidate domain to confirm web content is reachable.
 * Fail-soft: any error (connection refused, timeout, DNS miss, TLS error)
 * returns `true` so a flaky probe can't synthesise a HIGH severity via the
 * "no-web-content" corroborator. Parked-or-refused domains return `false`.
 *
 * 5xx responses also count as "has content" — we got reached the server,
 * the server just errored. Phishing infra rarely 5xx's; parked-page infra
 * usually 200's with adverts. The only consistent "no content" signal is a
 * hard transport failure.
 */
export async function probeHasWebContent(domain: string): Promise<boolean> {
	try {
		// safeFetch + manual redirect: the candidate is attacker-influenced, so we
		// MUST NOT auto-follow a 302 → internal/Cloudflare host (blind SSRF oracle,
		// OWASP A10). safeFetch validates the destination hostname; manual redirect
		// stops the worker from chasing an attacker-supplied Location. A 3xx still
		// proves the host is reachable, so any response counts as "has content".
		const resp = await safeFetch(`https://${domain}/`, {
			method: 'HEAD',
			redirect: 'manual',
			signal: AbortSignal.timeout(WEB_PROBE_TIMEOUT_MS),
		});
		// Any HTTP response (incl. 3xx) means the host is reachable — content exists.
		return Boolean(resp);
	} catch {
		// Transport failure (refused, timeout, DNS) — treat as no content (HIGH corroborator).
		return false;
	}
}

/**
 * Build a short human-readable list of corroborating signals for the finding
 * detail. Empty string when none apply (mail-infra-alone case).
 */
function describeCorroborators(signals: LookalikeSignals): string {
	const parts: string[] = [];
	if (signals.registrationDays !== null && signals.registrationDays < 90) {
		parts.push(`registered ${signals.registrationDays} day${signals.registrationDays === 1 ? '' : 's'} ago`);
	}
	if (signals.mxOnDisposable) parts.push('disposable MX provider');
	if (!signals.hasWebContent) parts.push('no reachable web content');
	return parts.join(', ');
}
