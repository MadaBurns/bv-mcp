// SPDX-License-Identifier: BUSL-1.1

/**
 * Lookalike domain detection tool.
 * Generates typosquat/lookalike domain permutations and checks for
 * active DNS registrations and mail infrastructure.
 * Standalone check — not included in scan_domain due to query volume.
 */

import { queryDnsRecords } from '../lib/dns';
import type { QueryDnsOptions } from '../lib/dns-types';
import { callReconScan, isReconHit } from '../lib/recon-binding';
import type { ReconBinding } from '../lib/recon-binding';
import type { CheckResult, Finding } from '../lib/scoring';
import { buildCheckResult, createFinding } from '../lib/scoring';
import { generateLookalikes } from './lookalike-analysis';
import { FALLBACK_RDAP_SERVERS, extractRegistrantOrg } from './check-rdap-lookup';
import { calibrateLookalikeSeverity, isDisposableMxHost, type LookalikeSignals } from './lookalike-severity';

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

/** Minimum number of NS records that must overlap to consider domains as sharing nameservers. */
const SHARED_NS_THRESHOLD = 1;

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
	const mxExchanges = realMxRecords
		.map(extractMxExchange)
		.filter((host): host is string => host !== null);

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
 * Check whether two NS sets share at least SHARED_NS_THRESHOLD nameservers.
 * Shared nameservers are a strong signal that both domains are controlled by the same entity.
 */
function sharesNameservers(primaryNs: Set<string>, lookalikeNs: Set<string>): boolean {
	let overlap = 0;
	for (const ns of lookalikeNs) {
		if (primaryNs.has(ns)) {
			overlap++;
			if (overlap >= SHARED_NS_THRESHOLD) return true;
		}
	}
	return false;
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
export async function checkLookalikes(
	domain: string,
	reconOptions: { reconBinding?: ReconBinding; reconAuthToken?: string } = {},
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
			),
		]);
		// Mark as partial so callers can skip caching
		result.partial = true;
		return result;
	});
}

async function checkLookalikesCore(
	domain: string,
	reconOptions: { reconBinding?: ReconBinding; reconAuthToken?: string } = {},
): Promise<CheckResult> {
	const findings: Finding[] = [];
	const permutations = generateLookalikes(domain);

	if (permutations.length === 0) {
		findings.push(
			createFinding(
				'lookalikes',
				'No active lookalike domains detected',
				'info',
				`No lookalike domain permutations could be generated for ${domain}.`,
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

	// Phase 1: Fast NS existence check — filter out unregistered domains
	// Also query the primary domain's NS for ownership comparison
	const [nsResult, primaryNs] = await Promise.all([filterByNsExistence(permsToProbe), queryPrimaryNs(domain)]);
	const { registered: registeredPerms, nsMap: lookalikeNsMap } = nsResult;

	if (registeredPerms.length === 0) {
		findings.push(
			createFinding(
				'lookalikes',
				'No active lookalike domains detected',
				'info',
				`Checked ${permutations.length} domain permutations of ${domain}. No active registrations detected.`,
			),
		);
		return buildCheckResult('lookalikes', findings);
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
	// so the calibrator can pick the right severity tier. Lookalikes that
	// share nameservers with the primary domain skip enrichment entirely (they
	// short-circuit to info-severity defensive-registration findings).
	const candidatesToEnrich: LookalikeResult[] = results.filter((r) => {
		const lookalikeNs = lookalikeNsMap.get(r.domain);
		const sameOwner = primaryNs.size > 0 && lookalikeNs !== undefined && sharesNameservers(primaryNs, lookalikeNs);
		return !sameOwner && (r.hasMX || r.hasA);
	});
	const enrichment = await enrichLookalikes(candidatesToEnrich);

	// Same-entity correlation (issue #263): a flagged lookalike that shares the
	// scan domain's RDAP registrant org is almost certainly the org's own
	// defensive registration / regional subsidiary (e.g. a vendor's regional
	// presence on a DIFFERENT DNS provider, which the shared-NS pass above
	// misses). We only fetch the primary's registrant org — and only apply the
	// correlation — when at least one enriched candidate would surface at
	// medium/high severity, so a clean scan pays no RDAP cost. The candidates'
	// own registrant orgs are already in `enrichment` (harvested from the same
	// fetch as registrationDays), so this adds exactly ONE extra RDAP fetch (the
	// primary), not one-per-candidate. The eligible set is capped at
	// SAME_ENTITY_RDAP_CAP, highest-severity first. Fail-soft: if the primary
	// RDAP org is unknown, NO downgrade happens (a real threat is never
	// suppressed because RDAP was unavailable).
	const sameEntityCandidates = computeSameEntityCandidates(results, lookalikeNsMap, primaryNs, enrichment);
	const primaryRegistrantOrg = sameEntityCandidates.length > 0 ? await probePrimaryRegistrantOrg(domain) : null;
	const sameEntityMatches = new Map<string, string>();
	if (primaryRegistrantOrg !== null) {
		for (const candidateDomain of sameEntityCandidates) {
			if (enrichment.get(candidateDomain)?.registrantOrg === primaryRegistrantOrg) {
				sameEntityMatches.set(candidateDomain, primaryRegistrantOrg);
			}
		}
	}

	// Classify results — check for shared nameservers with primary domain to detect defensive registrations
	let highCount = 0;
	for (const result of results) {
		const lookalikeNs = lookalikeNsMap.get(result.domain);
		const sameOwner = primaryNs.size > 0 && lookalikeNs !== undefined && sharesNameservers(primaryNs, lookalikeNs);

		if (sameOwner) {
			// Shared nameservers — likely a defensive registration by the same entity
			findings.push(
				createFinding(
					'lookalikes',
					`Lookalike domain likely owned by same entity: ${result.domain}`,
					'info',
					`The domain ${result.domain} shares nameservers with ${domain}, indicating it is likely a defensive registration by the same owner.${result.hasMX ? ' Has active mail infrastructure.' : ''}${result.hasA ? ' Has web presence.' : ''}`,
					{ lookalikeDomain: result.domain, hasA: result.hasA, hasMX: result.hasMX, sharedNs: true },
				),
			);
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
		// org matches the scan domain's, it's the org's own defensive / regional
		// registration. Downgrade to an info finding instead of a threat. Only
		// medium/high candidates are eligible (see computeSameEntityCandidates);
		// LOW web-only matches stay as-is (cheap, low-noise, not worth the fetch).
		const matchedOrg = sameEntityMatches.get(result.domain);
		if (matchedOrg !== undefined) {
			findings.push(
				createFinding(
					'lookalikes',
					`Lookalike domain likely owned by same entity: ${result.domain}`,
					'info',
					`The domain ${result.domain} shares the same RDAP registrant organisation as ${domain} ("${matchedOrg}"), indicating it is likely a defensive registration or regional presence by the same owner rather than a third-party lookalike.${result.hasMX ? ' Has active mail infrastructure.' : ''}${result.hasA ? ' Has web presence.' : ''}`,
					{ lookalikeDomain: result.domain, hasA: result.hasA, hasMX: result.hasMX, sharedRegistrantOrg: matchedOrg },
				),
			);
			continue;
		}

		if (result.hasMX) {
			if (severity === 'high') highCount++;
			findings.push(
				createFinding(
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
					},
				),
			);
		} else {
			// Web-only
			findings.push(
				createFinding(
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
					},
				),
			);
		}
	}

	// Summary finding for high-severity lookalikes. Only fires when at least one
	// candidate reached HIGH under the issue #264 matrix (mail-infra + corroborator).
	if (highCount > 0) {
		findings.push(
			createFinding(
				'lookalikes',
				`${highCount} lookalike domain${highCount > 1 ? 's' : ''} with mail capability detected`,
				'high',
				`${highCount} lookalike domain${highCount > 1 ? 's' : ''} of ${domain} ${highCount > 1 ? 'have' : 'has'} active mail infrastructure with corroborating phishing signals. Consider monitoring these domains and implementing DMARC with p=reject to protect your brand.`,
				{ lookalikeDomainCount: highCount },
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
			),
		);
	}

	// Recon enrichment: additive-only, fail-soft
	if (reconOptions.reconBinding) {
		const reconResult = await callReconScan(reconOptions.reconBinding, reconOptions.reconAuthToken, 'CT_LOOKALIKE', { domain });
		const hit = reconResult && isReconHit(reconResult.status);
		if (hit) {
			findings.push(
				createFinding(
					'lookalikes',
					'CT-observed lookalike corroboration',
					'medium',
					reconResult.details ?? `Threat intelligence corroborates CT-observed lookalike signal for ${domain}.`,
					{ domain, reconEnriched: true },
				),
			);
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
}

/**
 * Determine which lookalike candidates are eligible for the issue #263
 * same-entity (shared-registrant) downgrade. Eligibility mirrors the
 * classification loop's decision so we never fetch the primary's registrant
 * org speculatively: a candidate qualifies only when it is NOT already a
 * shared-NS same-owner hit, has mail/web infra, AND its calibrated severity is
 * medium or high (low web-only matches aren't worth the RDAP cost). The result
 * is sorted high-before-medium and capped at {@link SAME_ENTITY_RDAP_CAP} so a
 * permutation explosion can't widen the RDAP fan-out unbounded.
 */
function computeSameEntityCandidates(
	results: LookalikeResult[],
	lookalikeNsMap: Map<string, Set<string>>,
	primaryNs: Set<string>,
	enrichment: Map<string, LookalikeCorroborators>,
): string[] {
	const eligible: Array<{ domain: string; severity: 'medium' | 'high' }> = [];
	for (const result of results) {
		const lookalikeNs = lookalikeNsMap.get(result.domain);
		const sameOwner = primaryNs.size > 0 && lookalikeNs !== undefined && sharesNameservers(primaryNs, lookalikeNs);
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
		if (severity === 'medium' || severity === 'high') {
			eligible.push({ domain: result.domain, severity });
		}
	}
	eligible.sort((a, b) => (a.severity === b.severity ? 0 : a.severity === 'high' ? -1 : 1));
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
}

/** Empty probe result — used for early-outs and the catch path (fail-soft). */
const EMPTY_RDAP_PROBE: RdapProbeResult = { registrationDays: null, registrantOrg: null };

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
		const resp = await fetch(rdapUrl, {
			redirect: 'manual',
			signal: AbortSignal.timeout(RDAP_PROBE_TIMEOUT_MS),
			headers: { Accept: 'application/rdap+json, application/json' },
		});
		if (!resp.ok) return EMPTY_RDAP_PROBE;
		const data = (await resp.json()) as { events?: Array<{ eventAction?: string; eventDate?: string }> };
		const registration = Array.isArray(data.events) ? data.events.find((e) => e.eventAction === 'registration') : undefined;
		let registrationDays: number | null = null;
		if (registration?.eventDate) {
			const creationTime = new Date(registration.eventDate).getTime();
			if (Number.isFinite(creationTime)) {
				registrationDays = Math.floor((Date.now() - creationTime) / (1000 * 60 * 60 * 24));
			}
		}
		return { registrationDays, registrantOrg: extractRegistrantOrg(data) };
	} catch {
		return EMPTY_RDAP_PROBE;
	}
}

/**
 * Fetch the scan domain's normalised RDAP registrant org for same-entity
 * correlation (issue #263). Reuses {@link probeRdap}; fail-soft `null`.
 */
async function probePrimaryRegistrantOrg(domain: string): Promise<string | null> {
	return (await probeRdap(domain)).registrantOrg;
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
async function probeHasWebContent(domain: string): Promise<boolean> {
	try {
		const resp = await fetch(`https://${domain}/`, {
			method: 'HEAD',
			redirect: 'follow',
			signal: AbortSignal.timeout(WEB_PROBE_TIMEOUT_MS),
		});
		// Any HTTP response means the host is reachable — content exists.
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
