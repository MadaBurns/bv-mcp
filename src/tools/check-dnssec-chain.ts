// SPDX-License-Identifier: BUSL-1.1

/**
 * DNSSEC Chain-of-Trust Walk tool.
 * Walks the DNSSEC chain from root to target domain via DoH, reporting
 * DS/DNSKEY records and linkage at each zone level.
 *
 * Limitations (disclosed in output):
 * - No cryptographic RRSIG verification. Reports structure and linkage only.
 *
 * Workers-compatible: uses fetch API only (DNS-over-HTTPS).
 */

import { parseDnssecAlgorithmToken } from '@blackveil/dns-checks';
import { queryDns, queryDnsRecords } from '../lib/dns';
import type { QueryDnsOptions } from '../lib/dns-types';
import { buildCheckResult, createFinding } from '../lib/scoring';
import type { CheckResult, CheckCategory } from '../lib/scoring';

const CATEGORY = 'dnssec_chain' as CheckCategory;

/** DNSSEC signing algorithm names (IANA registry). */
const DNSSEC_ALGORITHMS: Record<number, string> = {
	1: 'RSA-MD5',
	3: 'DSA-SHA1',
	5: 'RSA-SHA1',
	6: 'DSA-NSEC3-SHA1',
	7: 'RSA-SHA1-NSEC3',
	8: 'RSA-SHA256',
	10: 'RSA-SHA512',
	12: 'ECC-GOST',
	13: 'ECDSAP256SHA256',
	14: 'ECDSAP384SHA384',
	15: 'Ed25519',
	16: 'Ed448',
};

/** Algorithms considered weak / deprecated. */
const WEAK_ALGORITHMS = new Set([1, 3, 5, 6, 7]);

/** DS digest type names. */
const DIGEST_TYPES: Record<number, string> = { 1: 'SHA-1', 2: 'SHA-256', 4: 'SHA-384' };

/**
 * Linkage status between DS and DNSKEY at a zone.
 * `unverified` is reserved for the root trust anchor when its DNSKEY could not
 * be retrieved — the root is always signed, so an empty result is a retrieval
 * failure, never a broken chain.
 */
type LinkageStatus = 'linked' | 'no_ds' | 'no_dnskey' | 'broken' | 'unverified';

/** Parsed DS record fields. */
interface ParsedDs {
	keyTag: number;
	algorithm: number;
	digestType: number;
	digest: string;
}

/** Parsed DNSKEY record fields. */
interface ParsedDnskey {
	flags: number;
	protocol: number;
	algorithm: number;
	pubkey: string;
	isKsk: boolean;
}

/** Per-zone walk result. */
interface ZoneResult {
	zone: string;
	dsRecords: ParsedDs[];
	dnskeyRecords: ParsedDnskey[];
	linkage: LinkageStatus;
	algorithms: string[];
	weakAlgorithms: string[];
	/**
	 * The DS probe threw (timeout / SERVFAIL / transport failure) rather than
	 * returning an empty answer. Both leave `dsRecords` empty and both make
	 * `determineLinkage()` say 'no_ds', so this flag is the ONLY thing that
	 * separates "the parent holds no DS" (measured) from "we never learned
	 * whether the parent holds a DS" (unmeasured) — the #638 distinction.
	 */
	dsQueryFailed: boolean;
}

// ---------------------------------------------------------------------------
// Parsers
// ---------------------------------------------------------------------------

function parseDsRecord(data: string): ParsedDs | null {
	const parts = data.trim().split(/\s+/);
	if (parts.length < 4) return null;
	const keyTag = parseInt(parts[0], 10);
	// Cloudflare DoH returns the algorithm as an IANA mnemonic (e.g. "ECDSAP256SHA256")
	// rather than a number; parseDnssecAlgorithmToken accepts either form.
	const algorithm = parseDnssecAlgorithmToken(parts[1]);
	const digestType = parseInt(parts[2], 10);
	const digest = parts.slice(3).join('');
	if (!Number.isFinite(keyTag) || algorithm === null || !Number.isFinite(digestType)) return null;
	return { keyTag, algorithm, digestType, digest };
}

function parseDnskeyRecord(data: string): ParsedDnskey | null {
	const parts = data.trim().split(/\s+/);
	if (parts.length < 4) return null;
	const flags = parseInt(parts[0], 10);
	const protocol = parseInt(parts[1], 10);
	// Cloudflare DoH returns the algorithm as an IANA mnemonic (e.g. "ECDSAP256SHA256")
	// rather than a number; parseDnssecAlgorithmToken accepts either form.
	const algorithm = parseDnssecAlgorithmToken(parts[2]);
	const pubkey = parts.slice(3).join('');
	if (!Number.isFinite(flags) || !Number.isFinite(protocol) || algorithm === null) return null;
	return { flags, protocol, algorithm, pubkey, isKsk: flags === 257 };
}

// ---------------------------------------------------------------------------
// Linkage determination
// ---------------------------------------------------------------------------

function determineLinkage(dsRecords: ParsedDs[], dnskeyRecords: ParsedDnskey[]): LinkageStatus {
	if (dsRecords.length === 0) return 'no_ds';
	if (dnskeyRecords.length === 0) return 'no_dnskey';

	// Check if any DS algorithm matches any DNSKEY algorithm
	const dsAlgs = new Set(dsRecords.map((ds) => ds.algorithm));
	const keyAlgs = new Set(dnskeyRecords.map((k) => k.algorithm));
	for (const alg of dsAlgs) {
		if (keyAlgs.has(alg)) return 'linked';
	}
	return 'broken';
}

// ---------------------------------------------------------------------------
// Zone hierarchy builder
// ---------------------------------------------------------------------------

/** Build zone hierarchy: "sub.example.com" → [".", "com", "example.com", "sub.example.com"] */
function buildZoneHierarchy(domain: string): string[] {
	const labels = domain.split('.');
	const zones: string[] = ['.'];
	for (let i = labels.length - 1; i >= 0; i--) {
		zones.push(labels.slice(i).join('.'));
	}
	return zones;
}

// ---------------------------------------------------------------------------
// Main export
// ---------------------------------------------------------------------------

/**
 * Walk the DNSSEC chain of trust from root to the target domain.
 * Queries DS and DNSKEY records at each zone level and reports linkage.
 *
 * @param domain - The domain to check (must already be validated and sanitized)
 * @param dnsOptions - Optional DNS query options
 * @returns CheckResult with chain-of-trust findings
 */
export async function checkDnssecChain(domain: string, dnsOptions?: QueryDnsOptions): Promise<CheckResult> {
	const findings: ReturnType<typeof createFinding>[] = [];
	const zones = buildZoneHierarchy(domain);
	const zoneResults: ZoneResult[] = [];
	let chainBroken = false;
	const weakAlgsFound: string[] = [];

	for (const zone of zones) {
		// Query DS (skip for root — root has no parent to hold DS)
		let dsRecords: ParsedDs[] = [];
		let dsQueryFailed = false;
		if (zone !== '.') {
			try {
				const rawDs = await queryDnsRecords(zone, 'DS', dnsOptions);
				dsRecords = rawDs.map(parseDsRecord).filter((r): r is ParsedDs => r !== null);
			} catch {
				// DS query failed. `dsRecords` stays empty, which is indistinguishable
				// from a measured "no DS" downstream — record the failure so the
				// island-of-trust and chainComplete decisions can refuse to draw a
				// conclusion from a delegation that was never observed.
				dsQueryFailed = true;
			}
		}

		// Query DNSKEY
		let dnskeyRecords: ParsedDnskey[] = [];
		try {
			const rawDnskey = await queryDnsRecords(zone, 'DNSKEY', dnsOptions);
			dnskeyRecords = rawDnskey.map(parseDnskeyRecord).filter((r): r is ParsedDnskey => r !== null);
		} catch {
			// DNSKEY query failed — treat as no DNSKEY
		}

		// Determine linkage. The root has no parent DS; an empty root DNSKEY means
		// the trust anchor could not be retrieved (transient), NOT a broken chain.
		const linkage: LinkageStatus =
			zone === '.' ? (dnskeyRecords.length > 0 ? 'linked' : 'unverified') : determineLinkage(dsRecords, dnskeyRecords);

		// Collect algorithm names
		const allAlgs = new Set<number>();
		for (const ds of dsRecords) allAlgs.add(ds.algorithm);
		for (const key of dnskeyRecords) allAlgs.add(key.algorithm);
		const algorithms = [...allAlgs].map((a) => DNSSEC_ALGORITHMS[a] ?? `Unknown(${a})`);
		const weakAlgorithms = [...allAlgs].filter((a) => WEAK_ALGORITHMS.has(a)).map((a) => DNSSEC_ALGORITHMS[a] ?? `Unknown(${a})`);
		weakAlgsFound.push(...weakAlgorithms);

		zoneResults.push({
			zone,
			dsRecords,
			dnskeyRecords,
			linkage,
			algorithms,
			weakAlgorithms,
			dsQueryFailed,
		});

		if (linkage === 'no_dnskey' || linkage === 'broken') {
			chainBroken = true;
		}

		// Stop walking if zone has no DS and no DNSKEY (unsigned from here down)
		if (zone !== '.' && dsRecords.length === 0 && dnskeyRecords.length === 0) {
			break;
		}
	}

	// Check AD flag on target domain.
	// ⚠️ `adFlag` initialises to `false`, so on a thrown probe the placeholder is
	// INDISTINGUISHABLE from a measured AD=false. `adQueryFailed` is what separates
	// "the resolver told us validation is failing" from "we never asked successfully";
	// scoring the placeholder would record an unissued probe as a deficiency (#638).
	let adFlag = false;
	let adQueryFailed = false;
	// `AD` is `z.boolean().optional()` on a passthrough schema, so a response that
	// simply OMITS the field parses fine and yields `false`. Absent is not the same
	// observation as `false`; only an explicitly present boolean counts as measured.
	let adObserved = false;
	try {
		const adResp = await queryDns(domain, 'A', true, dnsOptions);
		adObserved = typeof adResp.AD === 'boolean';
		adFlag = adResp.AD === true;
	} catch {
		adQueryFailed = true;
	}

	// Determine chain completeness
	const lastZone = zoneResults[zoneResults.length - 1];
	const reachedTarget = lastZone?.zone === domain;
	// The walk loop only ever exits early via the unsigned-zone `break` (no DS AND
	// no DNSKEY at a non-root zone), so `stoppedEarly` means exactly "the chain of
	// trust terminated unsigned at an ANCESTOR of the target".
	const stoppedEarly = !reachedTarget;
	// Chain is complete only if we reached the target AND it's not broken AND the target zone is actually signed
	const targetSigned = reachedTarget && (lastZone.dsRecords.length > 0 || lastZone.dnskeyRecords.length > 0);
	// The root trust anchor must have been retrieved for the chain to be "complete".
	const rootVerified = zoneResults.find((z) => z.zone === '.')?.linkage === 'linked';
	// Island of trust (#834): a non-root zone that publishes a DNSKEY while its parent
	// holds no DS for it. `targetSigned` accepts a DNSKEY alone and linkage 'no_ds'
	// sets neither `chainBroken` nor the walk's unsigned break, so before this guard
	// the shape sailed through to chainComplete: true / score 100 — despite the chain
	// of trust from the root anchor terminating at the parent: the published DNSKEY is
	// unreachable and validating resolvers treat the zone as insecure. The FIRST such
	// zone is where trust terminates (any DS/DNSKEY material below it is equally
	// unreachable from the root anchor).
	// ⚠️ `dsQueryFailed` gate (review follow-up): a timed-out/SERVFAIL DS probe also
	// lands on linkage 'no_ds' with an empty record set, so without this the island
	// finding would score 60 off a delegation nobody measured. An unmeasured DS is
	// reported through the inconclusive lane below instead, never as a deficiency.
	const islandZone = zoneResults.find((z) => z.zone !== '.' && z.linkage === 'no_ds' && z.dnskeyRecords.length > 0 && !z.dsQueryFailed);
	// A zone whose DS probe failed while its DNSKEY resolved is the SAME shape as an
	// island — we simply do not know which. It must not be laundered into a complete
	// chain either (that was the original #834 accidental-100 arriving via the
	// failure path), so it blocks chainComplete without producing a scored finding.
	const dsUnmeasuredZone = zoneResults.find((z) => z.zone !== '.' && z.dsQueryFailed && z.dnskeyRecords.length > 0);
	const chainComplete =
		reachedTarget && !chainBroken && targetSigned && islandZone === undefined && dsUnmeasuredZone === undefined && rootVerified;

	// --- Findings ---

	// Root trust-anchor retrieval failure (informational — NOT a chain break).
	// The root zone is always signed, so an empty DNSKEY result means a transient
	// resolver/cache failure rather than an actually-broken chain.
	if (zoneResults.find((z) => z.zone === '.')?.linkage === 'unverified') {
		findings.push(
			createFinding(
				CATEGORY,
				'Root trust anchor unverified',
				'info',
				'Could not retrieve the root zone (.) DNSKEY, so the chain of trust could not be verified all the way to the trust anchor. The root zone is always signed — an empty result indicates a transient resolver/cache issue, not a broken chain.',
				{ zone: '.', linkage: 'unverified' },
			),
		);
	}

	// Unsigned chain termination (high severity, decoupled penalty). Fires when the
	// walk reached the target and found it unsigned, OR when the walk stopped early
	// at an unsigned ANCESTOR zone (`stoppedEarly`) — the chain of trust is broken at
	// that ancestor, and any DNSSEC material published below it (an island of trust)
	// is unreachable from the root anchor, so validating resolvers treat the target
	// as insecure either way. Before this guard covered `stoppedEarly`, a subdomain
	// under an unsigned parent scored an accidental 100/passed while check_dnssec
	// scored the same domain 60 (#820 review follow-up). Mirrors check_dnssec's
	// "DNSSEC not enabled" finding (packages/dns-checks/src/checks/check-dnssec.ts:130-151):
	// the target has neither a DS in its parent nor a DNSKEY of its own, so the chain of
	// trust terminates at the target and DNSSEC provides no origin authentication for it.
	// The severity LABEL is `high` (per the same NIST SP 800-81r3 / RFC 9364 rationale as
	// check_dnssec — DNSSEC is one of several integrity controls, not a sole baseline), but
	// the SCORE penalty is decoupled to -40 via `penaltyOverride` (100-40=60) rather than the
	// raw high-severity default, keeping this tool's unsigned verdict numerically aligned
	// with scan_domain's dnssec category for the same domain (#810). We deliberately do NOT
	// set `missingControl: true` (that would zero the score to 0 via buildCheckResult's
	// `score: hasMissingControl ? 0 : score`) and the detail text avoids "no … record",
	// "missing", "required", and "not found" so `scoreIndicatesMissingControl`
	// (packages/dns-checks/src/scoring/model.ts:267-285) cannot auto-zero the finding.
	//
	// ⚠️ These states are ONE else-if chain on purpose (#851 review). The chain of
	// trust terminates or breaks at exactly one place, so exactly one of these
	// penalties may ever apply. Emitting them independently made the deductions
	// ADDITIVE, and nothing caps this category (`CATEGORY_PENALTY_CAPS` covers only
	// `subdomain_takeover`): a zone with a DS but no DNSKEY, scanned at a subdomain,
	// fired BOTH the broken (−55) and unsigned-termination (−40) findings for 95 →
	// score 5, and two broken zones summed to 110 → score 0. Both outcomes rank a
	// bogus chain BELOW the floor this ordering exists to establish, which is the
	// very defect being fixed. Additional broken zones are reported in metadata.
	if (chainBroken) {
		const brokenZones = zoneResults.filter((z) => z.linkage === 'no_dnskey' || z.linkage === 'broken');
		// The SHALLOWEST break is the causal one — everything below it is downstream
		// consequence, not an independent deficiency worth its own penalty.
		const bz = brokenZones[0]!;
		const reason = bz.linkage === 'no_dnskey' ? 'DS record exists but no DNSKEY found' : 'DS and DNSKEY algorithm mismatch';
		// `penaltyOverride: 55` (→ 45), NOT the default high −25 (→ 75) this finding
		// carried until #851. The termination findings were given a decoupled −40 (→ 60)
		// to match check_dnssec's unsigned posture, but this one kept the raw severity
		// penalty — ranking a chain that SERVFAILs ABOVE an unanchored-but-resolvable
		// zone. Intended ordering: bogus (45) < island = unsigned (60) < validating (100).
		// No `missingControl`: the DNSSEC material here is measured and present, it is the
		// linkage that fails, and a zero would collapse the ordering again.
		// ⚠️ Keep `reason` clear of "no … record" / "not found" / "missing" / "required":
		// this finding is `deterministic`, so MISSING_CONTROL_REGEX (scoring/model.ts)
		// would auto-zero it. "DS record exists but no DNSKEY found" passes only because
		// the "record" precedes the "no" — it is one word from a silent zeroing.
		// ⚠️ check_dnssec scores this same shape 0 (missingControl). That 45-vs-0
		// divergence is deliberate and tracked on #851 alongside the island one.
		findings.push(
			createFinding(
				CATEGORY,
				`Broken DNSSEC chain at ${bz.zone}`,
				'high',
				`DNSSEC chain is broken at ${bz.zone}: ${reason}. Resolvers that validate DNSSEC will return SERVFAIL for this zone.`,
				{
					zone: bz.zone,
					linkage: bz.linkage,
					penaltyOverride: 55,
					...(brokenZones.length > 1 ? { additionalBrokenZones: brokenZones.slice(1).map((z) => z.zone) } : {}),
				},
			),
		);
	} else if (!targetSigned || stoppedEarly) {
		// The zone where the chain of trust terminated unsigned: the target itself
		// when the walk got there, otherwise the unsigned ancestor it stopped at.
		const terminalZone = stoppedEarly ? (lastZone?.zone ?? domain) : domain;
		const detail = stoppedEarly
			? `DNSSEC is not configured for ${terminalZone}: the chain-of-trust walk found neither a DS at its parent zone nor a DNSKEY published by ${terminalZone} itself, so the chain of trust terminates at ${terminalZone} before reaching ${domain}. Any DNSSEC material published below ${terminalZone} is an unreachable island of trust. Without an intact chain, DNS responses for ${domain} are not cryptographically verified, leaving SPF, DMARC, and DKIM vulnerable to DNS-level manipulation.`
			: `DNSSEC is not configured for ${domain}: the chain-of-trust walk found neither a DS at the parent zone nor a DNSKEY published by ${domain} itself, so the chain terminates here. Without DNSSEC, DNS responses for ${domain} are not cryptographically verified, leaving SPF, DMARC, and DKIM vulnerable to DNS-level manipulation.`;
		findings.push(
			createFinding(CATEGORY, 'DNSSEC chain terminates unsigned', 'high', detail, {
				zone: terminalZone,
				linkage: 'no_ds',
				penaltyOverride: 40,
			}),
		);
	} else if (islandZone) {
		// Island of trust (#834). Same finding convention as the unsigned-termination
		// guard above (#810/#820): severity LABEL `high`, SCORE penalty decoupled to -40
		// via `penaltyOverride` (100-40=60), aligned with check_dnssec's posture for
		// unanchored DNSSEC. We deliberately do NOT set `missingControl: true` — a
		// published-but-unanchored DNSKEY is MEASURED DNSSEC material, not an absent
		// control, and missingControl would zero the score to 0 via buildCheckResult's
		// `score: hasMissingControl ? 0 : score`. (check_dnssec currently scores this
		// same shape 0 with missingControl — reconciling the two surfaces to a single
		// number is a deliberate operator scoring decision, out of scope here.) The
		// detail text avoids "no … record", "missing", "required", and "not found" so
		// `scoreIndicatesMissingControl` (packages/dns-checks/src/scoring/model.ts)
		// cannot auto-zero the finding. `else if`: the chain of trust terminates at
		// exactly one place, so at most one -40 termination finding ever fires.
		findings.push(
			createFinding(
				CATEGORY,
				`DNSSEC island of trust at ${islandZone.zone}`,
				'high',
				`${islandZone.zone} publishes a DNSKEY, but its parent zone holds no DS digest linking to it, so the chain of trust from the root anchor terminates at the parent. The published DNSKEY is unreachable from the trust anchor and validating resolvers treat ${islandZone.zone} as insecure — DNSSEC provides no origin authentication for ${domain}. Publish a DS for the zone's KSK at the parent (via the registrar) to anchor the chain.`,
				{ zone: islandZone.zone, linkage: 'no_ds', penaltyOverride: 40 },
			),
		);
	} else if (dsUnmeasuredZone) {
		// The DS probe for a zone that publishes a DNSKEY never completed. That is the
		// island-of-trust shape OR a perfectly anchored zone — indistinguishable from
		// here. Report it as unmeasured (`inconclusive` + `errorKind`, NEVER
		// `missingControl` — #638 law) with no penalty, and let the `partial` flag
		// below keep the non-answer out of the dispatch cache so a retry can measure it.
		findings.push(
			createFinding(
				CATEGORY,
				`DNSSEC delegation not assessable at ${dsUnmeasuredZone.zone}`,
				'info',
				`The DS lookup for ${dsUnmeasuredZone.zone} did not complete, so the delegation linking its parent to the DNSKEY it publishes could not be observed. The chain of trust for ${domain} is therefore unverified for this run — this reflects the lookup, not the zone's configuration. Re-run to assess it.`,
				{ zone: dsUnmeasuredZone.zone, inconclusive: true, confidence: 'heuristic', errorKind: 'dns_error' },
			),
		);
	}

	// AD-flag disclosure. `chainComplete` is computed from linkage alone and never
	// consulted `adFlag`, so before #851 the flag was measured and then discarded —
	// the summary carried it, nothing else did. Surfacing it closes that gap.
	//
	// ⚠️⚠️ It is surfaced at `info` with NO penalty, deliberately. An earlier cut of
	// this scored a measured `AD=false` on a complete chain as a −55 "validation
	// failing" verdict. That is WRONG, and was caught by measurement, not argument:
	// Cloudflare DoH (prod's primary resolver) returns `AD:false` for correctly-signed
	// zones depending on which POP answers and what that POP has cached — sampled
	// live, `verisign.com` returned false on two of three consecutive queries while
	// Google returned true throughout, and Cloudflare itself returned `AD:true` for
	// other record types of the SAME name in the same minute. Roughly one in five
	// sampled signed domains hit it. AD also reflects whether the RESOLVER validated,
	// not solely whether the zone is sound, and `dns-transport` may transparently swap
	// in a secondary resolver on an empty answer. A penalty built on that signal
	// penalises healthy zones at random — exactly the "confident finding a probe does
	// not support" class this sweep exists to remove. Reporting it without scoring it
	// is what the evidence supports. A sound bogus verdict needs RRSIG verification,
	// which this tool does not do; tracked on #851.
	if (chainComplete && adObserved && !adFlag) {
		findings.push(
			createFinding(
				CATEGORY,
				'DNSSEC chain links, but the resolver did not flag it authenticated',
				'info',
				`The chain of trust for ${domain} links structurally from the root anchor, but the resolver did not set the AD (Authenticated Data) flag on its answer. This is reported, not scored: the AD flag also depends on which resolver and cache answered, and validating resolvers routinely return it unset for sound zones. Treat it as a prompt to verify signature freshness and that the DS digest at the parent still matches the current KSK — not as evidence the zone is bogus. This tool reports structure and linkage and does not verify RRSIGs.`,
				{ confidence: 'heuristic', adFlag: false },
			),
		);
	}

	// Weak algorithm finding (medium severity)
	if (weakAlgsFound.length > 0) {
		const uniqueWeak = [...new Set(weakAlgsFound)];
		findings.push(
			createFinding(
				CATEGORY,
				'Weak DNSSEC algorithm in chain',
				'medium',
				`DNSSEC chain uses deprecated/weak algorithm(s): ${uniqueWeak.join(', ')}. These are considered cryptographically weak and should be migrated to RSA-SHA256 (algorithm 8) or ECDSA (algorithm 13/14).`,
				{ weakAlgorithms: uniqueWeak },
			),
		);
	}

	// Chain summary (always present — info severity)
	const zonesSummary = zoneResults.map((z) => ({
		zone: z.zone,
		dsCount: z.dsRecords.length,
		dnskeyCount: z.dnskeyRecords.length,
		kskCount: z.dnskeyRecords.filter((k) => k.isKsk).length,
		zskCount: z.dnskeyRecords.filter((k) => !k.isKsk).length,
		linkage: z.linkage,
		algorithms: z.algorithms,
		dsDigestTypes: [...new Set(z.dsRecords.map((ds) => DIGEST_TYPES[ds.digestType] ?? `Unknown(${ds.digestType})`))],
	}));

	let summaryStatus: string;
	if (stoppedEarly) {
		summaryStatus = `stopped at ${lastZone?.zone ?? '.'} — zone has no DS and no DNSKEY (not signed)`;
	} else if (!targetSigned) {
		summaryStatus = `${domain} has no DS and no DNSKEY — domain is not signed`;
	} else if (islandZone) {
		summaryStatus = `island of trust — ${islandZone.zone} publishes a DNSKEY but its parent holds no DS, so validating resolvers treat the zone as insecure`;
	} else if (chainComplete) {
		summaryStatus = 'complete chain from root to target';
	} else {
		summaryStatus = 'chain broken';
	}
	// Report the AD flag as UNMEASURED when it was, rather than printing the `false`
	// placeholder as though it were an observation (#851 review): the summary was
	// stating `AD flag: false` in the very run the check declares unassessable, which
	// hands an LLM a fabricated measurement.
	const adSummary = adQueryFailed || !adObserved ? 'not measured' : String(adFlag);
	const summaryDetail = `DNSSEC chain walk for ${domain}: ${summaryStatus}. Zones walked: ${zoneResults.map((z) => z.zone).join(' → ')}. AD flag: ${adSummary}. Limitation: no cryptographic RRSIG verification; reports structure and linkage only.`;

	findings.push(
		createFinding(CATEGORY, 'DNSSEC chain summary', 'info', summaryDetail, {
			chainComplete,
			adFlag: adQueryFailed || !adObserved ? null : adFlag,
			zonesWalked: zoneResults.length,
			zones: zonesSummary,
		}),
	);

	const result = buildCheckResult(CATEGORY, findings) as CheckResult;
	// A transient root-DNSKEY retrieval failure leaves the chain unverified. Mark
	// the result partial so the dispatch cache predicate skips it — otherwise a
	// one-off empty would be cached and served as a stale "unverified" result for
	// the cache TTL (#199).
	// Same reasoning for a DS probe that never completed (review follow-up): the run
	// measured less than it appears to have, so it must not be served from cache as a
	// settled answer for the TTL.
	// Same reasoning again for a failed AD probe on an otherwise complete chain
	// (#851): the run did not establish the validation outcome, so it must not be
	// served from cache as though it had.
	if (zoneResults.find((z) => z.zone === '.')?.linkage === 'unverified' || dsUnmeasuredZone || (chainComplete && adQueryFailed)) {
		result.partial = true;
	}
	return result;
}
