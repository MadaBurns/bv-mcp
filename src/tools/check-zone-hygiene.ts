// SPDX-License-Identifier: BUSL-1.1

/**
 * Zone Hygiene audit tool.
 * Reports the zone's SOA details (via the recursive resolver; no per-nameserver serial
 * comparison) and probes common sensitive subdomains for public DNS resolution.
 *
 * Workers-compatible: uses fetch API only (DNS-over-HTTPS).
 */

import { type CheckResult, type Finding, buildCheckResult, createFinding } from '../lib/scoring';
import { isInconclusiveRcode } from '@blackveil/dns-checks';
import { queryDns, queryDnsRecordsWithRcode } from '../lib/dns';
import { RecordType } from '../lib/dns-types';
import type { QueryDnsOptions } from '../lib/dns-types';
import { SENSITIVE_SUBDOMAINS, analyzeSensitiveSubdomains, isWildcardSynthetic, parseSoaRecord } from './zone-hygiene-analysis';
import type { SubdomainProbeResult, WildcardProbe } from './zone-hygiene-analysis';

/**
 * One A lookup, read raw: the addresses (type 1) AND the CNAME target (type 5) the
 * resolver followed to reach them. The target is what identifies a `*.zone CNAME
 * cdn` wildcard whose CDN hands every new label a different address subset —
 * addresses alone cannot match those. Normalised (lower-case, no trailing dot).
 *
 * `inconclusive` is true when the resolver answered SERVFAIL/REFUSED: an empty `ips` is
 * then "the resolver could not say", not "this name does not resolve".
 */
async function lookupA(fqdn: string, dnsOptions?: QueryDnsOptions): Promise<{ ips: string[]; cname?: string; inconclusive: boolean }> {
	const resp = await queryDns(fqdn, 'A', false, dnsOptions);
	const answers = resp.Answer ?? [];
	const ips = answers.filter((a) => a.type === RecordType.A).map((a) => a.data);
	const cname = answers
		.find((a) => a.type === RecordType.CNAME)
		?.data.toLowerCase()
		.replace(/\.$/, '');
	const inconclusive = isInconclusiveRcode(resp.Status);
	return cname ? { ips, cname, inconclusive } : { ips, inconclusive };
}

/** The info note recorded when a zone-consistency lookup (NS/SOA) never concluded. */
function zoneConsistencyNotAssessed(domain: string, record: 'NS' | 'SOA'): Finding {
	return createFinding(
		'zone_hygiene',
		'Zone consistency not assessed',
		'info',
		`The ${record} lookup for ${domain} was not answered (resolver error or SERVFAIL/REFUSED), so the zone's ${record} configuration could not be assessed. This is a failed probe, not evidence that the record is missing. Re-run check_zone_hygiene to complete it.`,
		{ inconclusive: true, errorKind: 'dns_error', record },
	);
}

/**
 * One AAAA lookup (#942), read the same way. Spent ONLY when the A canary came back
 * completely empty, so a zone with an IPv4 wildcard never pays for it.
 */
async function lookupAaaa(fqdn: string, dnsOptions?: QueryDnsOptions): Promise<string[]> {
	const resp = await queryDns(fqdn, 'AAAA', false, dnsOptions);
	return (resp.Answer ?? []).filter((a) => a.type === RecordType.AAAA).map((a) => a.data);
}

/**
 * Wildcard canary (#930). Same shape as the `ns` check's probe (`_bv-probe-<nonce>`),
 * so the scan-level nonce normalisation in test/scan-domain-dns-semaphore.spec.ts
 * already covers it. A random label per call: a fixed one could be registered.
 *
 * Four outcomes, four different claims — a thrown query is NOT "no wildcard":
 * reading it that way would let a transient resolver failure hand the sweep a
 * confident verdict it cannot support (the fail-open shape CLAUDE.md warns about).
 * A CNAME-only answer (dangling wildcard alias, no address) still counts as
 * `detected`: the zone answers for arbitrary names even though nothing "resolves".
 *
 * #942: an empty A answer no longer settles it. The DoH record layer filters answers
 * to the requested type, so an AAAA-only wildcard used to read as `absent` and the
 * A-only sweep below then earned a clean "no sensitive subdomains resolve publicly"
 * verdict for names that DO resolve over IPv6. One conditional AAAA query — never
 * issued on a zone whose A canary answered — turns that into the distinct
 * `detected_ipv6` outcome, which withholds the clean verdict without inventing hits.
 * A thrown AAAA query is `inconclusive` for the same reason a thrown A query is: the
 * sweep's answers could not be interpreted either way.
 */
async function probeWildcard(domain: string, dnsOptions?: QueryDnsOptions): Promise<WildcardProbe> {
	const probeSubdomain = `_bv-probe-${Math.random().toString(36).substring(2, 10)}.${domain}`;
	try {
		const { ips, cname } = await lookupA(probeSubdomain, dnsOptions);
		if (ips.length === 0 && cname === undefined) {
			// The A canary ANSWERED, and its answer is that this zone synthesises no IPv4
			// wildcard. The sensitive-subdomain sweep below is IPv4-only (`lookupA`), so that
			// one fact already settles every hit the sweep can produce — an IPv4 hit here
			// cannot be wildcard-synthetic. The AAAA canary is a STRICT ADDITION on top: it can
			// only UPGRADE the verdict to `detected_ipv6`. It must never be able to WITHDRAW a
			// measurement the A canary already made, so it gets its own catch.
			//
			// Inside the outer try it did exactly that: on any domain with no IPv4 wildcard —
			// the common case, not the rare one — a single flaked AAAA query returned
			// `inconclusive`, which skips the whole sweep and reports the check unassessed with
			// a note claiming we could not tell a resolving hit from a wildcard answer. The A
			// canary had told us precisely that. Same rule the `detected_ipv6` arm already
			// states: never route a measurement that WAS taken through the inconclusive lane.
			let v6: string[] = [];
			try {
				v6 = await lookupAaaa(probeSubdomain, dnsOptions);
			} catch {
				v6 = [];
			}
			if (v6.length > 0) return { status: 'detected_ipv6', ips: v6, probeSubdomain };
			return { status: 'absent', probeSubdomain };
		}
		return { status: 'detected', ips, ...(cname ? { cnameTarget: cname } : {}), probeSubdomain };
	} catch {
		return { status: 'inconclusive', probeSubdomain };
	}
}

/**
 * Audit DNS zone consistency and detect sensitive subdomains.
 *
 * 1. Queries NS records, then SOA for serial consistency analysis.
 * 2. Probes common sensitive subdomains (vpn, admin, staging, etc.) for public resolution.
 *
 * @param domain - The domain to check (must already be validated and sanitized)
 * @param dnsOptions - Optional DNS query options (e.g., scan-context optimizations)
 * @returns CheckResult with zone hygiene findings
 */
export async function checkZoneHygiene(domain: string, dnsOptions?: QueryDnsOptions): Promise<CheckResult> {
	const findings: Finding[] = [];
	// Set when the NS/SOA lookup never concluded (SERVFAIL/REFUSED): the result is then a
	// non-answer for that half, so it must not be cached for the 5-minute TTL.
	let consistencyInconclusive = false;

	// Phase 1: SOA Consistency Check
	try {
		// SERVFAIL/REFUSED is the resolver failing to answer, not the zone lacking the record,
		// so an empty answer is only a missing control when the rcode says it concluded.
		const nsOutcome = await queryDnsRecordsWithRcode(domain, 'NS', dnsOptions);
		const nameservers = nsOutcome.records.map((ns) => ns.replace(/\.$/, ''));

		if (nameservers.length === 0) {
			if (nsOutcome.inconclusive) {
				consistencyInconclusive = true;
				findings.push(zoneConsistencyNotAssessed(domain, 'NS'));
			} else {
				findings.push(
					createFinding('zone_hygiene', 'No NS records found', 'medium', `No nameserver records were returned for ${domain}. Unable to perform zone consistency analysis.`, { missingControl: true }),
				);
			}
		} else {
			// Query SOA record for the domain
			const soaOutcome = await queryDnsRecordsWithRcode(domain, 'SOA', dnsOptions);
			const soaRecords = soaOutcome.records;

			if (soaRecords.length === 0) {
				if (soaOutcome.inconclusive) {
					consistencyInconclusive = true;
					findings.push(zoneConsistencyNotAssessed(domain, 'SOA'));
				} else {
					findings.push(
						createFinding('zone_hygiene', 'No SOA record found', 'medium', `No SOA record was returned for ${domain}. Every zone must have exactly one SOA record.`, { missingControl: true }),
					);
				}
			} else {
				const soa = parseSoaRecord(soaRecords[0]);

				if (!soa) {
					findings.push(
						createFinding('zone_hygiene', 'SOA record parse failure', 'info', `The SOA record for ${domain} could not be parsed: ${soaRecords[0]}`),
					);
				} else {
					// NO per-nameserver serial comparison here. DoH reaches a recursive resolver, so
					// we hold ONE SOA answer; fanning that single serial out across the NS list and
					// handing it to `analyzeSoaConsistency` made every nameserver "agree" by
					// construction: the high "serial mismatch" finding could never fire and the
					// "consistent across all nameservers" pass was fabricated. Comparing the real
					// per-NS serials needs authoritative (TCP/53) probes (check_authoritative_dns_infra
					// makes them); this DoH-only check does not, so it asserts neither outcome.

					// Report SOA details as info
					findings.push(
						createFinding(
							'zone_hygiene',
							'SOA record details',
							'info',
							`SOA for ${domain}: primary NS ${soa.primaryNs}, serial ${soa.serial}, refresh ${soa.refresh}s, retry ${soa.retry}s, expire ${soa.expire}s, minimum TTL ${soa.minimum}s.`,
							{
								primaryNs: soa.primaryNs,
								serial: soa.serial,
								refresh: soa.refresh,
								retry: soa.retry,
								expire: soa.expire,
								minimum: soa.minimum,
								nameservers,
							},
						),
					);

					// Check for short expire (< 1 week = 604800s)
					if (soa.expire < 604800) {
						findings.push(
							createFinding(
								'zone_hygiene',
								'SOA expire value is short',
								'low',
								// #807: keep this wording consistent with the ns-analysis SOA-expire templates (no bare `<`).
								`SOA expire value is ${soa.expire}s, below the recommended 604800s (1 week). If the primary NS becomes unreachable, secondaries will stop serving the zone sooner than recommended.`,
								{ expire: soa.expire },
							),
						);
					}
				}
			}
		}
	} catch {
		findings.push(
			createFinding(
				'zone_hygiene',
				'Zone consistency check failed',
				'info',
				'DNS queries for NS/SOA records failed. Zone consistency could not be assessed.',
			),
		);
	}

	// Phase 2: Sensitive Subdomain Probing (batched to limit concurrent DNS queries)
	//
	// #930: a wildcard record answers for every name, so a zone like futuresoft.dk
	// (`*.futuresoft.dk A …`) used to yield ten medium "Internal subdomain resolves
	// publicly" findings plus "Excessive exposure" for hosts that do not exist — −165
	// on a category that additive penalties floor at 0. One canary query first; if it
	// fails, the sweep is skipped (its answers could not be interpreted) and the
	// category abstains on this signal rather than passing or failing it.
	let wildcard = await probeWildcard(domain, dnsOptions);
	if (wildcard.status === 'inconclusive') {
		findings.push(...analyzeSensitiveSubdomains([], wildcard));
		// `partial: true` only keeps the incomplete result out of the 5-minute cache; the
		// ENGINE reads `checkStatus`, and an absent one counts as measured
		// (`isCheckMeasured`, scoring/evidence.ts). Same split as check-subdomain-takeover's
		// markProbeInconclusive: if the SOA half produced scored evidence the category
		// stands on that; if every finding is `info` the only thing an unflagged result
		// would assert is a clean 100 the withheld sweep cannot support, so EXCLUDE it.
		const result = { ...buildCheckResult('zone_hygiene', findings), partial: true };
		if (findings.some((f) => f.severity !== 'info')) return result;
		return { ...result, score: 0, passed: false, checkStatus: 'error' };
	}

	const PROBE_BATCH_SIZE = 5;
	const probeResults: SubdomainProbeResult[] = [];
	// Names whose A query was rejected or answered SERVFAIL/REFUSED. These are NOT
	// `resolves: false` — that is a measurement ("no such host"), and these never made one —
	// so they stay out of `probeResults` and are reported separately below.
	const failedProbes: string[] = [];

	for (let i = 0; i < SENSITIVE_SUBDOMAINS.length; i += PROBE_BATCH_SIZE) {
		const batch = SENSITIVE_SUBDOMAINS.slice(i, i + PROBE_BATCH_SIZE);
		const settled = await Promise.allSettled(
			batch.map(async (subdomain): Promise<SubdomainProbeResult | null> => {
				const fqdn = `${subdomain}.${domain}`;
				try {
					const { ips, cname, inconclusive } = await lookupA(fqdn, dnsOptions);
					// SERVFAIL/REFUSED with nothing in the answer is "could not say", not "absent".
					// (An answer that carries an address/alias is evidence whatever the rcode.)
					if (inconclusive && ips.length === 0 && cname === undefined) {
						failedProbes.push(fqdn);
						return null;
					}
					return {
						subdomain: fqdn,
						resolves: ips.length > 0,
						ips,
						...(cname ? { cname } : {}),
					} as SubdomainProbeResult;
				} catch {
					failedProbes.push(fqdn);
					return null;
				}
			}),
		);
		for (const result of settled) {
			if (result.status === 'fulfilled' && result.value) {
				probeResults.push(result.value);
			}
		}
	}

	// A wildcard may answer from a pool (round-robin / CDN), so a hit whose address is
	// not the first canary's answer is not yet proven real. Spend ONE confirming canary,
	// only when such a hit exists, and widen the wildcard answer set with whatever it
	// returns — total canary cost stays at most 2 queries per check.
	if (wildcard.status === 'detected') {
		const detected = wildcard;
		const unexplained = probeResults.some((r) => r.resolves && !isWildcardSynthetic(r, detected));
		if (unexplained) {
			const confirm = await probeWildcard(domain, dnsOptions);
			if (confirm.status === 'detected') {
				wildcard = {
					...detected,
					ips: [...new Set([...detected.ips, ...confirm.ips])],
					...((detected.cnameTarget ?? confirm.cnameTarget) ? { cnameTarget: detected.cnameTarget ?? confirm.cnameTarget } : {}),
				};
			}
		}
	}

	const subdomainFindings = analyzeSensitiveSubdomains(probeResults, wildcard);
	if (failedProbes.length === 0) {
		findings.push(...subdomainFindings);
	} else {
		// "No sensitive subdomains resolve publicly" certifies ALL ten names; with any query
		// unanswered that claim is unsupported, so it is withheld (matched on its exact title,
		// emitted only by `analyzeSensitiveSubdomains`) and replaced by an explicit partial
		// statement. Hits and wildcard notes from the names that DID answer are kept as-is.
		findings.push(...subdomainFindings.filter((f) => f.title !== 'No sensitive subdomains resolve publicly'));
		findings.push(
			createFinding(
				'zone_hygiene',
				'Sensitive subdomain probe incomplete',
				'info',
				`${failedProbes.length} of ${SENSITIVE_SUBDOMAINS.length} internal subdomain name(s) (${failedProbes.join(', ')}) could not be queried (resolver error or SERVFAIL/REFUSED), so a clean "no sensitive subdomains resolve publicly" verdict cannot be given. Names that answered are reported as usual; the unqueried names are neither cleared nor flagged. Re-run check_zone_hygiene to complete this probe.`,
				{ inconclusive: true, errorKind: 'dns_error', failedProbes: [...failedProbes] },
			),
		);
	}

	const result = buildCheckResult('zone_hygiene', findings);
	if (failedProbes.length === 0 && !consistencyInconclusive) return result;

	// A half-measured result is not cached (`partial`). If NOTHING scored was measured —
	// every sweep name failed and the NS/SOA half is info-only — the only thing an unflagged
	// result could assert is a clean 100 nobody measured, so EXCLUDE it (same split as the
	// inconclusive-canary path above).
	const partialResult = { ...result, partial: true };
	const nothingMeasured = failedProbes.length === SENSITIVE_SUBDOMAINS.length && findings.every((f) => f.severity === 'info');
	if (!nothingMeasured) return partialResult;
	return { ...partialResult, score: 0, passed: false, checkStatus: 'error' as const };
}
