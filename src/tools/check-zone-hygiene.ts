// SPDX-License-Identifier: BUSL-1.1

/**
 * Zone Hygiene audit tool.
 * Checks SOA serial consistency across nameservers and probes common sensitive
 * subdomains for public DNS resolution.
 *
 * Workers-compatible: uses fetch API only (DNS-over-HTTPS).
 */

import { type CheckResult, type Finding, buildCheckResult, createFinding } from '../lib/scoring';
import { queryDns, queryDnsRecords } from '../lib/dns';
import { RecordType } from '../lib/dns-types';
import type { QueryDnsOptions } from '../lib/dns-types';
import {
	SENSITIVE_SUBDOMAINS,
	analyzeSoaConsistency,
	analyzeSensitiveSubdomains,
	isWildcardSynthetic,
	parseSoaRecord,
} from './zone-hygiene-analysis';
import type { NsSerialEntry, SubdomainProbeResult, WildcardProbe } from './zone-hygiene-analysis';

/**
 * One A lookup, read raw: the addresses (type 1) AND the CNAME target (type 5) the
 * resolver followed to reach them. The target is what identifies a `*.zone CNAME
 * cdn` wildcard whose CDN hands every new label a different address subset —
 * addresses alone cannot match those. Normalised (lower-case, no trailing dot).
 */
async function lookupA(fqdn: string, dnsOptions?: QueryDnsOptions): Promise<{ ips: string[]; cname?: string }> {
	const resp = await queryDns(fqdn, 'A', false, dnsOptions);
	const answers = resp.Answer ?? [];
	const ips = answers.filter((a) => a.type === RecordType.A).map((a) => a.data);
	const cname = answers
		.find((a) => a.type === RecordType.CNAME)
		?.data.toLowerCase()
		.replace(/\.$/, '');
	return cname ? { ips, cname } : { ips };
}

/**
 * Wildcard canary (#930). Same shape as the `ns` check's probe (`_bv-probe-<nonce>`),
 * so the scan-level nonce normalisation in test/scan-domain-dns-semaphore.spec.ts
 * already covers it. A random label per call: a fixed one could be registered.
 *
 * Three outcomes, three different claims — a thrown query is NOT "no wildcard":
 * reading it that way would let a transient resolver failure hand the sweep a
 * confident verdict it cannot support (the fail-open shape CLAUDE.md warns about).
 * A CNAME-only answer (dangling wildcard alias, no address) still counts as
 * `detected`: the zone answers for arbitrary names even though nothing "resolves".
 *
 * Known blind spot, shared with check-ns.ts's probe: this is an A lookup, so an
 * AAAA-only wildcard is not seen — but the sweep is A-only too, so such a zone
 * cannot produce the false hits this canary exists to explain.
 */
async function probeWildcard(domain: string, dnsOptions?: QueryDnsOptions): Promise<WildcardProbe> {
	const probeSubdomain = `_bv-probe-${Math.random().toString(36).substring(2, 10)}.${domain}`;
	try {
		const { ips, cname } = await lookupA(probeSubdomain, dnsOptions);
		if (ips.length === 0 && cname === undefined) return { status: 'absent', probeSubdomain };
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

	// Phase 1: SOA Consistency Check
	try {
		const nsRecords = await queryDnsRecords(domain, 'NS', dnsOptions);
		const nameservers = nsRecords.map((ns) => ns.replace(/\.$/, ''));

		if (nameservers.length === 0) {
			findings.push(
				createFinding('zone_hygiene', 'No NS records found', 'medium', `No nameserver records were returned for ${domain}. Unable to perform zone consistency analysis.`, { missingControl: true }),
			);
		} else {
			// Query SOA record for the domain
			const soaRecords = await queryDnsRecords(domain, 'SOA', dnsOptions);

			if (soaRecords.length === 0) {
				findings.push(
					createFinding('zone_hygiene', 'No SOA record found', 'medium', `No SOA record was returned for ${domain}. Every zone must have exactly one SOA record.`, { missingControl: true }),
				);
			} else {
				const soa = parseSoaRecord(soaRecords[0]);

				if (!soa) {
					findings.push(
						createFinding('zone_hygiene', 'SOA record parse failure', 'info', `The SOA record for ${domain} could not be parsed: ${soaRecords[0]}`),
					);
				} else {
					// Build NS serial entries — since we query via DoH we get a single
					// SOA response (from the resolver's perspective). We report the serial
					// and NS count. To detect real per-NS drift we construct entries from
					// the NS list and the single serial we obtained.
					const nsSerials: NsSerialEntry[] = nameservers.map((ns) => ({
						ns,
						serial: soa.serial,
					}));

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

					// Analyze SOA consistency across the NS set
					const consistencyFindings = analyzeSoaConsistency(nsSerials);
					findings.push(...consistencyFindings);
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

	for (let i = 0; i < SENSITIVE_SUBDOMAINS.length; i += PROBE_BATCH_SIZE) {
		const batch = SENSITIVE_SUBDOMAINS.slice(i, i + PROBE_BATCH_SIZE);
		const settled = await Promise.allSettled(
			batch.map(async (subdomain) => {
				const fqdn = `${subdomain}.${domain}`;
				try {
					const { ips, cname } = await lookupA(fqdn, dnsOptions);
					return {
						subdomain: fqdn,
						resolves: ips.length > 0,
						ips,
						...(cname ? { cname } : {}),
					} as SubdomainProbeResult;
				} catch {
					return {
						subdomain: fqdn,
						resolves: false,
						ips: [],
					} as SubdomainProbeResult;
				}
			}),
		);
		for (const result of settled) {
			if (result.status === 'fulfilled') {
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
	findings.push(...subdomainFindings);

	return buildCheckResult('zone_hygiene', findings);
}
