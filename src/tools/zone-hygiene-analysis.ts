// SPDX-License-Identifier: BUSL-1.1

import type { Finding } from '../lib/scoring';
import { createFinding } from '../lib/scoring';

/**
 * Common internal/sensitive subdomains to probe for public DNS resolution.
 * These subdomains, if publicly resolvable, may leak internal infrastructure details.
 */
export const SENSITIVE_SUBDOMAINS = [
	'vpn',
	'admin',
	'staging',
	'dev',
	'test',
	'corp',
	'intranet',
	'internal',
	'portal',
	'owa',
] as const;

/** Parsed SOA record fields. */
export interface SoaRecord {
	primaryNs: string;
	adminEmail: string;
	serial: number;
	refresh: number;
	retry: number;
	expire: number;
	minimum: number;
}

/**
 * Parse an SOA record data string into its component fields.
 *
 * SOA data format: `ns1.example.com. admin.example.com. 2024010101 7200 3600 1209600 300`
 *
 * @param data - Raw SOA record data string from DNS
 * @returns Parsed SOA fields, or null if the data is invalid
 */
export function parseSoaRecord(data: string): SoaRecord | null {
	if (!data || typeof data !== 'string') return null;

	const parts = data.trim().split(/\s+/);
	if (parts.length < 7) return null;

	const serial = parseInt(parts[2], 10);
	const refresh = parseInt(parts[3], 10);
	const retry = parseInt(parts[4], 10);
	const expire = parseInt(parts[5], 10);
	const minimum = parseInt(parts[6], 10);

	if ([serial, refresh, retry, expire, minimum].some((v) => !Number.isFinite(v) || v < 0)) {
		return null;
	}

	return {
		primaryNs: parts[0].replace(/\.$/, ''),
		adminEmail: parts[1].replace(/\.$/, ''),
		serial,
		refresh,
		retry,
		expire,
		minimum,
	};
}

/** Input for SOA consistency analysis: nameserver hostname and its serial (null if query failed). */
export interface NsSerialEntry {
	ns: string;
	serial: number | null;
}

/**
 * Analyze SOA serial consistency across nameservers.
 *
 * Compares serial numbers returned by different NS to detect zone drift
 * (stale secondaries that haven't received updates).
 *
 * @param nsSerials - Array of nameserver-to-serial mappings
 * @returns Findings for the zone_hygiene category
 */
export function analyzeSoaConsistency(nsSerials: NsSerialEntry[]): Finding[] {
	const findings: Finding[] = [];

	const responded = nsSerials.filter((entry) => entry.serial !== null);
	const failed = nsSerials.filter((entry) => entry.serial === null);

	if (responded.length < 2) {
		findings.push(
			createFinding(
				'zone_hygiene',
				'Insufficient NS responses for SOA comparison',
				'info',
				`Only ${responded.length} nameserver(s) returned SOA data. At least 2 are needed for serial consistency comparison.`,
			),
		);
		return findings;
	}

	// Check if all serials match
	const serials = new Set(responded.map((entry) => entry.serial));

	if (serials.size === 1) {
		findings.push(
			createFinding(
				'zone_hygiene',
				'SOA serial numbers consistent across all nameservers',
				'info',
				`All ${responded.length} nameservers report the same SOA serial (${responded[0].serial}). Zone data is synchronized.`,
				{ serial: responded[0].serial, nsCount: responded.length },
			),
		);
	} else {
		// Build serial-to-NS mapping for the detail string
		const serialMap: Record<string, string[]> = {};
		for (const entry of responded) {
			const key = String(entry.serial);
			if (!serialMap[key]) serialMap[key] = [];
			serialMap[key].push(entry.ns);
		}

		const detailParts = Object.entries(serialMap).map(([serial, nsList]) => `serial ${serial}: ${nsList.join(', ')}`);

		const serialMetadata: Record<string, number> = {};
		for (const entry of responded) {
			serialMetadata[entry.ns] = entry.serial!;
		}

		findings.push(
			createFinding(
				'zone_hygiene',
				'NS SOA serial mismatch (stale zone)',
				'high',
				`SOA serial numbers differ across nameservers, indicating zone propagation lag or stale secondaries. ${detailParts.join('; ')}.`,
				{ serials: serialMetadata },
			),
		);
	}

	// Note failed NS responses
	if (failed.length > 0) {
		findings.push(
			createFinding(
				'zone_hygiene',
				'NS configuration drift',
				'medium',
				`${failed.length} nameserver(s) failed to respond with SOA data: ${failed.map((e) => e.ns).join(', ')}. This may indicate misconfigured or unreachable secondaries.`,
				{ failedNs: failed.map((e) => e.ns) },
			),
		);
	}

	return findings;
}

/** Input for sensitive subdomain analysis. */
export interface SubdomainProbeResult {
	subdomain: string;
	resolves: boolean;
	ips: string[];
	/** Normalised CNAME target from the same A lookup, when the name is an alias (#930). */
	cname?: string;
}

/**
 * Outcome of the wildcard canary that precedes the sensitive-name sweep (#930).
 *
 * A wildcard record (`*.<zone>`) answers for EVERY name, so on such a zone the ten
 * probed internal names all "resolve" — to the wildcard's address — whether or not
 * the hosts exist. The canary is a label that cannot exist; what it answers with is
 * the wildcard answer, and any sweep hit carrying that answer is wildcard-synthetic.
 *
 * - `detected`: the canary resolved; `ips` is the union of every canary answer seen.
 * - `detected_ipv6`: the canary resolved over AAAA ONLY (#942) — the zone answers for
 *   arbitrary names, but not in the family the sweep queries.
 * - `absent`: the canary returned no answer in EITHER family — the sweep is interpreted
 *   as before.
 * - `inconclusive`: the canary query itself FAILED (transport error / timeout). The
 *   sweep cannot be interpreted either way, so it is not run and not reported.
 *
 * ⚠️ `detected_ipv6` is a DISTINCT status, deliberately NOT a `family` flag on
 * `detected`: `isWildcardSynthetic` compares a hit's IPv4 answers against the wildcard's
 * addresses, and feeding it v6 addresses would let a v6 wildcard fold a REAL IPv4 hit
 * into nothing — silently downgrading a genuine `medium`. The v6 arm must never reach it.
 */
export type WildcardProbe =
	| { status: 'detected'; ips: string[]; cnameTarget?: string; probeSubdomain: string }
	| { status: 'detected_ipv6'; ips: string[]; probeSubdomain: string }
	| { status: 'absent'; probeSubdomain: string }
	| { status: 'inconclusive'; probeSubdomain: string };

/** The `detected` arm of {@link WildcardProbe}. */
export type DetectedWildcard = Extract<WildcardProbe, { status: 'detected' }>;

/**
 * A sweep hit is wildcard-synthetic when it is explained by the wildcard answer:
 * either its CNAME target is the wildcard's CNAME target (a `*.zone CNAME cdn`
 * pool hands each new label its own address subset, so addresses alone cannot
 * match), or EVERY one of its addresses is a wildcard answer. `every`, not `some`:
 * a real host that also carries the wildcard's address alongside its own must
 * stay a real host.
 */
export function isWildcardSynthetic(entry: SubdomainProbeResult, wildcard: Pick<DetectedWildcard, 'ips' | 'cnameTarget'>): boolean {
	if (entry.cname !== undefined && wildcard.cnameTarget !== undefined && entry.cname === wildcard.cnameTarget) return true;
	return entry.ips.length > 0 && entry.ips.every((ip) => wildcard.ips.includes(ip));
}

/**
 * Analyze sensitive subdomain probe results.
 *
 * Identifies internal/infrastructure subdomains that resolve publicly,
 * which may leak internal network topology or attack surface.
 *
 * With a `detected` wildcard probe (#930), hits that carry the wildcard answer are
 * folded into ONE `info` observation rather than scored: they are evidence of the
 * wildcard, not of the hosts. Only hits with a DIFFERENT answer keep their scored
 * `medium`, and only those count toward "Excessive". The clean "No sensitive
 * subdomains resolve publicly" verdict is withheld on a wildcard zone — public DNS
 * cannot support it there. An `inconclusive` probe yields only an abstention note
 * (`inconclusive` + `errorKind`, never `missingControl`): the sweep was not run.
 *
 * A `detected_ipv6` probe (#942) is the narrow middle case: the sweep DID run and it is
 * IPv4-only, so every hit it found is REAL evidence — an AAAA wildcard cannot fabricate
 * an A answer — and keeps its scored `medium` (and its place in the "Excessive" count).
 * Only the CLEAN verdict is unsupportable, because a name that fails to resolve over
 * IPv4 may still resolve over the wildcard's IPv6. So this arm withholds that one
 * finding and adds a single `info` note: score-neutral by construction, and NOT routed
 * through the `inconclusive` / `checkStatus: 'error'` abstention lane, which would
 * discard measurements that were actually taken.
 *
 * @param results - Array of subdomain probe results
 * @param wildcard - Outcome of the wildcard canary; absent/`absent` = legacy behaviour
 * @returns Findings for the zone_hygiene category
 */
export function analyzeSensitiveSubdomains(results: SubdomainProbeResult[], wildcard?: WildcardProbe): Finding[] {
	const findings: Finding[] = [];

	if (wildcard?.status === 'inconclusive') {
		findings.push(
			createFinding(
				'zone_hygiene',
				'Sensitive subdomain probe not assessed',
				'info',
				`The wildcard canary query (${wildcard.probeSubdomain}) failed, so the internal subdomain sweep (vpn, admin, staging, dev, etc.) was not run: without knowing whether the zone answers for arbitrary names, a resolving hit could not be told from a wildcard answer. Re-run check_zone_hygiene to complete this probe.`,
				{ inconclusive: true, errorKind: 'dns_error', probeSubdomain: wildcard.probeSubdomain },
			),
		);
		return findings;
	}

	if (wildcard?.status === 'detected_ipv6') {
		findings.push(
			createFinding(
				'zone_hygiene',
				'Wildcard DNS (IPv6) masks the sensitive-subdomain verdict',
				'info',
				`The zone answers for arbitrary names over IPv6 (canary ${wildcard.probeSubdomain} resolved to ${wildcard.ips.join(', ')}) while returning no IPv4 answer, indicating an AAAA-only wildcard record. The internal-name sweep queries A records, so a name that returned no IPv4 address cannot be shown absent — it may still resolve through the wildcard over IPv6 — and the clean "no sensitive subdomains resolve publicly" verdict is therefore withheld. Any name that DID resolve over IPv4 is reported normally: an IPv6 wildcard cannot produce an IPv4 answer, so those hits are real.`,
				{
					wildcardDetected: true,
					wildcardFamily: 'aaaa',
					wildcardIps: wildcard.ips,
					probeSubdomain: wildcard.probeSubdomain,
				},
			),
		);
	}

	const hits = results.filter((r) => r.resolves);
	const synthetic = wildcard?.status === 'detected' ? hits.filter((r) => isWildcardSynthetic(r, wildcard)) : [];
	const resolving = wildcard?.status === 'detected' ? hits.filter((r) => !isWildcardSynthetic(r, wildcard)) : hits;

	if (wildcard?.status === 'detected') {
		const wildcardIps = wildcard.ips;
		const answer =
			wildcardIps.length > 0
				? `resolved to ${wildcardIps.join(', ')}${wildcard.cnameTarget ? ` via ${wildcard.cnameTarget}` : ''}`
				: `is an alias for ${wildcard.cnameTarget} that yields no address`;
		findings.push(
			createFinding(
				'zone_hygiene',
				'Wildcard DNS masks sensitive subdomain probing',
				'info',
				`The zone answers for arbitrary names (canary ${wildcard.probeSubdomain} ${answer}), indicating a wildcard record. ` +
					(synthetic.length > 0
						? `${synthetic.length} probed internal name(s) returned that same wildcard answer (${synthetic.map((r) => r.subdomain).join(', ')}) — this is not evidence that those hosts exist. `
						: '') +
					'Sensitive-subdomain exposure cannot be assessed from public DNS on a wildcard zone; the wildcard itself is scored by the ns check.',
				{
					wildcardDetected: true,
					wildcardIps,
					...(wildcard.cnameTarget ? { wildcardCnameTarget: wildcard.cnameTarget } : {}),
					probeSubdomain: wildcard.probeSubdomain,
					wildcardSyntheticSubdomains: synthetic.map((r) => r.subdomain),
				},
			),
		);
		if (resolving.length === 0) return findings;
	}

	if (resolving.length === 0) {
		// #942: on an AAAA-only wildcard zone the IPv4 sweep cannot prove absence, so the
		// clean verdict is withheld — the note above already stands in its place, and it
		// is `info`, which keeps this arm score-neutral.
		if (wildcard?.status === 'detected_ipv6') return findings;
		findings.push(
			createFinding(
				'zone_hygiene',
				'No sensitive subdomains resolve publicly',
				'info',
				'None of the probed internal subdomain names (vpn, admin, staging, dev, etc.) resolve to public IP addresses.',
			),
		);
		return findings;
	}

	// Report each resolving subdomain
	for (const entry of resolving) {
		findings.push(
			createFinding(
				'zone_hygiene',
				`Internal subdomain resolves publicly: ${entry.subdomain}`,
				'medium',
				`The subdomain ${entry.subdomain} resolves to ${entry.ips.join(', ')}. Internal infrastructure names visible in public DNS increase attack surface.`,
				{ subdomain: entry.subdomain, ips: entry.ips },
			),
		);
	}

	// Flag excessive exposure
	if (resolving.length >= 3) {
		findings.push(
			createFinding(
				'zone_hygiene',
				`Excessive internal subdomain exposure (${resolving.length} found)`,
				'medium',
				`${resolving.length} sensitive subdomains resolve publicly: ${resolving.map((r) => r.subdomain).join(', ')}. This level of internal DNS exposure significantly increases reconnaissance surface for attackers.`,
				{ count: resolving.length, subdomains: resolving.map((r) => r.subdomain) },
			),
		);
	}

	return findings;
}
