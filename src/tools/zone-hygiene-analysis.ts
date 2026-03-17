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
}

/**
 * Analyze sensitive subdomain probe results.
 *
 * Identifies internal/infrastructure subdomains that resolve publicly,
 * which may leak internal network topology or attack surface.
 *
 * @param results - Array of subdomain probe results
 * @returns Findings for the zone_hygiene category
 */
export function analyzeSensitiveSubdomains(results: SubdomainProbeResult[]): Finding[] {
	const findings: Finding[] = [];
	const resolving = results.filter((r) => r.resolves);

	if (resolving.length === 0) {
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
