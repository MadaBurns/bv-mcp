// SPDX-License-Identifier: BUSL-1.1

/**
 * Fast-Flux Detection tool (DoH-adapted).
 * Performs multiple rounds of A/AAAA queries with delays between them,
 * comparing IP answer sets and TTLs across rounds to detect fast-flux behavior.
 *
 * Limitations: DoH resolver caching may mask rotation. Lower fidelity than
 * direct UDP probing.
 *
 * Workers-compatible: uses fetch API only (DNS-over-HTTPS).
 */

import { queryDns } from '../lib/dns';
import type { DnsAnswer, QueryDnsOptions } from '../lib/dns-types';
import { buildCheckResult, createFinding } from '../lib/scoring';
import type { CheckResult, CheckCategory, Finding } from '../lib/scoring';

const CATEGORY = 'fast_flux' as CheckCategory;

/** A-record type code */
const TYPE_A = 1;
/** AAAA-record type code */
const TYPE_AAAA = 28;

interface RoundResult {
	ips: string[];
	minTtl: number;
}

/**
 * Detect fast-flux DNS behavior by querying A/AAAA records across multiple rounds.
 *
 * @param domain - The domain to check (must already be validated and sanitized)
 * @param rounds - Number of query rounds (3-5, default 3)
 * @param dnsOptions - Optional DNS query options
 * @param delayMs - Delay between rounds in ms (default 2000; tests can pass 0)
 * @returns CheckResult with fast-flux findings
 */
export async function checkFastFlux(
	domain: string,
	rounds?: number,
	dnsOptions?: QueryDnsOptions,
	delayMs = 2000,
): Promise<CheckResult> {
	const effectiveRounds = Math.max(3, Math.min(5, rounds ?? 3));
	const roundResults: RoundResult[] = [];

	for (let i = 0; i < effectiveRounds; i++) {
		// Delay between rounds (not before the first)
		if (i > 0 && delayMs > 0) {
			await new Promise((resolve) => setTimeout(resolve, delayMs));
		}

		try {
			// Query A + AAAA in parallel
			const [aResult, aaaaResult] = await Promise.allSettled([
				queryDns(domain, 'A', false, dnsOptions),
				queryDns(domain, 'AAAA', false, dnsOptions),
			]);

			const answers: DnsAnswer[] = [];

			if (aResult.status === 'fulfilled' && aResult.value.Answer) {
				answers.push(...aResult.value.Answer.filter((a) => a.type === TYPE_A));
			}
			if (aaaaResult.status === 'fulfilled' && aaaaResult.value.Answer) {
				answers.push(...aaaaResult.value.Answer.filter((a) => a.type === TYPE_AAAA));
			}

			const ips = answers.map((a) => a.data).sort();
			const minTtl = answers.length > 0 ? Math.min(...answers.map((a) => a.TTL)) : Infinity;

			roundResults.push({ ips, minTtl });
		} catch {
			// Round failed entirely — record empty result
			roundResults.push({ ips: [], minTtl: Infinity });
		}
	}

	// Check if all rounds failed
	const successfulRounds = roundResults.filter((r) => r.ips.length > 0);
	if (successfulRounds.length === 0) {
		const findings: Finding[] = [
			createFinding(
				CATEGORY,
				'DNS queries failed',
				'medium',
				`All ${effectiveRounds} query rounds failed for ${domain}. Unable to assess fast-flux behavior.`,
			),
		];
		return buildCheckResult(CATEGORY, findings) as CheckResult;
	}

	// Collect all unique IPs across all rounds
	const allUniqueIps = new Set<string>();
	for (const round of roundResults) {
		for (const ip of round.ips) {
			allUniqueIps.add(ip);
		}
	}

	// Count IP set changes between consecutive rounds
	let ipSetChanges = 0;
	for (let i = 1; i < roundResults.length; i++) {
		const prev = roundResults[i - 1].ips.join(',');
		const curr = roundResults[i].ips.join(',');
		if (prev !== curr && roundResults[i - 1].ips.length > 0 && roundResults[i].ips.length > 0) {
			ipSetChanges++;
		}
	}

	// Find minimum TTL across all rounds
	const overallMinTtl = Math.min(...successfulRounds.map((r) => r.minTtl));

	// Detect flux: low TTL AND IP changes
	const fluxDetected = overallMinTtl < 300 && ipSetChanges > 0;

	const findings: Finding[] = [];

	if (fluxDetected) {
		findings.push(
			createFinding(
				CATEGORY,
				'Fast-flux behavior detected',
				'high',
				`${domain} shows fast-flux indicators: ${allUniqueIps.size} unique IPs observed across ${effectiveRounds} rounds with ${ipSetChanges} IP set change(s) and minimum TTL of ${overallMinTtl}s. Rotating IPs with low TTLs are characteristic of fast-flux networks used to evade takedowns.`,
				{
					domain,
					flux_detected: true,
					unique_ips: allUniqueIps.size,
					ip_set_changes: ipSetChanges,
					min_ttl: overallMinTtl,
					rounds: effectiveRounds,
				},
			),
		);
	} else {
		findings.push(
			createFinding(
				CATEGORY,
				'Stable resolution — no fast-flux indicators',
				'info',
				`${domain} resolved consistently across ${effectiveRounds} rounds: ${allUniqueIps.size} unique IP(s), ${ipSetChanges} IP set change(s), minimum TTL ${overallMinTtl === Infinity ? 'N/A' : `${overallMinTtl}s`}. No fast-flux behavior detected.`,
				{
					domain,
					flux_detected: false,
					unique_ips: allUniqueIps.size,
					ip_set_changes: ipSetChanges,
					min_ttl: overallMinTtl === Infinity ? null : overallMinTtl,
					rounds: effectiveRounds,
				},
			),
		);
	}

	// Disclosure about limitations
	findings.push(
		createFinding(
			CATEGORY,
			'Detection limitations',
			'info',
			'DoH resolver caching may mask IP rotation. This check has lower fidelity than direct UDP probing against authoritative nameservers.',
		),
	);

	return buildCheckResult(CATEGORY, findings) as CheckResult;
}
