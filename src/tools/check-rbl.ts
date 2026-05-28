// SPDX-License-Identifier: BUSL-1.1

/**
 * Real-time Blocklist (RBL) check tool.
 * Resolves MX IPs for a domain and checks against 7 DNS-based blocklists.
 *
 * Spamhaus ZEN is intentionally NOT in the provider set. bv-mcp queries via
 * shared public resolvers, where ZEN returns rate-limit/refused codes
 * (127.255.255.x) indistinguishable from a real verdict — and bv-mcp has no
 * reliable ZEN query path (its secondary-resolver token only drives
 * empty-result confirmation, it does not reroute the ZEN lookup). ZEN is
 * therefore dropped unconditionally: neither queried nor counted.
 */

import { queryDnsRecords, queryMxRecords } from '../lib/dns';
import type { QueryDnsOptions } from '../lib/dns-types';
import { reverseIPv4, isPrivateIP, isValidIPv4 } from '../lib/ip-utils';
import { buildCheckResult, createFinding } from '../lib/scoring';
import type { CheckResult, CheckCategory } from '../lib/scoring';

interface RblZone {
	name: string;
	zone: string;
}

const RBL_ZONES: RblZone[] = [
	{ name: 'SpamCop', zone: 'bl.spamcop.net' },
	{ name: 'UCEProtect L1', zone: 'dnsbl-1.uceprotect.net' },
	{ name: 'UCEProtect L2', zone: 'dnsbl-2.uceprotect.net' },
	{ name: 'Mailspike', zone: 'bl.mailspike.net' },
	{ name: 'Barracuda', zone: 'b.barracudacentral.org' },
	{ name: 'PSBL', zone: 'psbl.surriel.com' },
	{ name: 'SORBS', zone: 'dnsbl.sorbs.net' },
];

const CATEGORY = 'rbl' as CheckCategory;
const MAX_MX_IPS = 4;

/** Mailspike positive reputation codes: 127.0.0.10 through 127.0.0.14. */
function isMailspikePositive(ip: string): boolean {
	const last = parseInt(ip.split('.').pop() ?? '0', 10);
	return last >= 10 && last <= 14;
}

/**
 * Check MX server IPs against 7 DNS-based Real-time Blocklists.
 * Falls back to domain A records if no MX records exist.
 *
 * Spamhaus ZEN is excluded from the provider set — see the module header.
 */
export async function checkRbl(domain: string, dnsOptions?: QueryDnsOptions): Promise<CheckResult> {
	const findings: ReturnType<typeof createFinding>[] = [];

	// Step 1: Resolve MX → hosts → IPs. Fall back to domain A records.
	let ips: string[] = [];
	let usedFallback = false;

	try {
		const mxRecords = await queryMxRecords(domain, dnsOptions);
		if (mxRecords.length > 0) {
			const mxHosts = mxRecords.map((r) => r.exchange).filter(Boolean);
			const ipResults = await Promise.allSettled(
				mxHosts.slice(0, MAX_MX_IPS).map((host) => queryDnsRecords(host, 'A', dnsOptions)),
			);
			for (const r of ipResults) {
				if (r.status === 'fulfilled') ips.push(...r.value);
			}
		}
	} catch {
		// MX resolution failed
	}

	if (ips.length === 0) {
		try {
			ips = await queryDnsRecords(domain, 'A', dnsOptions);
			if (ips.length > 0) usedFallback = true;
		} catch {
			// A resolution also failed
		}
	}

	if (ips.length === 0) {
		findings.push(
			createFinding(CATEGORY, 'No IP addresses found', 'info', `Could not resolve any IP addresses for ${domain} (no MX or A records).`, {
				domain,
			}),
		);
		return buildCheckResult(CATEGORY, findings) as CheckResult;
	}

	if (usedFallback) {
		findings.push(
			createFinding(CATEGORY, 'No MX records — using A record fallback', 'info', `${domain} has no MX records. Using A record IP(s) for RBL checks.`, {
				domain,
				fallback: true,
			}),
		);
	}

	// Deduplicate, validate, and limit. Malformed resolver data should not be
	// used to construct DNSBL query names or reported as clean.
	const allIps = [...new Set(ips)];
	const invalidIps = allIps.filter((ip) => !isValidIPv4(ip));
	ips = allIps.filter(isValidIPv4).slice(0, MAX_MX_IPS);

	if (ips.length === 0) {
		findings.push(
			createFinding(
				CATEGORY,
				'No valid public IPv4 addresses found',
				'info',
				`Resolved records for ${domain} did not contain any valid IPv4 addresses that can be checked against RBLs.`,
				{ domain, invalidIps },
			),
		);
		return buildCheckResult(CATEGORY, findings) as CheckResult;
	}

	if (invalidIps.length > 0) {
		findings.push(
			createFinding(CATEGORY, 'Malformed IP addresses ignored', 'info', `Ignored malformed IP address value(s): ${invalidIps.join(', ')}.`, {
				domain,
				invalidIps,
			}),
		);
	}

	// Step 2: Check each IP against all RBL zones
	let totalListings = 0;
	let checkedPublicIps = 0;

	for (const ip of ips) {
		if (isPrivateIP(ip)) {
			findings.push(
				createFinding(CATEGORY, `Private IP detected: ${ip}`, 'info', `MX resolves to private IP ${ip} — RBL checks skipped for this address.`, {
					ip,
					private: true,
				}),
			);
			continue;
		}

		checkedPublicIps++;
		const reversed = reverseIPv4(ip);
		let ipListingCount = 0;
		const ipListingIndices: number[] = [];

		const rblResults = await Promise.allSettled(
			RBL_ZONES.map(async (rbl) => {
				const queryName = `${reversed}.${rbl.zone}`;
				try {
					const answers = await queryDnsRecords(queryName, 'A', dnsOptions);
					if (answers.length === 0) return { rbl, listed: false };

					const returnIp = answers[0];

					// Mailspike positive reputation
					if (rbl.zone === 'bl.mailspike.net' && isMailspikePositive(returnIp)) {
						return { rbl, listed: false, positiveRep: true };
					}

					return { rbl, listed: true, returnIp };
				} catch {
					return { rbl, listed: false, error: true };
				}
			}),
		);

		for (const settled of rblResults) {
			if (settled.status === 'rejected') continue;
			const result = settled.value;

			if (result.positiveRep) {
				findings.push(
					createFinding(CATEGORY, `Positive Mailspike reputation for ${ip}`, 'info', `${ip} has positive reputation on Mailspike.`, {
						ip,
						zone: result.rbl.zone,
						positiveReputation: true,
					}),
				);
				continue;
			}

			if (result.error || !result.listed) continue;

			ipListingCount++;
			totalListings++;

			ipListingIndices.push(findings.length);
			findings.push(
				createFinding(CATEGORY, `Listed on ${result.rbl.name}`, 'low', `${ip} is listed on ${result.rbl.name}.`, {
					ip,
					zone: result.rbl.zone,
					returnCode: result.returnIp,
				}),
			);
		}

		// Elevate severity if 2+ RBLs list the same IP
		if (ipListingCount >= 2) {
			const firstLowIdx = ipListingIndices.find((idx) => findings[idx]?.severity === 'low');
			if (firstLowIdx !== undefined) {
				const f = findings[firstLowIdx];
				findings[firstLowIdx] = createFinding(
					CATEGORY,
					f.title,
					'medium',
					f.detail + ` (elevated: listed on ${ipListingCount} RBLs)`,
					f.metadata,
				);
			}
		}
	}

	if (checkedPublicIps === 0) {
		findings.push(
			createFinding(CATEGORY, 'No public IPv4 addresses checked', 'info', `No public IPv4 addresses were available for ${domain}; RBL checks were skipped.`, {
				domain,
				ips,
			}),
		);
	} else if (totalListings === 0 && !findings.some((f) => f.title.includes('Listed'))) {
		findings.push(
			createFinding(CATEGORY, 'IP reputation clean — not listed on any RBL', 'info', `All checked IPs for ${domain} are clean on ${RBL_ZONES.length} RBLs.`, {
				ips,
				zones: RBL_ZONES.map((z) => z.zone),
			}),
		);
	}

	return buildCheckResult(CATEGORY, findings) as CheckResult;
}
