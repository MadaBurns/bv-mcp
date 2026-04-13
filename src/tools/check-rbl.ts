// SPDX-License-Identifier: BUSL-1.1

/**
 * Real-time Blocklist (RBL) check tool.
 * Resolves MX IPs for a domain and checks against 8 DNS-based blocklists.
 */

import { queryDnsRecords, queryMxRecords } from '../lib/dns';
import type { QueryDnsOptions } from '../lib/dns-types';
import { reverseIPv4, isPrivateIP } from '../lib/ip-utils';
import { buildCheckResult, createFinding } from '../lib/scoring';
import type { CheckResult, CheckCategory } from '../lib/scoring';

interface RblZone {
	name: string;
	zone: string;
}

const RBL_ZONES: RblZone[] = [
	{ name: 'Spamhaus ZEN', zone: 'zen.spamhaus.org' },
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

/** Spamhaus ZEN return code descriptions (keyed by last two octets). */
const SPAMHAUS_CODES: Record<string, string> = {
	'0.2': 'SBL — direct spam source',
	'0.3': 'SBL CSS — spam support service',
	'0.4': 'XBL CBL — exploited host',
	'0.5': 'XBL — exploited host (NJABL)',
	'0.9': 'SBL DROP — hijacked netblock',
	'0.10': 'PBL ISP — end-user IP',
	'0.11': 'PBL ISP — end-user IP',
};

/** Decode Spamhaus ZEN return code. Returns null for quota codes. */
function decodeSpamhausCode(ip: string): string | null {
	if (ip.startsWith('127.255.255.')) return null; // quota
	const lastTwo = ip.split('.').slice(2).join('.');
	return SPAMHAUS_CODES[lastTwo] ?? `Listed (${ip})`;
}

/** Mailspike positive reputation codes: 127.0.0.10 through 127.0.0.14. */
function isMailspikePositive(ip: string): boolean {
	const last = parseInt(ip.split('.').pop() ?? '0', 10);
	return last >= 10 && last <= 14;
}

/**
 * Check MX server IPs against 8 DNS-based Real-time Blocklists.
 * Falls back to domain A records if no MX records exist.
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

	// Deduplicate and limit
	ips = [...new Set(ips)].slice(0, MAX_MX_IPS);

	// Step 2: Check each IP against all RBL zones
	let totalListings = 0;

	for (const ip of ips) {
		// Only check IPv4
		if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) continue;

		if (isPrivateIP(ip)) {
			findings.push(
				createFinding(CATEGORY, `Private IP detected: ${ip}`, 'info', `MX resolves to private IP ${ip} — RBL checks skipped for this address.`, {
					ip,
					private: true,
				}),
			);
			continue;
		}

		const reversed = reverseIPv4(ip);
		let ipListingCount = 0;
		let hasSpamhausListing = false;
		const ipListingIndices: number[] = [];

		const rblResults = await Promise.allSettled(
			RBL_ZONES.map(async (rbl) => {
				const queryName = `${reversed}.${rbl.zone}`;
				try {
					const answers = await queryDnsRecords(queryName, 'A', dnsOptions);
					if (answers.length === 0) return { rbl, listed: false };

					const returnIp = answers[0];

					// Spamhaus quota codes
					if (rbl.zone === 'zen.spamhaus.org' && returnIp.startsWith('127.255.255.')) {
						return { rbl, listed: false, quota: true };
					}

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

			if (result.quota) {
				findings.push(
					createFinding(CATEGORY, `${result.rbl.name} quota exceeded`, 'info', `Spamhaus returned a quota/rate-limit response for ${ip}. Use a DQS key for reliable results.`, {
						ip,
						zone: result.rbl.zone,
						quota: true,
					}),
				);
				continue;
			}

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
			if (result.rbl.zone === 'zen.spamhaus.org') hasSpamhausListing = true;

			const severity = result.rbl.zone === 'zen.spamhaus.org' ? 'high' : 'low';
			const detail =
				result.rbl.zone === 'zen.spamhaus.org'
					? `${ip} is listed on ${result.rbl.name}: ${decodeSpamhausCode(result.returnIp!) ?? result.returnIp}.`
					: `${ip} is listed on ${result.rbl.name}.`;

			ipListingIndices.push(findings.length);
			findings.push(
				createFinding(CATEGORY, `Listed on ${result.rbl.name}`, severity as 'high' | 'low', detail, {
					ip,
					zone: result.rbl.zone,
					returnCode: result.returnIp,
				}),
			);
		}

		// Elevate severity if 2+ non-Spamhaus RBLs list the same IP
		if (!hasSpamhausListing && ipListingCount >= 2) {
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

	if (totalListings === 0 && !findings.some((f) => f.title.includes('Listed'))) {
		findings.push(
			createFinding(CATEGORY, 'IP reputation clean — not listed on any RBL', 'info', `All checked IPs for ${domain} are clean on ${RBL_ZONES.length} RBLs.`, {
				ips,
				zones: RBL_ZONES.map((z) => z.zone),
			}),
		);
	}

	return buildCheckResult(CATEGORY, findings) as CheckResult;
}
