// SPDX-License-Identifier: BUSL-1.1

/**
 * ASN Lookup tool via Team Cymru DNS.
 * Maps domain A-record IPs to Autonomous System Numbers (ASNs) using
 * Team Cymru's DNS-based ASN service (origin.asn.cymru.com / asn.cymru.com).
 */

import { queryDnsRecordsWithRcode, queryTxtRecords } from '../lib/dns';
import { buildDnsErrorResult } from '../lib/dns-error-result';
import type { QueryDnsOptions } from '../lib/dns-types';
import { isValidIPv4, reverseIPv4 } from '../lib/ip-utils';
import { callReconScan, isReconHit } from '../lib/recon-binding';
import type { ReconBinding, BindingDegradationSink } from '../lib/recon-binding';
import { buildCheckResult, createFinding } from '../lib/scoring';
import type { CheckResult, CheckCategory } from '../lib/scoring';

const CATEGORY = 'asn' as CheckCategory;

/** Cap on A-record addresses looked up in Team Cymru (serial loop, two DoH queries each — SQ-282). */
const MAX_ADDRESSES_EXAMINED = 10;

/**
 * ASNs associated with hosting providers commonly used for malicious infrastructure.
 * Presence is not inherently bad, but warrants awareness in a security context.
 */
const HIGH_RISK_ASNS = new Set([
	9009, // M247
	53667, // Frantech/BuyVM
	36352, // ColoCrossing
	20473, // Vultr
	14061, // DigitalOcean
	63949, // Linode/Akamai
]);

interface AsnOrigin {
	asn: number;
	prefix: string;
	cc: string;
	registry: string;
	allocated: string;
}

/** Parse a Cymru origin TXT response: "ASN | prefix | CC | registry | allocated" */
function parseOriginTxt(txt: string): AsnOrigin | null {
	const parts = txt.split('|').map((p) => p.trim());
	if (parts.length < 5) return null;
	const asn = parseInt(parts[0], 10);
	if (!Number.isFinite(asn) || asn <= 0) return null;
	return {
		asn,
		prefix: parts[1],
		cc: parts[2],
		registry: parts[3],
		allocated: parts[4],
	};
}

/** Parse a Cymru org TXT response: "ASN | CC | registry | allocated | org name" */
function parseOrgTxt(txt: string): string | null {
	const parts = txt.split('|').map((p) => p.trim());
	if (parts.length < 5) return null;
	return parts[4] || null;
}

/**
 * Look up ASN information for a domain's A-record IPs via Team Cymru DNS.
 *
 * For each resolved IPv4 address:
 * 1. Queries `{reversed}.origin.asn.cymru.com` TXT for ASN/prefix/CC
 * 2. Queries `AS{asn}.asn.cymru.com` TXT for the organization name
 *
 * Flags high-risk ASNs (commonly abused hosting providers) as medium severity.
 *
 * @param domain - The domain to look up
 * @param dnsOptions - Optional DNS query options
 * @returns CheckResult with ASN findings
 */
export async function checkCymruAsn(
	domain: string,
	dnsOptions?: QueryDnsOptions,
	reconOptions: { reconBinding?: ReconBinding; reconAuthToken?: string; onBindingDegradation?: BindingDegradationSink } = {},
): Promise<CheckResult> {
	const findings: ReturnType<typeof createFinding>[] = [];

	// Step 1: Resolve domain A records
	let ips: string[] = [];
	try {
		const outcome = await queryDnsRecordsWithRcode(domain, 'A', dnsOptions);
		// SERVFAIL/REFUSED: the resolver never concluded, so an empty set is not "no A records".
		if (outcome.inconclusive) throw new Error(`DNS query for A records of ${domain} did not conclude (rcode ${outcome.rcode})`);
		ips = outcome.records;
	} catch (err) {
		// A failed lookup is a non-measurement — abstain rather than certify a clean info result (SQ-282).
		return buildDnsErrorResult(CATEGORY, 'ASN lookup', err);
	}

	if (ips.length === 0) {
		findings.push(
			createFinding(
				CATEGORY,
				'No A records found',
				'info',
				`Could not resolve any A records for ${domain}. ASN lookup requires IPv4 addresses.`,
				{
					domain,
				},
			),
		);
		return buildCheckResult(CATEGORY, findings) as CheckResult;
	}

	// Deduplicate and keep only well-formed IPv4 addresses. DoH schemas verify
	// shape, not semantic A-record contents, so malformed resolver data must not
	// be used to construct Cymru query names.
	const allIps = [...new Set(ips)];
	const invalidIps = allIps.filter((ip) => !isValidIPv4(ip));
	ips = allIps.filter(isValidIPv4);

	if (ips.length === 0) {
		findings.push(
			createFinding(
				CATEGORY,
				'No valid IPv4 A records found',
				'info',
				`Resolved A records for ${domain} did not contain any valid IPv4 addresses. ASN lookup skipped.`,
				{ domain, invalidIps },
			),
		);
		return buildCheckResult(CATEGORY, findings) as CheckResult;
	}

	if (invalidIps.length > 0) {
		findings.push(
			createFinding(CATEGORY, 'Malformed A records ignored', 'info', `Ignored malformed A record value(s): ${invalidIps.join(', ')}.`, {
				domain,
				invalidIps,
			}),
		);
	}

	// Step 2: Query Cymru origin for each IP. The loop is serial (two DoH round
	// trips per address), so an unbounded A set (~100 records) outruns the tool
	// timeout — cap it and say so (SQ-282).
	const totalIps = ips.length;
	if (totalIps > MAX_ADDRESSES_EXAMINED) {
		ips = ips.slice(0, MAX_ADDRESSES_EXAMINED);
		findings.push(
			createFinding(
				CATEGORY,
				'ASN lookup limited to a subset of addresses',
				'info',
				`${domain} resolves to ${totalIps} IPv4 addresses; only the first ${MAX_ADDRESSES_EXAMINED} were looked up in Team Cymru. ASN coverage is partial.`,
				{ domain, truncated: true, examined: MAX_ADDRESSES_EXAMINED, total: totalIps },
			),
		);
	}
	const seenAsns = new Set<number>();

	for (const ip of ips) {
		const reversed = reverseIPv4(ip);
		const originName = `${reversed}.origin.asn.cymru.com`;

		let originTxts: string[] = [];
		try {
			originTxts = await queryTxtRecords(originName, dnsOptions);
		} catch {
			// Origin lookup failed for this IP
		}

		if (originTxts.length === 0) {
			findings.push(
				createFinding(CATEGORY, `No ASN data for ${ip}`, 'info', `No ASN data returned from Team Cymru for ${ip}.`, {
					ip,
				}),
			);
			continue;
		}

		const origin = parseOriginTxt(originTxts[0]);
		if (!origin) {
			findings.push(
				createFinding(CATEGORY, `Unparseable ASN response for ${ip}`, 'info', `Team Cymru returned an unparseable response for ${ip}.`, {
					ip,
					raw: originTxts[0],
				}),
			);
			continue;
		}

		// Step 3: Query org name (deduplicate by ASN to avoid redundant lookups)
		let orgName: string | null = null;
		if (!seenAsns.has(origin.asn)) {
			try {
				const orgTxts = await queryTxtRecords(`AS${origin.asn}.asn.cymru.com`, dnsOptions);
				if (orgTxts.length > 0) {
					orgName = parseOrgTxt(orgTxts[0]);
				}
			} catch {
				// Org lookup failed — continue with ASN number only
			}
		}
		seenAsns.add(origin.asn);

		// Step 4: Build findings
		const isHighRisk = HIGH_RISK_ASNS.has(origin.asn);
		const orgLabel = orgName ? ` (${orgName})` : '';

		if (isHighRisk) {
			findings.push(
				createFinding(
					CATEGORY,
					`High-risk ASN ${origin.asn} detected`,
					'medium',
					`${ip} is announced by high-risk ASN ${origin.asn}${orgLabel} in prefix ${origin.prefix} (${origin.cc}, ${origin.registry}).`,
					{ ip, asn: origin.asn, prefix: origin.prefix, cc: origin.cc, registry: origin.registry, orgName, highRisk: true },
				),
			);
		}

		findings.push(
			createFinding(
				CATEGORY,
				`ASN ${origin.asn} for ${ip}`,
				'info',
				`${ip} → AS${origin.asn}${orgLabel}, prefix ${origin.prefix}, country ${origin.cc}, registry ${origin.registry}, allocated ${origin.allocated}.`,
				{ ip, asn: origin.asn, prefix: origin.prefix, cc: origin.cc, registry: origin.registry, allocated: origin.allocated, orgName },
			),
		);
	}

	// Recon enrichment: additive-only, fail-soft
	if (reconOptions.reconBinding) {
		const reconResult = await callReconScan(
			reconOptions.reconBinding,
			reconOptions.reconAuthToken,
			'MALICIOUS_ASN',
			{ domain },
			undefined,
			reconOptions.onBindingDegradation,
		);
		const hit = reconResult && isReconHit(reconResult.status);
		if (hit) {
			findings.push(
				createFinding(
					CATEGORY,
					'Malicious-ASN intel corroboration',
					'medium',
					reconResult.details ?? `Threat intelligence corroborates malicious-ASN signal for ${domain}.`,
					{ domain, reconEnriched: true },
				),
			);
		}
	}

	return buildCheckResult(CATEGORY, findings) as CheckResult;
}
