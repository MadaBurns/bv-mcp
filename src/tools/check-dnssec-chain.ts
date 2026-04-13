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

/** Linkage status between DS and DNSKEY at a zone. */
type LinkageStatus = 'linked' | 'no_ds' | 'no_dnskey' | 'broken';

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
}

// ---------------------------------------------------------------------------
// Parsers
// ---------------------------------------------------------------------------

function parseDsRecord(data: string): ParsedDs | null {
	const parts = data.trim().split(/\s+/);
	if (parts.length < 4) return null;
	const keyTag = parseInt(parts[0], 10);
	const algorithm = parseInt(parts[1], 10);
	const digestType = parseInt(parts[2], 10);
	const digest = parts.slice(3).join('');
	if (!Number.isFinite(keyTag) || !Number.isFinite(algorithm) || !Number.isFinite(digestType)) return null;
	return { keyTag, algorithm, digestType, digest };
}

function parseDnskeyRecord(data: string): ParsedDnskey | null {
	const parts = data.trim().split(/\s+/);
	if (parts.length < 4) return null;
	const flags = parseInt(parts[0], 10);
	const protocol = parseInt(parts[1], 10);
	const algorithm = parseInt(parts[2], 10);
	const pubkey = parts.slice(3).join('');
	if (!Number.isFinite(flags) || !Number.isFinite(protocol) || !Number.isFinite(algorithm)) return null;
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
		if (zone !== '.') {
			try {
				const rawDs = await queryDnsRecords(zone, 'DS', dnsOptions);
				dsRecords = rawDs.map(parseDsRecord).filter((r): r is ParsedDs => r !== null);
			} catch {
				// DS query failed — treat as no DS
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

		// Determine linkage (root always has no_ds since we skip DS query)
		const linkage = zone === '.' ? (dnskeyRecords.length > 0 ? 'linked' : 'no_dnskey') : determineLinkage(dsRecords, dnskeyRecords);

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
		});

		if (linkage === 'no_dnskey' || linkage === 'broken') {
			chainBroken = true;
		}

		// Stop walking if zone has no DS and no DNSKEY (unsigned from here down)
		if (zone !== '.' && dsRecords.length === 0 && dnskeyRecords.length === 0) {
			break;
		}
	}

	// Check AD flag on target domain
	let adFlag = false;
	try {
		const adResp = await queryDns(domain, 'A', true, dnsOptions);
		adFlag = adResp.AD === true;
	} catch {
		// AD check failed — leave as false
	}

	// Determine chain completeness
	const lastZone = zoneResults[zoneResults.length - 1];
	const reachedTarget = lastZone?.zone === domain;
	// Chain is complete only if we reached the target AND it's not broken AND the target zone is actually signed
	const targetSigned = reachedTarget && (lastZone.dsRecords.length > 0 || lastZone.dnskeyRecords.length > 0);
	const chainComplete = reachedTarget && !chainBroken && targetSigned;

	// --- Findings ---

	// Broken chain finding (high severity)
	if (chainBroken) {
		const brokenZones = zoneResults.filter((z) => z.linkage === 'no_dnskey' || z.linkage === 'broken');
		for (const bz of brokenZones) {
			const reason = bz.linkage === 'no_dnskey' ? 'DS record exists but no DNSKEY found' : 'DS and DNSKEY algorithm mismatch';
			findings.push(
				createFinding(
					CATEGORY,
					`Broken DNSSEC chain at ${bz.zone}`,
					'high',
					`DNSSEC chain is broken at ${bz.zone}: ${reason}. Resolvers that validate DNSSEC will return SERVFAIL for this zone.`,
					{ zone: bz.zone, linkage: bz.linkage },
				),
			);
		}
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

	const stoppedEarly = !reachedTarget;
	let summaryStatus: string;
	if (stoppedEarly) {
		summaryStatus = `stopped at ${lastZone?.zone ?? '.'} — zone has no DS and no DNSKEY (not signed)`;
	} else if (!targetSigned) {
		summaryStatus = `${domain} has no DS and no DNSKEY — domain is not signed`;
	} else if (chainComplete) {
		summaryStatus = 'complete chain from root to target';
	} else {
		summaryStatus = 'chain broken';
	}
	const summaryDetail = `DNSSEC chain walk for ${domain}: ${summaryStatus}. Zones walked: ${zoneResults.map((z) => z.zone).join(' → ')}. AD flag: ${adFlag}. Limitation: no cryptographic RRSIG verification; reports structure and linkage only.`;

	findings.push(
		createFinding(CATEGORY, 'DNSSEC chain summary', 'info', summaryDetail, {
			chainComplete,
			adFlag,
			zonesWalked: zoneResults.length,
			zones: zonesSummary,
		}),
	);

	return buildCheckResult(CATEGORY, findings) as CheckResult;
}
