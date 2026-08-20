// SPDX-License-Identifier: BUSL-1.1

/**
 * NSEC3 Parameter Analysis tool.
 * Assesses zone walkability risk by analyzing NSEC3PARAM configuration via DoH.
 *
 * Workers-compatible: uses fetch API only (DNS-over-HTTPS).
 */

import { queryDnsRecords } from '../lib/dns';
import type { QueryDnsOptions, DnsAuthority, DohResponse } from '../lib/dns-types';
import { DNS_TIMEOUT_MS } from '../lib/config';
import { buildCheckResult, createFinding } from '../lib/scoring';
import type { CheckResult, CheckCategory } from '../lib/scoring';
import { CLOUDFLARE_DOH_ENDPOINT } from '../lib/dns-endpoints';

const CATEGORY = 'nsec_walkability' as CheckCategory;

/** DNS record type codes for denial-of-existence records. */
const NSEC_TYPE = 47;
const NSEC3_TYPE = 50;

/**
 * Verdict of the DO=1 NXDOMAIN denial-of-existence probe.
 * - `walkable`         — a real plain-NSEC chain (next-name is a different existing owner)
 * - `minimally-covering` — RFC 4470 "black lie" NSEC (next-name = `\000.<qname>`); NOT walkable
 * - `nsec3`            — an NSEC3 record proved hashed denial despite no NSEC3PARAM; not walkable
 * - `inconclusive`     — no NSEC/NSEC3 could be read (probe failed / authority stripped)
 */
type DenialVerdict = 'walkable' | 'minimally-covering' | 'nsec3' | 'inconclusive';

interface DenialProbeResult {
	probeName: string;
	verdict: DenialVerdict;
	/** The observed NSEC next-name (first rdata token), when an NSEC was read. */
	nextName?: string;
}

/** Random, almost-certainly-nonexistent label so the probe forces an NXDOMAIN/NXNAME reply. */
function probeNonce(): string {
	const uuid = globalThis.crypto?.randomUUID?.();
	return (uuid ?? Math.random().toString(36).slice(2)).replace(/-/g, '').slice(0, 16);
}

/**
 * Classify the authority-section denial records for a probed non-existent name.
 *
 * RFC 4470 minimally-covering NSEC ("NSEC black lies") synthesizes an NSEC whose
 * owner is the queried name and whose next-name is `\000.<qname>` (a `\x00` label
 * prepended to the qname), carrying a minimally-covering type bitmap (`RRSIG NSEC`,
 * often with `NXNAME`/`TYPE128`). Such a zone publishes no NSEC3PARAM yet is NOT
 * walkable. Only an NSEC whose next-name is a genuinely different existing owner
 * name indicates a walkable plain-NSEC chain.
 *
 * ⚠️ The technique is PROVIDER-NEUTRAL — several managed DNS providers implement
 * it, and this check reads the record only, never the operator (#728: a zone served
 * entirely by Route 53 was told the record was "the Cloudflare default"). Do not
 * re-introduce a vendor name here or in any customer-visible detail below.
 */
function classifyDenial(probeName: string, authority: DnsAuthority[] | null): { verdict: DenialVerdict; nextName?: string } {
	if (!authority) return { verdict: 'inconclusive' };

	// NSEC3 in the authority section → hashed denial-of-existence → not plain-walkable.
	if (authority.some((rr) => rr.type === NSEC3_TYPE)) return { verdict: 'nsec3' };

	const nsec = authority.find((rr) => rr.type === NSEC_TYPE);
	if (!nsec) return { verdict: 'inconclusive' };

	const tokens = nsec.data.trim().split(/\s+/);
	const rawNext = tokens[0] ?? '';
	const bitmap = tokens.slice(1).map((t) => t.toUpperCase());
	const nextName = rawNext.replace(/\.$/, '');
	const qname = probeName.replace(/\.$/, '').toLowerCase();
	const nn = nextName.toLowerCase();

	// RFC 4470 / compact-denial signatures of a minimally-covering (black-lie) NSEC:
	const isSynthesizedNext =
		nn === `\\000.${qname}` || // the exact `\x00`-prepended next-name RFC 4470 describes
		nn.startsWith('\\000.') ||
		nn.startsWith('\\x00.') ||
		nn.startsWith('\\0.') ||
		nn === qname; // owner==next epsilon form
	const isMinimalBitmap = bitmap.includes('NXNAME') || bitmap.includes('TYPE128');

	if (isSynthesizedNext || isMinimalBitmap) return { verdict: 'minimally-covering', nextName };

	// A real, different existing next owner name → the plain-NSEC chain is walkable.
	return { verdict: 'walkable', nextName };
}

/**
 * Probe a guaranteed-nonexistent label under the zone with the DNSSEC OK (DO=1)
 * bit set and read the authority-section denial-of-existence records. This is the
 * only way to distinguish a walkable plain-NSEC chain from RFC 4470 minimally-
 * covering NSEC — the absence of NSEC3PARAM alone cannot.
 *
 * Self-contained fetch (not the shared DoH transport) because the transport does
 * not expose the DO bit; without DO=1 the resolver strips the NSEC RRs. Fail-soft:
 * any error → `inconclusive` (never a false "walkable").
 */
async function probeDenialNsec(domain: string, dnsOptions?: QueryDnsOptions): Promise<DenialProbeResult> {
	const probeName = `bvnsec-probe-${probeNonce()}.${domain}`;
	const params = new URLSearchParams({ name: probeName, type: 'A', do: '1' });
	const url = `${CLOUDFLARE_DOH_ENDPOINT}?${params.toString()}`;
	try {
		const resp = await fetch(url, {
			method: 'GET',
			headers: { Accept: 'application/dns-json' },
			signal: AbortSignal.timeout(dnsOptions?.timeoutMs ?? DNS_TIMEOUT_MS),
		});
		if (!resp.ok) return { probeName, verdict: 'inconclusive' };
		const data = (await resp.json()) as DohResponse;
		const { verdict, nextName } = classifyDenial(probeName, data.Authority ?? []);
		return { probeName, verdict, nextName };
	} catch {
		return { probeName, verdict: 'inconclusive' };
	}
}

/** NSEC3 hash algorithm names (RFC 5155 §11). Only algorithm 1 is defined. */
const NSEC3_HASH_ALGORITHMS: Record<number, string> = {
	1: 'SHA-1',
};

/** Parsed NSEC3PARAM fields. */
interface Nsec3Params {
	algorithm: number;
	algorithmName: string;
	flags: number;
	iterations: number;
	salt: string; // "-" means empty
}

/**
 * Parse an NSEC3PARAM data string: "algorithm flags iterations salt"
 * Salt of "-" indicates an empty salt (RFC 5155 §4.2).
 */
function parseNsec3Param(data: string): Nsec3Params | null {
	const parts = data.trim().split(/\s+/);
	if (parts.length < 4) return null;

	const algorithm = parseInt(parts[0], 10);
	const flags = parseInt(parts[1], 10);
	const iterations = parseInt(parts[2], 10);
	const salt = parts[3];

	if (!Number.isFinite(algorithm) || !Number.isFinite(flags) || !Number.isFinite(iterations)) {
		return null;
	}

	return {
		algorithm,
		algorithmName: NSEC3_HASH_ALGORITHMS[algorithm] ?? `Unknown (${algorithm})`,
		flags,
		iterations,
		salt,
	};
}

/**
 * Determine whether a zone is DNSSEC-signed by probing for DNSKEY records, with
 * a DS lookup as a backstop. NSEC/NSEC3 records only exist in signed zones, so
 * this gate prevents reporting an unsigned (DNSSEC-absent) zone as "walkable".
 *
 * Conservative: if both lookups error, we treat the zone as unsigned so the
 * tool does not raise a high-severity walkability finding on weak evidence.
 */
async function isZoneSigned(domain: string, dnsOptions?: QueryDnsOptions): Promise<boolean> {
	try {
		const dnskey = await queryDnsRecords(domain, 'DNSKEY', dnsOptions);
		if (dnskey.length > 0) return true;
	} catch {
		// fall through to DS backstop
	}
	try {
		const ds = await queryDnsRecords(domain, 'DS', dnsOptions);
		return ds.length > 0;
	} catch {
		return false;
	}
}

/**
 * Assess NSEC zone walkability risk.
 *
 * For signed zones with no NSEC3PARAM, a DO=1 denial-of-existence probe reads the
 * authority-section NSEC to distinguish a walkable plain-NSEC chain from RFC 4470
 * minimally-covering NSEC ("black lies"), which is not walkable (#565). When the
 * probe cannot read a denial record, walkability is reported inconclusive (info)
 * rather than a confident high, since NSEC3PARAM absence alone does not prove it.
 *
 * @param domain - The domain to check (must already be validated and sanitized)
 * @param dnsOptions - Optional DNS query options
 * @returns CheckResult with NSEC3 walkability findings
 */
export async function checkNsecWalkability(domain: string, dnsOptions?: QueryDnsOptions): Promise<CheckResult> {
	const findings: ReturnType<typeof createFinding>[] = [];

	let nsec3Records: string[] = [];
	try {
		nsec3Records = await queryDnsRecords(domain, 'NSEC3PARAM', dnsOptions);
	} catch {
		findings.push(
			createFinding(
				CATEGORY,
				'NSEC3PARAM query failed',
				'info',
				`DNS query for NSEC3PARAM records at ${domain} failed. Unable to assess zone walkability. Note: this analysis cannot probe for actual NSEC/NSEC3 denial records via DoH and analyzes configuration parameters only.`,
				{ domain },
			),
		);
		return buildCheckResult(CATEGORY, findings) as CheckResult;
	}

	if (nsec3Records.length === 0) {
		// NSEC and NSEC3 only exist in DNSSEC-signed zones. An unsigned zone has no
		// NSEC chain at all, so "fully walkable" is a false positive. Gate the high
		// severity behind confirmed signing: check for DNSKEY (and DS as a backstop)
		// before concluding the zone uses plain NSEC.
		const signed = await isZoneSigned(domain, dnsOptions);

		if (!signed) {
			findings.push(
				createFinding(
					CATEGORY,
					'Zone not DNSSEC-signed — walkability N/A',
					'info',
					`No NSEC3PARAM record was found for ${domain}, and no DNSKEY/DS records were found either, so the zone is not DNSSEC-signed. NSEC/NSEC3 denial-of-existence records only exist in signed zones, so there is no NSEC chain to walk. Zone-walking risk does not apply here. (To gain DNSSEC's spoofing/cache-poisoning protections, the zone would need to be signed — at which point NSEC3 should be used to prevent enumeration.)`,
					{ domain, walkable: false, dnssecSigned: false },
				),
			);
			return buildCheckResult(CATEGORY, findings) as CheckResult;
		}

		// Absence of NSEC3PARAM does NOT prove the zone is walkable. RFC 4470
		// "minimally-covering" NSEC (a.k.a. NSEC black lies), implemented by several
		// managed DNS providers, publishes no NSEC3PARAM and no NSEC3, yet is NOT walkable.
		// Actively probe: query a guaranteed-nonexistent label with DO=1 and inspect
		// the authority-section NSEC record to distinguish the two cases (#565).
		const probe = await probeDenialNsec(domain, dnsOptions);

		if (probe.verdict === 'walkable') {
			findings.push(
				createFinding(
					CATEGORY,
					'Zone is walkable via plain NSEC',
					'high',
					`The zone for ${domain} is DNSSEC-signed (DNSKEY/DS present), publishes no NSEC3PARAM, and a DO=1 denial-of-existence probe returned a plain NSEC record whose next-name (${probe.nextName}) is a genuinely different existing owner name. The zone therefore uses plain NSEC and is fully walkable — an attacker can enumerate all zone contents by following NSEC chain links.`,
					{ domain, walkable: true, dnssecSigned: true, nextName: probe.nextName ?? null, probe: 'nsec-next-name' },
				),
			);
			return buildCheckResult(CATEGORY, findings) as CheckResult;
		}

		if (probe.verdict === 'minimally-covering') {
			findings.push(
				createFinding(
					CATEGORY,
					'Signed zone uses minimally-covering NSEC (RFC 4470) — not walkable',
					'info',
					`The zone for ${domain} is DNSSEC-signed and publishes no NSEC3PARAM, but a DO=1 denial-of-existence probe returned a minimally-covering NSEC record (RFC 4470 "NSEC black lies", implemented by several managed DNS providers): the NSEC next-name is the synthesized \`\\000.<qname>\` (${probe.nextName}) rather than a real adjacent owner. This proves the zone is NOT walkable — an attacker cannot enumerate zone contents from the NSEC chain — even though no NSEC3PARAM is published.`,
					{ domain, walkable: false, dnssecSigned: true, nextName: probe.nextName ?? null, probe: 'nsec-next-name', minimallyCovering: true },
				),
			);
			return buildCheckResult(CATEGORY, findings) as CheckResult;
		}

		if (probe.verdict === 'nsec3') {
			findings.push(
				createFinding(
					CATEGORY,
					'Signed zone uses NSEC3 denial-of-existence — not trivially walkable',
					'info',
					`The zone for ${domain} is DNSSEC-signed and publishes no NSEC3PARAM record, but a DO=1 denial-of-existence probe returned an NSEC3 (hashed) denial record. The zone therefore uses NSEC3 rather than plain NSEC, so it is not trivially walkable. (A missing NSEC3PARAM is unusual for an NSEC3 zone but does not by itself imply walkability.)`,
					{ domain, walkable: false, dnssecSigned: true, probe: 'nsec3-observed' },
				),
			);
			return buildCheckResult(CATEGORY, findings) as CheckResult;
		}

		// Inconclusive: signed, no NSEC3PARAM, but the probe could not read an NSEC/NSEC3
		// record (probe failed or authority section stripped). Do NOT assert a confident
		// high/walkable on the absence of NSEC3PARAM alone — downgrade to info (#565).
		findings.push(
			createFinding(
				CATEGORY,
				'Zone walkability could not be confirmed',
				'info',
				`The zone for ${domain} is DNSSEC-signed (DNSKEY/DS present) and publishes no NSEC3PARAM record, so it may use plain NSEC (walkable) or RFC 4470 minimally-covering NSEC (not walkable). A DO=1 denial-of-existence probe could not read an authority-section NSEC/NSEC3 record to confirm which, so zone walkability is inconclusive. If the zone genuinely uses plain NSEC, deploying NSEC3 would prevent enumeration.`,
				{ domain, walkable: null, dnssecSigned: true, probe: 'inconclusive' },
			),
		);
		return buildCheckResult(CATEGORY, findings) as CheckResult;
	}

	// Parse the first NSEC3PARAM record (zones should have exactly one)
	const params = parseNsec3Param(nsec3Records[0]);

	if (!params) {
		findings.push(
			createFinding(
				CATEGORY,
				'Unparseable NSEC3PARAM',
				'info',
				`NSEC3PARAM record for ${domain} could not be parsed: ${nsec3Records[0]}`,
				{ domain, raw: nsec3Records[0] },
			),
		);
		return buildCheckResult(CATEGORY, findings) as CheckResult;
	}

	const hasSalt = params.salt !== '-';
	const hasIterations = params.iterations > 0;

	// Check opt-out flag (bit 0 of flags)
	if (params.flags & 1) {
		findings.push(
			createFinding(
				CATEGORY,
				'NSEC3 opt-out enabled',
				'low',
				`NSEC3PARAM for ${domain} has the opt-out flag set (flags=${params.flags}). Opt-out allows unsigned delegations to be omitted from the NSEC3 chain, which may leave some subdomains without denial-of-existence protection.`,
				{ domain, flags: params.flags, optOut: true },
			),
		);
	}

	// Assess walkability risk based on parameters
	if (!hasIterations && !hasSalt) {
		// RFC 9276 default: 0 iterations, no salt — low enumeration cost
		findings.push(
			createFinding(
				CATEGORY,
				'NSEC3 with minimal parameters',
				'medium',
				`NSEC3PARAM for ${domain} uses 0 iterations and no salt (RFC 9276 recommended defaults). While NSEC3 prevents trivial zone walking, the low enumeration cost means offline dictionary attacks against the hashed names are feasible. Algorithm: ${params.algorithmName}. Note: this tool analyzes NSEC3PARAM configuration only and cannot probe for actual NSEC3 denial records via DoH.`,
				{
					domain,
					algorithm: params.algorithmName,
					algorithmId: params.algorithm,
					iterations: params.iterations,
					salt: params.salt,
					hasSalt: false,
				},
			),
		);
	} else {
		// Has salt and/or iterations > 0 — standard NSEC3 configuration
		findings.push(
			createFinding(
				CATEGORY,
				'NSEC3 parameters configured',
				'info',
				`NSEC3PARAM for ${domain}: algorithm ${params.algorithmName}, ${params.iterations} iteration${params.iterations !== 1 ? 's' : ''}, salt ${hasSalt ? params.salt : 'none'}. Zone uses NSEC3 hashed denial-of-existence, which mitigates trivial zone walking. Note: this tool analyzes configuration parameters only.`,
				{
					domain,
					algorithm: params.algorithmName,
					algorithmId: params.algorithm,
					iterations: params.iterations,
					salt: params.salt,
					hasSalt,
				},
			),
		);
	}

	return buildCheckResult(CATEGORY, findings) as CheckResult;
}
