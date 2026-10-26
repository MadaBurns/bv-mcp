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
import { buildDnsErrorResult } from '../lib/dns-error-result';
import type { CheckResult, CheckCategory, Finding } from '../lib/scoring';
import { CLOUDFLARE_DOH_ENDPOINT } from '../lib/dns-endpoints';
import { disposeUnreadResponseBody, readJsonResponseCapped } from '../lib/response-body';

const CATEGORY = 'nsec_walkability' as CheckCategory;

/** DNS record type codes for denial-of-existence records. */
const NSEC_TYPE = 47;
const NSEC3_TYPE = 50;
const DOH_MAX_BODY_BYTES = 512 * 1024;

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
	const uuid = typeof crypto !== 'undefined' ? crypto.randomUUID?.() : undefined;
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
			redirect: 'manual',
			signal: AbortSignal.timeout(dnsOptions?.timeoutMs ?? DNS_TIMEOUT_MS),
		});
		if (!resp.ok) {
			await disposeUnreadResponseBody(resp);
			return { probeName, verdict: 'inconclusive' };
		}
		const data = await readJsonResponseCapped<DohResponse>(resp, DOH_MAX_BODY_BYTES);
		if (!data) return { probeName, verdict: 'inconclusive' };
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
	let nsec3Records: string[] = [];
	try {
		nsec3Records = await queryDnsRecords(domain, 'NSEC3PARAM', dnsOptions);
	} catch (err) {
		// The old branch pushed an `info` finding through a bare buildCheckResult: a failed
		// NSEC3PARAM lookup scored 100 and `passed: true`, and with `partial` unset both cache
		// predicates stored that non-answer for the check's TTL. The finding's own prose said
		// "Unable to assess zone walkability" — nothing passed, so abstain (#900).
		return buildDnsErrorResult(CATEGORY, 'NSEC3PARAM', err) as CheckResult;
	}

	if (nsec3Records.length === 0) return assessZoneWithoutNsec3Param(domain, dnsOptions);
	return assessNsec3Param(domain, nsec3Records[0]);
}

/** Finding for a zone with no NSEC3PARAM that is not DNSSEC-signed at all. */
function notSignedWalkabilityFinding(domain: string): Finding {
	return createFinding(
		CATEGORY,
		'Zone not DNSSEC-signed — walkability N/A',
		'info',
		`No NSEC3PARAM record was found for ${domain}, and no DNSKEY/DS records were found either, so the zone is not DNSSEC-signed. NSEC/NSEC3 denial-of-existence records only exist in signed zones, so there is no NSEC chain to walk. Zone-walking risk does not apply here. (To gain DNSSEC's spoofing/cache-poisoning protections, the zone would need to be signed — at which point NSEC3 should be used to prevent enumeration.)`,
		{ domain, walkable: false, dnssecSigned: false },
	);
}

/** Plain NSEC chain with a real adjacent owner: the zone is walkable. */
function walkableNsecFinding(domain: string, probe: DenialProbeResult): Finding {
	// `missingControl: false`, not `subjectTerms` (SQ-102): this finding requires a SIGNED zone,
	// so it never asserts an absent control, and its static detail carries a "no NSEC3PARAM …
	// plain NSEC record" span only 6 characters past MISSING_CONTROL_REGEX's 64-character gap.
	// Redacting a declared term inside that span (a dotless next-name such as "NSEC") would
	// shorten it into a match. The declaration takes the verdict away from the prose entirely.
	return createFinding(
		CATEGORY,
		'Zone is walkable via plain NSEC',
		'high',
		`The zone for ${domain} is DNSSEC-signed (DNSKEY/DS present), publishes no NSEC3PARAM, and a DO=1 denial-of-existence probe returned a plain NSEC record whose next-name (${probe.nextName}) is a genuinely different existing owner name. The zone therefore uses plain NSEC and is fully walkable — an attacker can enumerate all zone contents by following NSEC chain links.`,
		{
			domain,
			walkable: true,
			dnssecSigned: true,
			nextName: probe.nextName ?? null,
			probe: 'nsec-next-name',
			missingControl: false,
		},
	);
}

/** RFC 4470 minimally-covering NSEC: signed, not walkable. */
function minimallyCoveringFinding(domain: string, probe: DenialProbeResult): Finding {
	return createFinding(
		CATEGORY,
		'Signed zone uses minimally-covering NSEC (RFC 4470) — not walkable',
		'info',
		`The zone for ${domain} is DNSSEC-signed and publishes no NSEC3PARAM, but a DO=1 denial-of-existence probe returned a minimally-covering NSEC record (RFC 4470 "NSEC black lies", implemented by several managed DNS providers): the NSEC next-name is the synthesized \`\\000.<qname>\` (${probe.nextName}) rather than a real adjacent owner. This proves the zone is NOT walkable — an attacker cannot enumerate zone contents from the NSEC chain — even though no NSEC3PARAM is published.`,
		{
			domain,
			walkable: false,
			dnssecSigned: true,
			nextName: probe.nextName ?? null,
			probe: 'nsec-next-name',
			minimallyCovering: true,
		},
	);
}

/** NSEC3 observed despite no NSEC3PARAM: hashed denial, not trivially walkable. */
function nsec3ObservedFinding(domain: string): Finding {
	return createFinding(
		CATEGORY,
		'Signed zone uses NSEC3 denial-of-existence — not trivially walkable',
		'info',
		`The zone for ${domain} is DNSSEC-signed and publishes no NSEC3PARAM record, but a DO=1 denial-of-existence probe returned an NSEC3 (hashed) denial record. The zone therefore uses NSEC3 rather than plain NSEC, so it is not trivially walkable. (A missing NSEC3PARAM is unusual for an NSEC3 zone but does not by itself imply walkability.)`,
		{ domain, walkable: false, dnssecSigned: true, probe: 'nsec3-observed' },
	);
}

/** Signed, no NSEC3PARAM, probe could not read a denial record. */
function inconclusiveWalkabilityFinding(domain: string): Finding {
	// Inconclusive: signed, no NSEC3PARAM, but the probe could not read an NSEC/NSEC3
	// record (probe failed or authority section stripped). Do NOT assert a confident
	// high/walkable on the absence of NSEC3PARAM alone — downgrade to info (#565).
	return createFinding(
		CATEGORY,
		'Zone walkability could not be confirmed',
		'info',
		`The zone for ${domain} is DNSSEC-signed (DNSKEY/DS present) and publishes no NSEC3PARAM record, so it may use plain NSEC (walkable) or RFC 4470 minimally-covering NSEC (not walkable). A DO=1 denial-of-existence probe could not read an authority-section NSEC/NSEC3 record to confirm which, so zone walkability is inconclusive. If the zone genuinely uses plain NSEC, deploying NSEC3 would prevent enumeration.`,
		{ domain, walkable: null, dnssecSigned: true, probe: 'inconclusive' },
	);
}

/** Maps the DO=1 denial probe verdict to its finding (signed zone, no NSEC3PARAM). */
function probeVerdictFinding(domain: string, probe: DenialProbeResult): Finding {
	if (probe.verdict === 'walkable') return walkableNsecFinding(domain, probe);
	if (probe.verdict === 'minimally-covering') return minimallyCoveringFinding(domain, probe);
	if (probe.verdict === 'nsec3') return nsec3ObservedFinding(domain);
	return inconclusiveWalkabilityFinding(domain);
}

/** No NSEC3PARAM: gate on confirmed signing, then probe the denial record. Query order is load-bearing. */
async function assessZoneWithoutNsec3Param(domain: string, dnsOptions?: QueryDnsOptions): Promise<CheckResult> {
	// NSEC and NSEC3 only exist in DNSSEC-signed zones. An unsigned zone has no
	// NSEC chain at all, so "fully walkable" is a false positive. Gate the high
	// severity behind confirmed signing: check for DNSKEY (and DS as a backstop)
	// before concluding the zone uses plain NSEC.
	const signed = await isZoneSigned(domain, dnsOptions);

	if (!signed) return buildCheckResult(CATEGORY, [notSignedWalkabilityFinding(domain)]) as CheckResult;

	// Absence of NSEC3PARAM does NOT prove the zone is walkable. RFC 4470
	// "minimally-covering" NSEC (a.k.a. NSEC black lies), implemented by several
	// managed DNS providers, publishes no NSEC3PARAM and no NSEC3, yet is NOT walkable.
	// Actively probe: query a guaranteed-nonexistent label with DO=1 and inspect
	// the authority-section NSEC record to distinguish the two cases (#565).
	const probe = await probeDenialNsec(domain, dnsOptions);

	return buildCheckResult(CATEGORY, [probeVerdictFinding(domain, probe)]) as CheckResult;
}

function optOutFinding(domain: string, params: Nsec3Params): Finding {
	return createFinding(
		CATEGORY,
		'NSEC3 opt-out enabled',
		'low',
		`NSEC3PARAM for ${domain} has the opt-out flag set (flags=${params.flags}). Opt-out allows unsigned delegations to be omitted from the NSEC3 chain, which may leave some subdomains without denial-of-existence protection.`,
		{ domain, flags: params.flags, optOut: true },
	);
}

function minimalParamsFinding(domain: string, params: Nsec3Params): Finding {
	// RFC 9276 default: 0 iterations, no salt — low enumeration cost
	return createFinding(
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
	);
}

function configuredParamsFinding(domain: string, params: Nsec3Params): Finding {
	const hasSalt = params.salt !== '-';
	// Has salt and/or iterations > 0 — standard NSEC3 configuration
	return createFinding(
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
	);
}

function nsec3ParamsFinding(domain: string, params: Nsec3Params): Finding {
	// Assess walkability risk based on parameters
	const hasIterations = params.iterations > 0;
	const hasSalt = params.salt !== '-';
	return !hasIterations && !hasSalt ? minimalParamsFinding(domain, params) : configuredParamsFinding(domain, params);
}

/** Analyse the first NSEC3PARAM record (zones should have exactly one). */
function assessNsec3Param(domain: string, record: string): CheckResult {
	const params = parseNsec3Param(record);

	if (!params) {
		return buildCheckResult(CATEGORY, [
			createFinding(CATEGORY, 'Unparseable NSEC3PARAM', 'info', `NSEC3PARAM record for ${domain} could not be parsed: ${record}`, {
				domain,
				raw: record,
			}),
		]) as CheckResult;
	}

	const findings: Finding[] = [];
	// Check opt-out flag (bit 0 of flags)
	if (params.flags & 1) findings.push(optOutFinding(domain, params));
	findings.push(nsec3ParamsFinding(domain, params));
	return buildCheckResult(CATEGORY, findings) as CheckResult;
}
