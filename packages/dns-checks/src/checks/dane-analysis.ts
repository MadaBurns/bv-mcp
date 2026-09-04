// SPDX-License-Identifier: BUSL-1.1

/**
 * DANE (DNS-Based Authentication of Named Entities) analysis helpers.
 * Pure functions for analyzing TLSA records and classifying DANE presence.
 *
 * Copyright (c) 2023-2026 BLACKVEIL Security
 * Licensed under BUSL-1.1
 */

import type { Finding } from '../types';
import { createFinding } from '../check-utils';
import { SUBJECT_TERMS_METADATA_KEY } from '../scoring/model';

/** Parsed TLSA record with usage, selector, matching type, and certificate data */
export interface TlsaRecord {
	usage: number;
	selector: number;
	matchingType: number;
	certData: string;
}

/**
 * Parse a TLSA record data string into structured fields.
 * Handles both human-readable format (`usage selector matchingType certData`)
 * and hex wire format (data starting with `\#`).
 */
export function parseTlsaRecord(data: string): TlsaRecord | null {
	if (data.startsWith('\\#') || data.startsWith('#')) {
		const parts = data.trim().split(/\s+/);
		const hexStart = parts[0] === '\\#' || parts[0] === '#' ? 2 : 1;
		const hexBytes = parts.slice(hexStart);
		if (hexBytes.length < 4) return null;

		const usage = parseInt(hexBytes[0], 16);
		const selector = parseInt(hexBytes[1], 16);
		const matchingType = parseInt(hexBytes[2], 16);
		if (isNaN(usage) || isNaN(selector) || isNaN(matchingType)) return null;

		const certData = hexBytes.slice(3).join('');
		return { usage, selector, matchingType, certData };
	}

	const parts = data.trim().split(/\s+/);
	if (parts.length < 4) return null;

	const usage = parseInt(parts[0], 10);
	const selector = parseInt(parts[1], 10);
	const matchingType = parseInt(parts[2], 10);
	if (isNaN(usage) || isNaN(selector) || isNaN(matchingType)) return null;

	const certData = parts.slice(3).join('');
	return { usage, selector, matchingType, certData };
}

/** TLSA usage field labels for human-readable output. */
const USAGE_LABELS: Record<number, string> = {
	0: 'PKIX-TA (CA constraint)',
	1: 'PKIX-EE (service certificate constraint)',
	2: 'DANE-TA (trust anchor assertion)',
	3: 'DANE-EE (domain-issued certificate)',
};

/**
 * One member of the certificate chain a host served, as captured by an out-of-package
 * probe (bv-tls-probe over the operator-only `BV_TLS_PROBE` binding). Digests are
 * lowercase hex; DER is base64. Every field is optional so a probe that omits one
 * makes the affected association UNVERIFIABLE rather than UNMATCHED — a dropped field
 * must never read as a broken pin.
 */
export interface ServedCertificateChainEntry {
	/** SHA-256 over the certificate DER (TLSA selector 0, matching type 1). */
	sha256?: string;
	/** SHA-512 over the certificate DER (selector 0, matching type 2). */
	sha512?: string;
	/** SHA-256 over the SubjectPublicKeyInfo DER (selector 1, matching type 1). */
	spkiSha256?: string;
	/** SHA-512 over the SubjectPublicKeyInfo DER (selector 1, matching type 2). */
	spkiSha512?: string;
	/** Base64 certificate DER (selector 0, matching type 0 — full data). */
	der?: string;
	/** Base64 SubjectPublicKeyInfo DER (selector 1, matching type 0). Not in the probe contract for non-leaf entries. */
	spkiDer?: string;
}

/**
 * The certificate a host served on a given port, captured by an external probe.
 * Runtime-agnostic: this package never parses X.509 — every comparison is digest /
 * hex equality against material the probe already derived. `chain[0]` is the leaf;
 * the leaf-level fields duplicate it for the selector-0 / selector-1 end-entity paths.
 */
export interface ServedCertificate {
	/** Exact host the probe pinned — DANE pins the TLSA owner's host, so this MUST equal the scanned name. */
	host: string;
	port: number;
	/** ISO timestamp of the capture. */
	capturedAt?: string;
	leafDer?: string;
	leafSpkiDer?: string;
	leafSha256?: string;
	leafSha512?: string;
	leafSpkiSha256?: string;
	leafSpkiSha512?: string;
	/** Whole served chain, index 0 == leaf (DANE-TA usage 2 / PKIX-TA usage 0 search every entry). */
	chain?: ServedCertificateChainEntry[];
	/**
	 * True when the served chain exceeded the probe's entry cap and trailing entries were
	 * dropped. A trust-anchor usage (0 / 2) that matches no RETAINED entry is then
	 * UNVERIFIABLE — the anchor may sit in the dropped tail — never a mismatch.
	 */
	chainTruncated?: boolean;
	/** The chain's original length before truncation. */
	chainLength?: number;
	subjectName?: string;
	subjectAlternativeNames?: string[];
	validFrom?: number;
	validTo?: number;
}

/**
 * What the certificate probe reported when no certificate is available.
 * - `unavailable` — no probe capability at all (BSL self-hosts without the binding).
 *   The pin stays "present, not verified" and keeps its small deduction.
 * - `pending` — the probe was reached but is still warming its cache; the verdict
 *   arrives on a later call. The pin is UNMEASURED this run: no deduction, `partial`.
 * - `failed` — the probe was attempted and returned no usable certificate (capture
 *   error, off-host redirect, host mismatch, transport failure). Also UNMEASURED.
 */
export type CertificateProbeOutcome = 'unavailable' | 'pending' | 'failed';

/** Verification input for {@link analyzeTlsaRecords}: the served certificate, or why there is none. */
export interface TlsaVerificationContext {
	/** The certificate the host served. When present, every association is compared against it. */
	servedCertificate?: ServedCertificate | null;
	/** Why no certificate is available. Ignored when `servedCertificate` is set. Default `unavailable`. */
	certificateProbe?: CertificateProbeOutcome;
	/** Machine token explaining a `pending` / `failed` probe (surfaced as `notAssessedReason`). */
	certificateProbeReason?: string;
}

/** Result of {@link verifyTlsaAssociations}. */
export interface TlsaVerification {
	/** Associations whose pinned data matches the served certificate (RFC 7671: one suffices). */
	matched: TlsaRecord[];
	/** Associations the served certificate could be compared against and does NOT match. */
	unmatched: TlsaRecord[];
	/** Associations that could not be compared (unknown field values, probe material absent, or a truncated chain). */
	unverifiable: TlsaRecord[];
	/**
	 * The subset of `unverifiable` whose verdict was withheld ONLY because the served chain
	 * was truncated (`chainTruncated: true`): trust-anchor usages that matched no retained
	 * entry. Empty unless the probe reported truncation.
	 */
	truncatedChain: TlsaRecord[];
}

/** Decode base64 to lowercase hex. Returns null when the input is not valid base64. */
function base64ToHex(b64: string): string | null {
	try {
		const bin = atob(b64.replace(/\s+/g, ''));
		let hex = '';
		for (let i = 0; i < bin.length; i++) hex += bin.charCodeAt(i).toString(16).padStart(2, '0');
		return hex;
	} catch {
		return null;
	}
}

/** Canonical form for hex comparison: lowercase, whitespace stripped (TLSA presentation may split hex). */
function canonicalHex(value: string): string {
	return value.replace(/\s+/g, '').toLowerCase();
}

/** The material one chain member offers for a given selector. Absent fields are uncomparable. */
interface AssociationCandidate {
	sha256?: string;
	sha512?: string;
	/** Base64 DER of the selected object (certificate or SPKI). */
	der?: string;
}

function leafCandidate(cert: ServedCertificate, selector: number): AssociationCandidate {
	return selector === 0
		? { sha256: cert.leafSha256, sha512: cert.leafSha512, der: cert.leafDer }
		: { sha256: cert.leafSpkiSha256, sha512: cert.leafSpkiSha512, der: cert.leafSpkiDer };
}

function chainCandidate(
	entry: ServedCertificateChainEntry,
	selector: number,
	isLeaf: boolean,
	cert: ServedCertificate,
): AssociationCandidate {
	if (selector === 0) {
		return {
			sha256: entry.sha256 ?? (isLeaf ? cert.leafSha256 : undefined),
			sha512: entry.sha512 ?? (isLeaf ? cert.leafSha512 : undefined),
			der: entry.der ?? (isLeaf ? cert.leafDer : undefined),
		};
	}
	return {
		sha256: entry.spkiSha256 ?? (isLeaf ? cert.leafSpkiSha256 : undefined),
		sha512: entry.spkiSha512 ?? (isLeaf ? cert.leafSpkiSha512 : undefined),
		// The probe contract carries no SPKI DER for non-leaf entries; the leaf's is known.
		der: entry.spkiDer ?? (isLeaf ? cert.leafSpkiDer : undefined),
	};
}

/**
 * The chain members a record's usage may match (RFC 7671 §5). End-entity usages (1, 3)
 * bind the LEAF only; trust-anchor usages (0, 2) may match ANY served chain member —
 * including the leaf, which §5.2 allows when the TA is also the EE. Returns null for a
 * usage outside 0–3.
 */
function candidatesFor(record: TlsaRecord, cert: ServedCertificate): AssociationCandidate[] | null {
	if (record.selector !== 0 && record.selector !== 1) return null;
	switch (record.usage) {
		case 1:
		case 3:
			return [leafCandidate(cert, record.selector)];
		case 0:
		case 2: {
			const chain = cert.chain ?? [];
			if (chain.length === 0) return [leafCandidate(cert, record.selector)];
			return chain.map((entry, i) => chainCandidate(entry, record.selector, i === 0, cert));
		}
		default:
			return null;
	}
}

/** true = match, false = compared and differs, null = this candidate cannot be compared. */
function compareCandidate(record: TlsaRecord, candidate: AssociationCandidate): boolean | null {
	const pinned = canonicalHex(record.certData);
	if (pinned.length === 0) return null;
	switch (record.matchingType) {
		case 1:
			return candidate.sha256 === undefined ? null : canonicalHex(candidate.sha256) === pinned;
		case 2:
			return candidate.sha512 === undefined ? null : canonicalHex(candidate.sha512) === pinned;
		case 0: {
			if (candidate.der === undefined) return null;
			const hex = base64ToHex(candidate.der);
			return hex === null ? null : hex === pinned;
		}
		default:
			return null;
	}
}

/**
 * Compare a TLSA RRset against the certificate the host served (RFC 7671 semantics).
 *
 * Pure and runtime-agnostic — digest / hex equality only, no X.509 parsing:
 *
 * | usage        | compared against              | selector 0 → | selector 1 → |
 * | ------------ | ----------------------------- | ------------ | ------------ |
 * | 3 DANE-EE    | the leaf                      | cert DER     | SPKI DER     |
 * | 1 PKIX-EE    | the leaf                      | cert DER     | SPKI DER     |
 * | 2 DANE-TA    | ANY served chain entry (incl. leaf, §5.2) | cert DER | SPKI DER |
 * | 0 PKIX-TA    | ANY served chain entry (incl. leaf)       | cert DER | SPKI DER |
 *
 * matching type 1 = SHA-256 of the selected object, 2 = SHA-512, 0 = the full object
 * (hex of the base64-decoded DER, compared case-insensitively). Any other usage /
 * selector / matching type — or probe material the comparison needs but does not have
 * — lands in `unverifiable`, never `unmatched`. Strings are parsed with
 * {@link parseTlsaRecord}; unparseable strings are dropped (they carry their own
 * "Malformed TLSA record" finding upstream).
 */
export function verifyTlsaAssociations(records: TlsaRecord[] | string[], cert: ServedCertificate): TlsaVerification {
	const matched: TlsaRecord[] = [];
	const unmatched: TlsaRecord[] = [];
	const unverifiable: TlsaRecord[] = [];
	const truncatedChain: TlsaRecord[] = [];
	for (const raw of records) {
		const record = typeof raw === 'string' ? parseTlsaRecord(raw) : raw;
		if (!record) continue;
		const candidates = candidatesFor(record, cert);
		if (!candidates) {
			unverifiable.push(record);
			continue;
		}
		// A record is UNMATCHED only when EVERY candidate it may match was compared and
		// differs. One uncomparable candidate (a chain member the probe carried no material
		// for) is enough to withhold that verdict — for a TA usage the pin may match that
		// very member — so it lands in `unverifiable` instead.
		let sawUncomparable = false;
		let hit = false;
		for (const candidate of candidates) {
			const outcome = compareCandidate(record, candidate);
			if (outcome === null) {
				sawUncomparable = true;
				continue;
			}
			if (outcome) {
				hit = true;
				break;
			}
		}
		if (hit) matched.push(record);
		else if (sawUncomparable) unverifiable.push(record);
		else if ((record.usage === 0 || record.usage === 2) && cert.chainTruncated === true) {
			// Every RETAINED chain entry was compared and differs, but the probe dropped the
			// chain's tail — the anchor may be there. Withhold the verdict.
			unverifiable.push(record);
			truncatedChain.push(record);
		} else unmatched.push(record);
	}
	return { matched, unmatched, unverifiable, truncatedChain };
}

/**
 * Machine-readable `notAssessedReason` tokens for a pin the probe could not verify.
 * Every one of them scores the SAME `low` "present, not verified" finding (95) as a
 * consumer with no probe at all — an attempted-but-unanswered comparison is not better
 * evidence than no comparison. The token tells consumers WHICH sub-state applies.
 */
export const DANE_PIN_NOT_ASSESSED_REASONS = {
	/** The probe's cold-cache verdict; the answer arrives on a later call. */
	pending: 'certificate_probe_pending',
	/** The probe reached the host but could not capture a usable certificate. */
	captureFailed: 'capture_failed',
	/** The probe followed a redirect off the TLSA owner's host (permanent for that host). */
	offHostRedirect: 'off_host_redirect',
	/** The capture describes a host other than the scanned one (permanent). */
	hostMismatch: 'host_mismatch',
	/** The host did not answer the probe. */
	unreachable: 'unreachable',
	/** The probe service itself failed (5xx, throw, timeout, budget cut). */
	probeUnavailable: 'probe_unavailable',
	/** A trust-anchor pin may sit in the chain tail the probe dropped (permanent). */
	chainTruncated: 'chain_truncated',
} as const;

/**
 * Reasons a later scan may resolve by itself. A result carrying one is marked `partial`
 * (not cached for the scan TTL, re-tried next scan). The rest are permanent for the
 * host and cache normally — no retry-forever.
 */
export const DANE_PIN_TRANSIENT_REASONS: ReadonlySet<string> = new Set([
	DANE_PIN_NOT_ASSESSED_REASONS.pending,
	DANE_PIN_NOT_ASSESSED_REASONS.captureFailed,
	DANE_PIN_NOT_ASSESSED_REASONS.unreachable,
	DANE_PIN_NOT_ASSESSED_REASONS.probeUnavailable,
]);

/** True when a `notAssessedReason` names a transient probe outcome worth re-trying. */
export function isTransientDanePinReason(reason: unknown): boolean {
	return typeof reason === 'string' && DANE_PIN_TRANSIENT_REASONS.has(reason);
}

/**
 * Analyze a set of TLSA records for a given DNS name.
 * Validates field ranges, checks DNSSEC dependency, and flags weak matching types.
 */
export function analyzeTlsaRecords(records: string[], name: string, hasDnssec: boolean, verification?: TlsaVerificationContext): Finding[] {
	const findings: Finding[] = [];
	const seenDaneWithoutDnssec = new Set<string>();
	const validRecords: TlsaRecord[] = [];

	for (const record of records) {
		const parsed = parseTlsaRecord(record);
		if (!parsed) {
			findings.push(createFinding('dane', 'Malformed TLSA record', 'medium', `Could not parse TLSA record for ${name}: ${record}`));
			continue;
		}

		// Validate usage field (0-3)
		if (parsed.usage < 0 || parsed.usage > 3) {
			findings.push(
				createFinding(
					'dane',
					'Invalid TLSA usage',
					'medium',
					`TLSA record for ${name} has invalid usage value ${parsed.usage}. Valid range is 0-3.`,
					{ usage: parsed.usage },
				),
			);
			continue;
		}

		// Validate selector field (0-1)
		if (parsed.selector < 0 || parsed.selector > 1) {
			findings.push(
				createFinding(
					'dane',
					'Invalid TLSA selector',
					'medium',
					`TLSA record for ${name} has invalid selector value ${parsed.selector}. Valid range is 0-1.`,
					{ selector: parsed.selector },
				),
			);
			continue;
		}

		// Validate matching type field (0-2)
		if (parsed.matchingType < 0 || parsed.matchingType > 2) {
			findings.push(
				createFinding(
					'dane',
					'Invalid TLSA matching type',
					'medium',
					`TLSA record for ${name} has invalid matching type ${parsed.matchingType}. Valid range is 0-2.`,
					{ matchingType: parsed.matchingType },
				),
			);
			continue;
		}

		// DANE-EE (3) and DANE-TA (2) require DNSSEC for security — deduplicate per host
		if ((parsed.usage === 2 || parsed.usage === 3) && !hasDnssec && !seenDaneWithoutDnssec.has(name)) {
			seenDaneWithoutDnssec.add(name);
			const usageLabel = USAGE_LABELS[parsed.usage] ?? `usage ${parsed.usage}`;
			findings.push(
				createFinding(
					'dane',
					'DANE without DNSSEC',
					'high',
					`TLSA record for ${name} uses ${usageLabel} but DNSSEC is not validated. Without DNSSEC, DANE records can be spoofed, negating their security benefit.`,
					{ usage: parsed.usage, name },
				),
			);
		}

		// Matching type 0 = full certificate data (less secure than hash)
		if (parsed.matchingType === 0) {
			findings.push(
				createFinding(
					'dane',
					'TLSA uses full certificate matching',
					'low',
					`TLSA record for ${name} uses matching type 0 (full certificate). SHA-256 (type 1) or SHA-512 (type 2) matching is recommended for better security and smaller records.`,
					{ matchingType: parsed.matchingType, name },
				),
			);
		}

		// Collect well-formed records for the consolidated verdict below
		validRecords.push(parsed);
	}
	const validRecordCount = validRecords.length;

	// Consolidated verdict for the well-formed records (#841).
	//
	// HONESTY (#841): this analyzer parses DNS; it never fetches a certificate. A stale
	// DANE-EE pin parses identically to a correct one, so "well-formed" is a SYNTAX
	// verdict. Since scoring model 1.22.0 the served certificate CAN reach this function —
	// the bv-mcp wrapper captures it over the operator-only bv-tls-probe binding and
	// passes it in `verification` — and the verdict ladder is:
	//   any association matches            → info, `certificateMatchVerified: true`   (100)
	//   certificate served, none match     → high "pin does not match"                 (75)
	//   probe attempted, no certificate    → the SAME low "present, not verified" (95) plus
	//                                        `certificateProbe` + `notAssessedReason` metadata
	//   no probe capability (self-hosts)   → low "present, not verified" — the 1.18.0 posture, unchanged (95)
	// Every unverified state sits at 95 (operator-ratified 1.18.0 posture): an attempted
	// comparison that produced no answer is not better evidence than no comparison, so it
	// must never outscore the honest self-host disclosure. Only an ACTUAL comparison moves
	// the score — up to 100 or down to 75.
	// `certificateMatchVerified` is the machine-readable marker every consumer must read
	// (maturity staging counts a DANE pin toward Stage 4 ONLY when it is `true`).
	if (validRecordCount > 0) {
		const cert = verification?.servedCertificate ?? null;
		if (cert) {
			findings.push(buildVerifiedVerdict(name, validRecords, cert));
		} else if (verification?.certificateProbe === 'pending' || verification?.certificateProbe === 'failed') {
			findings.push(buildUnmeasuredVerdict(name, validRecordCount, verification.certificateProbe, verification.certificateProbeReason));
		} else {
			findings.push(buildUnverifiedVerdict(name, validRecordCount));
		}
	}

	return findings;
}

/**
 * The 1.18.0 posture: present + well-formed, not confirmed against the served
 * certificate. Text is pinned by dane-honest-labeling.test.ts. `extra` carries the
 * sub-state metadata (`certificateProbe`, `notAssessedReason`, …) when a probe was
 * attempted; the no-probe path passes nothing so its metadata is byte-identical.
 */
function buildUnverifiedVerdict(name: string, validRecordCount: number, extra: Record<string, unknown> = {}): Finding {
	const detail =
		validRecordCount === 1
			? `TLSA record present and syntactically well-formed for ${name}. This check does not verify the pinned data against the certificate the server presents, so a stale pin is not detected here. Where the RRset is DNSSEC-authenticated and no association matches the served certificate, DANE-validating clients reject the connection. Confirm the pin matches the live certificate after every certificate rotation.`
			: `${validRecordCount} DANE TLSA records present and syntactically well-formed for ${name}. This check does not verify the pinned data against the certificate the server presents, so a stale pin is not detected here. Authentication succeeds while any one association still matches, so a single superseded record during a rollover is not itself fatal; where the RRset is DNSSEC-authenticated and none match, DANE-validating clients reject the connection. Confirm each pin matches the live certificate after every certificate rotation.`;
	return createFinding('dane', `DANE TLSA configured for ${name}`, 'low', detail, {
		name,
		validRecordCount,
		certificateMatchVerified: false,
		...extra,
	});
}

/**
 * The probe was ATTEMPTED and returned no certificate: the pin is still unverified, so
 * the verdict is the SAME `low` as the no-probe path (95) — never `info`/100, which
 * would rank "we tried and learned nothing" above the honest self-host disclosure.
 * The metadata names the sub-state: `certificateProbe` (`pending` | `failed`) and a
 * `notAssessedReason` token. `checkDANEHTTPS` marks the result `partial` only for the
 * TRANSIENT reasons ({@link DANE_PIN_TRANSIENT_REASONS}) so a cold cache is re-tried and
 * a permanently-failing host is not re-probed forever. No `inconclusive` marker: that
 * vocabulary is reserved for no-penalty abstentions, and this finding carries a penalty
 * because the TLSA measurement itself is real.
 */
function buildUnmeasuredVerdict(
	name: string,
	validRecordCount: number,
	outcome: 'pending' | 'failed',
	reason: string | undefined,
): Finding {
	const notAssessedReason =
		reason ?? (outcome === 'pending' ? DANE_PIN_NOT_ASSESSED_REASONS.pending : DANE_PIN_NOT_ASSESSED_REASONS.captureFailed);
	return buildUnverifiedVerdict(name, validRecordCount, { certificateProbe: outcome, notAssessedReason });
}

/** Compact presentation of an association for prose / metadata. */
function describeAssociation(r: TlsaRecord): string {
	return `${r.usage} ${r.selector} ${r.matchingType} ${canonicalHex(r.certData)}`;
}

/**
 * A certificate WAS captured: compare and rule. The `high` mismatch wording is
 * deliberately free of the `MISSING_CONTROL_REGEX` triggers ("missing", "required",
 * "not found", "no … record") — `dane_https` sits in `PROFILE_CRITICAL_CATEGORIES`
 * for `non_mail` / `web_only`, and a `high` that read as a missing control would arm
 * the critical-gap ceiling and cap the whole scan at 64. A mismatch is a MEASURED
 * defect (−25, category 75), not an absent control. Pinned by
 * dane-pin-verification.test.ts.
 */
function buildVerifiedVerdict(name: string, validRecords: TlsaRecord[], cert: ServedCertificate): Finding {
	const verification = verifyTlsaAssociations(validRecords, cert);
	const served = {
		servedHost: cert.host,
		servedPort: cert.port,
		...(cert.capturedAt ? { capturedAt: cert.capturedAt } : {}),
		...(cert.leafSha256 ? { servedLeafSha256: canonicalHex(cert.leafSha256) } : {}),
		...(cert.leafSpkiSha256 ? { servedLeafSpkiSha256: canonicalHex(cert.leafSpkiSha256) } : {}),
	};

	if (verification.matched.length > 0) {
		const first = verification.matched[0];
		const usageLabel = USAGE_LABELS[first.usage] ?? `usage ${first.usage}`;
		const others = validRecords.length - verification.matched.length;
		return createFinding(
			'dane',
			`DANE TLSA verified against the served certificate for ${name}`,
			'info',
			`The TLSA association ${describeAssociation(first)} (${usageLabel}) at ${name} matches the certificate ${cert.host} serves on port ${cert.port}${cert.capturedAt ? ` (captured ${cert.capturedAt})` : ''}.${others > 0 ? ` ${others} further association${others === 1 ? '' : 's'} in the RRset did not match — normal during a certificate rollover, harmless while one association matches.` : ''} Keep the RRset in step with certificate rotation; a CDN-managed certificate rotates on the provider's schedule.`,
			{
				...served,
				name,
				validRecordCount: validRecords.length,
				certificateMatchVerified: true,
				matchedAssociations: verification.matched.map(describeAssociation),
				matchedUsage: first.usage,
				matchedSelector: first.selector,
				matchedMatchingType: first.matchingType,
				matchedCertData: canonicalHex(first.certData),
				...(verification.unmatched.length > 0 ? { unmatchedAssociations: verification.unmatched.map(describeAssociation) } : {}),
				...(verification.unverifiable.length > 0 ? { unverifiableAssociations: verification.unverifiable.map(describeAssociation) } : {}),
			},
		);
	}

	if (verification.truncatedChain.length > 0) {
		// A trust-anchor pin may sit in the chain tail the probe dropped: the pin is
		// unverified (the same `low`, 95), never a mismatch. Permanent for that host, so
		// no `certificateProbe` marker — the result is not `partial` and caches normally.
		return buildUnverifiedVerdict(name, validRecords.length, {
			...served,
			notAssessedReason: DANE_PIN_NOT_ASSESSED_REASONS.chainTruncated,
			chainTruncated: true,
			...(cert.chainLength !== undefined ? { chainLength: cert.chainLength } : {}),
			unverifiableAssociations: verification.unverifiable.map(describeAssociation),
			...(verification.unmatched.length > 0 ? { unmatchedAssociations: verification.unmatched.map(describeAssociation) } : {}),
		});
	}

	if (verification.unverifiable.length > 0) {
		// At least one association could not be compared, so "the pin is wrong" is not
		// established — fall back to the honest present-not-verified posture.
		const unverified = buildUnverifiedVerdict(name, validRecords.length);
		return {
			...unverified,
			metadata: {
				...unverified.metadata,
				...served,
				unmatchedAssociations: verification.unmatched.map(describeAssociation),
				unverifiableAssociations: verification.unverifiable.map(describeAssociation),
			},
		};
	}

	const pinned = verification.unmatched.map(describeAssociation);
	const count = pinned.length;
	return createFinding(
		'dane',
		`DANE TLSA pin does not match the served certificate for ${name}`,
		'high',
		`${count === 1 ? 'The TLSA association' : `Each of the ${count} TLSA associations`} published at ${name} was compared against the certificate ${cert.host} serves on port ${cert.port}${cert.capturedAt ? ` (captured ${cert.capturedAt})` : ''} and none of them match it: pinned ${pinned.join('; ')}; served leaf SPKI SHA-256 ${served.servedLeafSpkiSha256 ?? 'unavailable'}, leaf SHA-256 ${served.servedLeafSha256 ?? 'unavailable'}. Where the RRset is DNSSEC-authenticated, DANE-validating clients reject the connection to this host. Republish the TLSA RRset from the current certificate (its issuer for DANE-TA) and automate the update on every rotation — a CDN-managed certificate rotates on the provider's schedule, so a hand-maintained DANE-EE pin drifts by default.`,
		{
			...served,
			name,
			validRecordCount: validRecords.length,
			certificateMatchVerified: false,
			pinned,
			unmatchedAssociations: pinned,
			// The pinned data is a raw DNS record token the zone owner controls. Declaring it
			// as subject data has the missing-control predicate test the prose WITHOUT it, so
			// a record such as `3 1 1 missing` cannot smuggle a regex trigger into a `high`
			// finding and zero the category / arm the critical-gap ceiling.
			[SUBJECT_TERMS_METADATA_KEY]: pinned,
		},
	);
}

/**
 * Generate findings when no TLSA records are found for MX and/or HTTPS endpoints.
 */
export function classifyDanePresence(hasMxTlsa: boolean, hasHttpsTlsa: boolean): Finding[] {
	const findings: Finding[] = [];

	if (!hasMxTlsa) {
		findings.push(
			createFinding(
				'dane',
				'No DANE TLSA for MX servers',
				'medium',
				'No TLSA records found for MX server SMTP ports (_25._tcp). DANE pins TLS certificates to DNS, preventing CA misissuance attacks on email delivery.',
			),
		);
	}

	if (!hasHttpsTlsa) {
		findings.push(
			createFinding(
				'dane',
				'No DANE TLSA for HTTPS',
				'low',
				'No TLSA record found for HTTPS endpoint (_443._tcp). DANE can pin web server certificates to DNS, providing an additional layer of trust beyond the CA system.',
			),
		);
	}

	return findings;
}
