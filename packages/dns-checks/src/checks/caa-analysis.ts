// SPDX-License-Identifier: BUSL-1.1

/**
 * CAA record analysis helpers.
 * Pure functions for summarizing and validating CAA records.
 *
 * Copyright (c) 2023-2026 BLACKVEIL Security
 * Licensed under BUSL-1.1
 */

import type { Finding } from '../types';
import { createFinding } from '../check-utils';

/** Parsed CAA record with flags, tag, and value */
export interface CaaRecord {
	flags: number;
	tag: string;
	value: string;
}

/**
 * Parse a single CAA record data string.
 * Handles both human-readable format (e.g. `0 issue "letsencrypt.org"`)
 * and Cloudflare DoH hex wire format (e.g. `\# 19 00 05 69 73 73 75 65...`).
 */
export function parseCaaRecord(data: string): CaaRecord | null {
	if (data.startsWith('\\#') || data.startsWith('#')) {
		const parts = data.trim().split(/\s+/);
		const hexStart = parts[0] === '\\#' || parts[0] === '#' ? 2 : 1;
		const hexBytes = parts.slice(hexStart);
		if (hexBytes.length < 3) return null;

		const flags = parseInt(hexBytes[0], 16);
		const tagLen = parseInt(hexBytes[1], 16);
		if (isNaN(flags) || isNaN(tagLen) || hexBytes.length < 2 + tagLen) return null;

		const tag = hexBytes
			.slice(2, 2 + tagLen)
			.map((hexByte) => String.fromCharCode(parseInt(hexByte, 16)))
			.join('');
		const value = hexBytes
			.slice(2 + tagLen)
			.map((hexByte) => String.fromCharCode(parseInt(hexByte, 16)))
			.join('');

		return { flags, tag: tag.toLowerCase(), value };
	}

	// Match only the `<flags> <tag> ` prefix with a regex (no adjacent unbounded
	// quantifiers → ReDoS-free), then take the value by slicing. The previous
	// single regex used `"?([^"]*)"?\s*$`, whose `[^"]*` (which includes
	// whitespace) overlapped the trailing `\s*$`, giving polynomial backtracking
	// on a crafted CAA value (CWE-1333 / js/polynomial-redos).
	const prefix = data.match(/^(\d+)\s+(\S+)\s+/);
	if (prefix) {
		let value = data.slice(prefix[0].length).trim();
		if (value.length >= 2 && value.startsWith('"') && value.endsWith('"')) {
			value = value.slice(1, -1);
		}
		return {
			flags: parseInt(prefix[1], 10),
			tag: prefix[2].toLowerCase(),
			value,
		};
	}

	return null;
}

export function summarizeCaaTags(caaRecords: CaaRecord[]): {
	hasIssue: boolean;
	hasIssuewild: boolean;
	hasIodef: boolean;
} {
	let hasIssue = false;
	let hasIssuewild = false;
	let hasIodef = false;

	for (const record of caaRecords) {
		if (record.tag === 'issue') {
			hasIssue = true;
		}
		if (record.tag === 'issuewild') {
			hasIssuewild = true;
		}
		if (record.tag === 'iodef') {
			hasIodef = true;
		}
	}

	return { hasIssue, hasIssuewild, hasIodef };
}

export function getCaaValidationFindings(tagSummary: { hasIssue: boolean; hasIssuewild: boolean; hasIodef: boolean }): Finding[] {
	const findings: Finding[] = [];

	if (!tagSummary.hasIssue) {
		findings.push(
			createFinding(
				'caa',
				'No CAA issue tag',
				'medium',
				'CAA records exist but no "issue" tag found. The "issue" tag specifies which CAs are authorized to issue certificates.',
			),
		);
	}

	if (!tagSummary.hasIssuewild) {
		findings.push(
			createFinding(
				'caa',
				'No CAA issuewild tag',
				'low',
				'No "issuewild" CAA tag found. Consider adding one to control wildcard certificate issuance separately.',
			),
		);
	}

	if (!tagSummary.hasIodef) {
		findings.push(
			createFinding(
				'caa',
				'No CAA iodef tag',
				'low',
				'No "iodef" CAA tag found. The iodef tag specifies where CAs should report policy violations.',
			),
		);
	}

	return findings;
}

export function getCaaConfiguredFinding(): Finding {
	return createFinding('caa', 'CAA properly configured', 'info', 'CAA records found with issue, issuewild, and iodef tags configured.');
}

// ─── CAA enforceability signals (CA/Browser Forum TLS Baseline Requirements) ────
//
// Two properties decide whether a published CAA policy is actually *enforceable*
// against a CA, independent of how well-formed its tags are:
//
//   1. How long a CA may keep acting on a STALE copy of the policy (TTL).
//   2. Whether the policy can be stripped in transit before the CA ever sees it
//      (DNSSEC).
//
// CITATION STYLE — the BR section numbers are deliberately written in the spaced
// form "§4.2.2 subsection 1" / "subsection 1.3". Do NOT collapse them back into
// the conventional dotted form: four dot-separated numeric components are a valid
// dotted quad, and BOTH secret scanners this repo runs in CI (the gitleaks
// `real-ipv4-address` rule and repo-safety's `public-ipv4`) then flag the citation
// as a leaked public IP. The spaced form keeps the reference precise without
// widening either scanner's allowlist to accommodate a false positive.
//
// FUTURE (dated): RFC 8657 `accounturi=` / `validationmethods=` pinning is
// deliberately NOT evaluated here. CAs are only required to "SHOULD" process
// those parameters until 2027-03-15, Let's Encrypt is the only CA with confirmed
// support, and RFC 8657 itself instructs domain owners not to assume the
// restrictions are effective absent a CA statement. Revisit after 2027-03-15,
// when the requirement becomes MUST and scoring it would reflect reality.

/**
 * The floor of the CAA reuse window in CA/B Forum TLS BR v2.2.8, §4.2.2 subsection 1:
 *
 * > If the CA issues a certificate after processing a CAA record, it MUST do so
 * > within the TTL of the CAA record, or 8 hours, whichever is greater.
 *
 * "Whichever is GREATER" — so the effective staleness window is `max(TTL, 8h)`.
 * A TTL at or below this value contributes nothing; the 8-hour floor already
 * dominates. Below this, TTL is simply not a finding.
 */
export const CAA_BR_REUSE_WINDOW_FLOOR_SECONDS = 28800;

/**
 * TTL at or below which the extension over the 8-hour floor is not worth
 * reporting: 24 hours.
 *
 * Rationale for the threshold (rather than "anything over the 8h floor"):
 * between 8h and 24h a long TTL widens the window by at most 16 hours, so an
 * operator who revokes a CA's authorization in the morning still has it fully
 * effective by the next morning — the same working-day remediation cycle as the
 * floor itself. Above 24h the stale-policy window spans MULTIPLE days and
 * outlives a normal same-day incident response: a domain publishing CAA with a
 * 7-day TTL has handed every CA a 7-day licence to keep issuing under a policy
 * the owner has already withdrawn. That is the point at which the TTL, not the
 * BR floor, is what governs.
 */
export const CAA_TTL_STALENESS_THRESHOLD_SECONDS = 86400;

/** Render a second count as a compact human duration ("7 days", "36 hours"). */
function formatDuration(seconds: number): string {
	if (seconds % 86400 === 0) {
		const days = seconds / 86400;
		return `${days} day${days === 1 ? '' : 's'}`;
	}
	const hours = Math.round((seconds / 3600) * 10) / 10;
	return `${hours} hour${hours === 1 ? '' : 's'}`;
}

/**
 * Long-TTL staleness finding for a CAA RRset.
 *
 * The CAA reuse window is a FLOOR, not a cap: BR §4.2.2 subsection 1 permits a CA to issue
 * within `max(TTL, 8h)` of processing the record, so a long TTL *extends* the
 * period in which a CA may still act on a withdrawn policy. Returns `null` when
 * the TTL is at or under {@link CAA_TTL_STALENESS_THRESHOLD_SECONDS} (nothing
 * materially wider than the 8-hour floor), or when no TTL was observed.
 *
 * Severity is `low` by design — this is a hardening nuance about revocation
 * latency, not an exposure. Nothing about it makes the CAA policy itself weaker
 * while it stands.
 *
 * @param ttlSeconds - Minimum TTL across the CAA RRset, or `undefined` if unknown.
 * @param ownerName - The name the CAA RRset was found at (may be an ancestor).
 */
export function getCaaTtlStalenessFinding(ttlSeconds: number | undefined, ownerName: string): Finding | null {
	if (ttlSeconds === undefined || !Number.isFinite(ttlSeconds) || ttlSeconds <= CAA_TTL_STALENESS_THRESHOLD_SECONDS) {
		return null;
	}
	const window = Math.max(ttlSeconds, CAA_BR_REUSE_WINDOW_FLOOR_SECONDS);
	return createFinding(
		'caa',
		'CAA record TTL widens the CA reuse window',
		'low',
		`The CAA RRset at ${ownerName} has a TTL of ${ttlSeconds}s (${formatDuration(ttlSeconds)}). Under CA/Browser Forum TLS Baseline Requirements v2.2.8 §4.2.2 subsection 1 a CA may issue within the TTL of the CAA record "or 8 hours, whichever is greater" — so this TTL, not the 8-hour floor, sets the window. If you withdraw a CA's authorization, that CA may still issue for up to ${formatDuration(window)} afterwards. Lower the CAA TTL (1 hour or less is typical) so policy changes take effect promptly.`,
		{
			caaTtlSeconds: ttlSeconds,
			caaReuseWindowSeconds: window,
			caaReuseWindowFloorSeconds: CAA_BR_REUSE_WINDOW_FLOOR_SECONDS,
		},
	);
}

/**
 * CAA × DNSSEC pairing finding — whether the published CAA policy is
 * cryptographically enforceable.
 *
 * CABF Ballot SC-085 added BR §4.2.2 subsection 1.3 (in force 2026-03-15): DNSSEC validation
 * back to the IANA root trust anchor MUST be performed on all CAA lookups, and
 * DNSSEC validation ERRORS MUST NOT be treated as permission to issue. The BRs
 * keep an explicit escape hatch, though: a CA may treat a lookup failure as
 * permission to issue once it confirms the domain is "Insecure" per RFC 4035
 * §4.3. So over an UNSIGNED zone the CAA RRset is advisory — an on-path or
 * cache-poisoning attacker can strip it and the CA is permitted to proceed.
 * Over a SIGNED zone the same record is enforced by CA policy.
 *
 * Both branches are `info`: the negative one is the missing half of a pairing
 * (the remediation is DNSSEC, which the `dnssec` category already scores — this
 * must not double-penalize), and the positive one is evidence, not a deficiency.
 *
 * @param dnssecAuthenticated - Whether the resolver authenticated the CAA
 *   response (DoH `AD` flag). `false` means the answer resolved as Insecure —
 *   exactly the RFC 4035 §4.3 determination the BR escape hatch turns on.
 * @param ownerName - The name the CAA RRset was found at (may be an ancestor).
 */
export function getCaaDnssecPairingFinding(dnssecAuthenticated: boolean, ownerName: string): Finding {
	if (dnssecAuthenticated) {
		return createFinding(
			'caa',
			'CAA policy is DNSSEC-protected',
			'info',
			`The CAA RRset at ${ownerName} was returned DNSSEC-authenticated. Under CA/Browser Forum TLS BR §4.2.2 subsection 1.3 (in force 2026-03-15) CAs must validate CAA lookups with DNSSEC to the root and must not treat validation errors as permission to issue, so this policy is cryptographically enforceable rather than advisory — it cannot be stripped in transit to unlock issuance.`,
			{ caaDnssecAuthenticated: true, caaEnforceable: true },
		);
	}
	return createFinding(
		'caa',
		'CAA policy is not DNSSEC-protected',
		'info',
		`The CAA RRset at ${ownerName} was returned without DNSSEC authentication, so the zone resolves as "Insecure". CA/Browser Forum TLS BR §4.2.2 subsection 1.3 requires CAs to validate CAA lookups with DNSSEC, but permits treating a lookup failure as permission to issue once the domain is confirmed Insecure per RFC 4035 §4.3. An on-path or cache-poisoning attacker can therefore strip this CAA policy and a CA is still permitted to issue. Signing the zone is what turns CAA from advisory into a control CAs must honour.`,
		{ caaDnssecAuthenticated: false, caaEnforceable: false },
	);
}
