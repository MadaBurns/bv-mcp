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
	hasIssuemail: boolean;
} {
	let hasIssue = false;
	let hasIssuewild = false;
	let hasIodef = false;
	let hasIssuemail = false;

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
		if (record.tag === 'issuemail') {
			hasIssuemail = true;
		}
	}

	return { hasIssue, hasIssuewild, hasIodef, hasIssuemail };
}

/**
 * RFC 8657 parameters carried inside an `issue` / `issuewild` CAA value.
 *
 * The value grammar (RFC 8659 §4.2) is `issuer-domain-name *(";" parameter)`, so
 * the parameters are a suffix of the SAME value string, not separate records.
 */
export interface CaaParameters {
	/**
	 * The issuer domain name preceding the parameter list, lowercased. Empty string
	 * for the explicit no-issuance form — see {@link CaaParameters.noIssuance}.
	 */
	issuerDomain: string;
	/**
	 * True for the RFC 8659 §4.2 explicit no-issuance form (`issue ";"`), where the
	 * issuer-domain-name is absent and NO CA is authorized. This is the opposite of
	 * a parameterless grant, so it must never be read as "any CA may issue": the
	 * empty `issuerDomain` alone does not distinguish the two.
	 */
	noIssuance: boolean;
	/** RFC 8657 §3 `accounturi` — pins issuance to one ACME account. */
	accounturi?: string;
	/**
	 * RFC 8657 §4 `validationmethods` — the ACME challenge types the CA may use.
	 * Always a list: the grammar is comma-separated and a single method is a
	 * one-element list, never a bare string.
	 */
	validationmethods?: string[];
}

/** Strip one layer of surrounding double quotes from a parameter value. */
function unquote(value: string): string {
	if (value.length >= 2 && value.startsWith('"') && value.endsWith('"')) {
		return value.slice(1, -1);
	}
	return value;
}

/**
 * Parse the RFC 8657 parameters out of an `issue` / `issuewild` CAA value.
 *
 * Parameter tags are matched case-INSENSITIVELY (`AccountURI` === `accounturi`):
 * RFC 8659 §4.2 defines the property tag as case-insensitive and CAs in practice
 * accept mixed case here, so a case-sensitive parse would silently report a real
 * account pin as absent.
 *
 * @param value - The raw CAA record value (the `value` field of a {@link CaaRecord}).
 */
export function parseCaaParameters(value: string): CaaParameters {
	const segments = value.split(';');
	const issuerDomain = (segments[0] ?? '').trim().toLowerCase();
	// RFC 8659 §4.2: a value whose issuer-domain-name is absent forbids ALL issuance.
	// Distinguished from an empty/absent value, which is not a no-issuance directive.
	const noIssuance = issuerDomain === '' && segments.length > 1;

	const params: CaaParameters = { issuerDomain, noIssuance };

	for (const segment of segments.slice(1)) {
		const eq = segment.indexOf('=');
		if (eq === -1) continue;
		const key = segment.slice(0, eq).trim().toLowerCase();
		const raw = unquote(segment.slice(eq + 1).trim());
		if (key === 'accounturi') {
			params.accounturi = raw;
		} else if (key === 'validationmethods') {
			params.validationmethods = raw
				.split(',')
				.map((method) => method.trim())
				.filter((method) => method.length > 0);
		}
	}

	return params;
}

// ─── Bounds on RFC 8657 parameter rendering (CWE-1333 / CWE-770) ──────────────
//
// CAA values are DNS data, so for any domain an attacker controls they are
// ATTACKER-AUTHORED and unbounded in both length and cardinality. Two costs
// follow, and both were measured on the pre-cap implementation:
//
//   * CPU — the distinct-method dedupe was `Array.includes` inside a loop, i.e.
//     O(n²). MEASURED on the pre-cap body: a single realistic ~64 KB DoH response
//     cost 116.9-197.7 ms (4.3k-16.3k distinct methods, depending on token length);
//     50k methods 1,437 ms; 200k methods 20,199 ms. Now a `Set`: 1.1 / 5.4 /
//     16.0 ms respectively.
//   * OUTPUT — the joined detail string and the metadata array were unbounded.
//     MEASURED: the same 64 KB input produced a 68,759-byte finding detail and
//     200k methods a 2,707,291-byte one, all of which flows verbatim into the MCP
//     `structuredContent` LLM channel. Now 591 / 734 bytes.
//
// Same class of hazard the two existing remediation comments in this file address
// (`parseCaaRecord` ReDoS, `MISSING_CONTROL_REGEX` bound), and the caps follow the
// package's existing `MAX_*` convention (`MAX_INCLUDE_PROBES`,
// `MAX_LAME_DELEGATION_PROBES`, `MAX_META_STRING`).
//
// Every cap is set FAR above real-world CAA practice, so no honest policy is ever
// clipped: ACME defines three validation methods in total (`http-01`, `dns-01`,
// `tls-alpn-01`), and a CAA RRset naming more than a handful of distinct issuers
// is already unusual. When a cap DOES bite, the truncation is stated in the detail
// and flagged in metadata — a clipped list must never read as a complete one.

/** Distinct `validationmethods` tokens retained. ACME defines 3; 8 is generous headroom. */
export const MAX_CAA_VALIDATION_METHODS = 8;

/** Distinct issuer domains rendered in the detail. */
export const MAX_CAA_ISSUERS = 8;

/**
 * Rendered length of ONE attacker-authored token (a method name or issuer domain).
 * Longest real token is `tls-alpn-01` (11) and an issuer is a DNS label sequence;
 * 64 keeps any legitimate value intact while stopping a 64 KB "method".
 */
export const MAX_CAA_TOKEN_LENGTH = 64;

/** Appended to any value this module clipped, so truncation is visible in the text itself. */
export const TRUNCATION_MARKER = '...(truncated)';

/**
 * Defensive ceiling on the emitted detail string. The per-token and per-list caps
 * already bound the detail to roughly 2 KB; this is the belt-and-braces backstop
 * that holds even if a future clause is added without one.
 */
export const MAX_CAA_PARAMETER_DETAIL_LENGTH = 4_000;

/** Clamp one attacker-authored token to a bounded, honestly-marked rendering. */
function clampToken(token: string): string {
	return token.length > MAX_CAA_TOKEN_LENGTH ? `${token.slice(0, MAX_CAA_TOKEN_LENGTH)}${TRUNCATION_MARKER}` : token;
}

/**
 * RFC 8657 account / validation-method binding finding.
 *
 * `accounturi` pins issuance to a single ACME account and `validationmethods`
 * restricts which challenge types a CA may accept — together they narrow a CAA
 * grant from "this CA may issue" to "this CA may issue, for this account, via
 * these methods". That closes the residual hole in a plain CAA grant: an attacker
 * who can pass ANY validation at an authorized CA can otherwise still obtain a
 * certificate.
 *
 * ALWAYS `info`, and ALWAYS ABSENT when no parameters are published. These are
 * BONUS signals, not a baseline: the overwhelming majority of CAA-publishing
 * domains carry no RFC 8657 parameters, so emitting a scored finding for their
 * absence would penalize essentially every domain that did the right thing by
 * publishing CAA at all. Absence is not a defect — say nothing.
 *
 * @param caaRecords - The parsed CAA RRset governing the name.
 */
export function getCaaParameterBindingFindings(caaRecords: CaaRecord[]): Finding[] {
	// `Set`, not `Array.includes` — the linear scan inside the loop was the O(n²).
	// The account URIs are only ever COUNTED, so they are counted rather than
	// retained: keeping 16k attacker-authored URI strings alive bought nothing.
	const validationMethods = new Set<string>();
	const issuers = new Set<string>();
	let accountUriCount = 0;
	let validationMethodsTruncated = false;
	let issuersTruncated = false;

	for (const record of caaRecords) {
		if (record.tag !== 'issue' && record.tag !== 'issuewild') continue;
		const params = parseCaaParameters(record.value);
		if (params.accounturi === undefined && params.validationmethods === undefined) continue;
		if (params.accounturi !== undefined) accountUriCount += 1;
		for (const method of params.validationmethods ?? []) {
			const token = clampToken(method);
			// Duplicate-first: a repeated token is NOT a dropped one, so an RRset that
			// republishes the same methods on `issue` and `issuewild` must not be
			// mislabelled as truncated.
			if (validationMethods.has(token)) continue;
			if (validationMethods.size >= MAX_CAA_VALIDATION_METHODS) {
				validationMethodsTruncated = true;
				continue;
			}
			validationMethods.add(token);
		}
		if (params.issuerDomain !== '') {
			const issuer = clampToken(params.issuerDomain);
			if (!issuers.has(issuer)) {
				if (issuers.size >= MAX_CAA_ISSUERS) issuersTruncated = true;
				else issuers.add(issuer);
			}
		}
	}

	if (accountUriCount === 0 && validationMethods.size === 0) return [];

	const methodList = [...validationMethods];
	const issuerList = [...issuers];

	const clauses: string[] = [];
	if (accountUriCount > 0) {
		clauses.push(
			`issuance is pinned to ${accountUriCount === 1 ? 'a specific ACME account' : `${accountUriCount} specific ACME accounts`}`,
		);
	}
	if (methodList.length > 0) {
		clauses.push(
			`the permitted validation method${methodList.length === 1 && !validationMethodsTruncated ? ' is' : 's are'} restricted to ${methodList.join(
				', ',
			)}${validationMethodsTruncated ? ` (list truncated — these are the first ${MAX_CAA_VALIDATION_METHODS} of a longer published list)` : ''}`,
		);
	}

	const issuerPrefix =
		issuerList.length > 0
			? ` for ${issuerList.join(', ')}${
					issuersTruncated ? ` (issuer list truncated — these are the first ${MAX_CAA_ISSUERS} of a longer published list)` : ''
				}`
			: '';

	// PROSE HAZARD — do not copy-edit this sentence back toward the words
	// "required", "missing", "not found", or a "no <…> record" phrasing.
	// `scoreIndicatesMissingControl` (scoring/model.ts) runs MISSING_CONTROL_REGEX
	// over BOTH the title and the detail, and a match at `high`/`critical` severity
	// ZEROES the whole `caa` category rather than deducting from it. This finding is
	// `info`, so today the match would be inert — but the earlier wording ("CAs are
	// only *required* to honour these parameters from 2027-03-15") did match, which
	// made a future severity bump a silent category wipe. The identical landmine is
	// commented at the "No CAA records" emission site in check-caa.ts. Guarded by
	// the severity-promoted arm of caa-analysis.test.ts.
	const detail = `The CAA policy${issuerPrefix} carries RFC 8657 parameters: ${clauses.join(
		', and ',
	)}. This narrows the grant beyond "this CA may issue" — an attacker who could otherwise pass a different validation method, or use a different account at the same authorized CA, is excluded. CAs must honour these parameters from 2027-03-15; until then support is at each CA's discretion, so confirm it with yours.`;

	return [
		createFinding(
			'caa',
			'CAA restricts issuance beyond the CA (RFC 8657)',
			'info',
			detail.length > MAX_CAA_PARAMETER_DETAIL_LENGTH
				? `${detail.slice(0, MAX_CAA_PARAMETER_DETAIL_LENGTH - TRUNCATION_MARKER.length)}${TRUNCATION_MARKER}`
				: detail,
			{
				caaAccountBound: accountUriCount > 0,
				caaValidationMethodBound: methodList.length > 0,
				...(methodList.length > 0 ? { caaValidationMethods: methodList } : {}),
				// Truncation is reported, never implied by silence: a consumer reading the
				// method list must be able to tell a complete list from a clipped one.
				...(validationMethodsTruncated ? { caaValidationMethodsTruncated: true } : {}),
				...(issuersTruncated ? { caaIssuersTruncated: true } : {}),
			},
		),
	];
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
// RFC 8657 `accounturi=` / `validationmethods=` pinning IS evaluated here, as of
// 2026-08-20 — see `getCaaParameterBindingFindings`. This REVERSES the earlier
// dated exclusion, which read:
//
//   > FUTURE (dated): RFC 8657 `accounturi=` / `validationmethods=` pinning is
//   > deliberately NOT evaluated here. CAs are only required to "SHOULD" process
//   > those parameters until 2027-03-15, Let's Encrypt is the only CA with
//   > confirmed support, and RFC 8657 itself instructs domain owners not to
//   > assume the restrictions are effective absent a CA statement. Revisit after
//   > 2027-03-15, when the requirement becomes MUST and scoring it would reflect
//   > reality.
//
// What changed: CA processing of these parameters becomes MANDATORY on
// 2027-03-15. Publishing them is the action domain owners must take BEFORE that
// date for the binding to be in force when it starts being honoured, so a scanner
// that stays silent until the deadline reports the gap only once it is too late to
// have closed it in advance.
//
// The original reasoning is nonetheless still respected, and constrains HOW this
// is reported: because CA support is not yet universal, the parameters are
// surfaced as an `info` observation with penalty 0 and their ABSENCE emits nothing
// at all. Nothing here is scored. That keeps faith with RFC 8657's instruction not
// to assume the restrictions are effective absent a CA statement — we report what
// is published, and do not credit or penalize it. Revisit the SCORING question
// (not the parsing question) after 2027-03-15.

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
 * TTL at or below which a CAA RRset's TTL is not reportable: the BR reuse-window
 * floor itself, 8 hours. Deliberately IDENTICAL to
 * {@link CAA_BR_REUSE_WINDOW_FLOOR_SECONDS} — this is the principled threshold,
 * not a tuned one.
 *
 * The BR rule is `max(TTL, 8h)`. At or below 8h the FLOOR dominates and the TTL
 * contributes literally nothing to the staleness window, so there is nothing to
 * report. Strictly above 8h the TTL — not the floor — is what governs how long a
 * CA may keep issuing under a policy the owner has already withdrawn. That
 * crossover is the only non-arbitrary place to put the line.
 *
 * MEASURED BASIS (do not "fix" this back to a round number): an earlier revision
 * set this to 86400s (24h) with a hand-picked "buffer" rationale. A 1,000-domain
 * corpus scan on 2026-08-03 refuted it — across all 161 CAA-publishing domains,
 * 135 CAA RRsets were observed and the MAXIMUM TTL seen was 21600s (6 hours), so
 * the finding could not fire at all. At the 8h floor it will still fire close to
 * never on real corpora. That is CORRECT and expected: it is a property of
 * real-world CAA TTL practice (operators keep CAA TTLs short), not a dead
 * detector. Raising the number back up would only re-guarantee silence; lowering
 * it below the floor would report a TTL that provably widens nothing.
 */
export const CAA_TTL_STALENESS_THRESHOLD_SECONDS = CAA_BR_REUSE_WINDOW_FLOOR_SECONDS;

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
 * the TTL is at or under {@link CAA_TTL_STALENESS_THRESHOLD_SECONDS} — i.e. at or
 * under the 8-hour floor, where the floor dominates and the TTL widens nothing —
 * or when no TTL was observed. Fires only for a TTL STRICTLY above the floor.
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
