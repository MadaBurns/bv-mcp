// SPDX-License-Identifier: BUSL-1.1

import type { CheckCategory, CheckResult, CheckStatus, Finding, Severity } from '../types';
import { CATEGORY_DISPLAY_WEIGHTS, CATEGORY_PENALTY_CAPS, SEVERITY_PENALTIES } from '../types';
import { sanitizeFindingMetadata, sanitizeStructuredString } from './metadata-sanitize';

export type { CheckCategory, CheckResult, CheckStatus, Finding, Severity };
export { CATEGORY_DISPLAY_WEIGHTS, CATEGORY_PENALTY_CAPS, SEVERITY_PENALTIES };

export type { CategoryTier } from '../types';
export { CATEGORY_TIERS } from '../types';
export type { ScanScore } from '../types';

/** Display/UI weight distribution for categories — re-exported from types for convenience. */

/** Severity penalty multipliers — re-exported from types for convenience. */

export type FindingConfidence = 'deterministic' | 'heuristic' | 'verified';

function isExplicitConfidence(value: unknown): value is FindingConfidence {
	return value === 'deterministic' || value === 'heuristic' || value === 'verified';
}

/**
 * Infer how strongly a finding can be trusted based on available evidence.
 * - verified: explicit proof (currently only supported on takeover checks)
 * - heuristic: signal-based or partial-evidence checks
 * - deterministic: direct record/protocol validation
 */
export function inferFindingConfidence(finding: Finding): FindingConfidence {
	const declared = finding.metadata?.confidence;
	if (isExplicitConfidence(declared)) return declared;

	if (finding.category === 'subdomain_takeover') {
		const status = finding.metadata?.verificationStatus;
		if (status === 'verified') return 'verified';
		return 'heuristic';
	}

	const text = `${finding.title} ${finding.detail}`.toLowerCase();
	if (
		text.includes('common selectors') ||
		text.includes('among tested selectors') ||
		text.includes('inferred') ||
		text.includes('manual review') ||
		text.includes('possible') ||
		text.includes('potential') ||
		text.includes('could indicate')
	) {
		return 'heuristic';
	}

	return 'deterministic';
}

function withConfidenceMetadata(finding: Finding): Finding {
	const confidence = inferFindingConfidence(finding);
	return {
		...finding,
		metadata: {
			...(finding.metadata ?? {}),
			confidence,
		},
	};
}

/**
 * Compute the score for a single check category based on its findings.
 * Starts at 100 and deducts points based on finding severities.
 *
 * When `category` is supplied and present in `CATEGORY_PENALTY_CAPS`, the
 * total penalty is capped before clamping — this preserves discriminative
 * power between "many same-class findings" and "single catastrophic finding"
 * in categories like `subdomain_takeover` where a single upstream resource
 * deletion can produce many same-class findings (e.g., one AWS NLB deletion
 * orphaning 9 subdomains). Categories without a cap retain the legacy
 * uncapped-then-clamped behavior.
 *
 * Backwards-compatible: omitting `category` keeps the original behavior.
 */
export function computeCategoryScore(findings: Finding[], category?: CheckCategory): number {
	let penalty = 0;
	for (const finding of findings) {
		// `penaltyOverride` decouples the displayed severity from the score penalty:
		// a finding can carry a triage-facing severity label (e.g. DNSSEC `high`)
		// while applying a different, fixed deduction. Honored only when numeric;
		// anything else falls back to the severity default.
		const override = finding.metadata?.penaltyOverride;
		penalty += typeof override === 'number' ? override : SEVERITY_PENALTIES[finding.severity];
	}
	if (category !== undefined) {
		const cap = CATEGORY_PENALTY_CAPS[category];
		if (cap !== undefined && penalty > cap) {
			penalty = cap;
		}
	}
	return Math.max(0, Math.min(100, 100 - penalty));
}

/**
 * Regex for detecting missing control patterns in finding text.
 * The "no … record" gap is a bounded `[^\r\n]{1,64}` (not `.+\s+`): the old
 * `.+\s+record` had two overlapping unbounded quantifiers, giving polynomial
 * backtracking on a long no-"record" string (CWE-1333 / js/polynomial-redos).
 * The bound is well above any real finding phrase ("No SPF record found").
 */
const MISSING_CONTROL_REGEX = /(no\s+[^\r\n]{1,64}\srecord|missing|required|not\s+found)/i;

/**
 * Metadata key a call site can use to DECLARE substrings of its own prose that are
 * subject data rather than authored assertion (see {@link redactSubjectData}). Use it
 * whenever a `high`/`critical` finding interpolates a value that is not structurally
 * recognisable as a host/URL/email — a raw record token, a DKIM selector, an upstream
 * error string. Values are matched case-insensitively as plain substrings.
 */
export const SUBJECT_TERMS_METADATA_KEY = 'subjectTerms';

/**
 * Redaction placeholder. Deliberately a NON-whitespace, non-letter character: replacing
 * a token with the empty string could splice two halves of the prose together and
 * MANUFACTURE a match ("not <host> found" → "not  found"). `-` blocks that join while
 * still satisfying the `no\s+…\srecord` gap, so authored prose keeps matching exactly
 * as it did before.
 */
const REDACTED = '-';

/** A URL — wholly runtime-derived (policy URLs, BIMI logo URLs). Leading punctuation already trimmed. */
const URL_TOKEN = /^(?:https?|ftp):\/\//i;

/**
 * A contact address echoed from a record (SOA RNAME, DMARC `rua=` / `ruf=`) — local part,
 * an at-sign, then a dotted host. Written in prose rather than as a literal example: the
 * repo-safety scanner's `real-email-address` rule matches an address-shaped literal even in
 * a comment, and blocking a commit over a doc example is not worth the illustration.
 */
const EMAIL_TOKEN = /^[^\s@]{1,64}@[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)*\.[a-z]{2,63}$/i;

/**
 * A DNS name: two or more labels, the last alphabetic (a TLD). Leading `_` is allowed so
 * `_dmarc.example.com` / `_mta-sts.example.com` are recognised. Anchored and label-bounded
 * — every quantifier is capped and the `.` separators make the label partition unique, so
 * there is no ambiguity for a backtracking engine to explore (CWE-1333, same care as
 * MISSING_CONTROL_REGEX above).
 */
const HOST_TOKEN = /^_?[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?(?:\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)*\.[a-z]{2,63}$/i;

/** Longest DNS name (RFC 1035 §2.3.4) — anything longer is prose, not a name. */
const MAX_NAME_LENGTH = 255;

const LEADING_PUNCT = /^[^\p{L}\p{N}_]+/u;

/** Single word character. Used for a LINEAR trailing-run scan — see below. */
const WORD_CHAR = /[\p{L}\p{N}_]/u;

/**
 * Length of the token's trailing non-word run.
 *
 * Semantically identical to `/[^\p{L}\p{N}_]+$/u`, but linear instead of quadratic.
 * That regex is unanchored on the LEFT, so on a long non-word run that does not reach the
 * end of the string the engine retries from every start position and backtracks the whole
 * run each time: O(N²). This matters because the string is attacker-controlled and
 * UNBOUNDED — `sanitizeDnsData` explicitly does not truncate `detail`, and checks such as
 * `check-svcb-https.ts` interpolate a raw DNS record value into it, so a scanned domain
 * picks both the length and the bytes. Measured on `AAAA` + N×`/` + `A`, one call:
 * 8KB→37ms, 16KB→143ms, 32KB→560ms, 64KB→2,215ms of Worker CPU.
 *
 * Scanning backwards costs O(trailing run) with no backtracking. Surrogate pairs are
 * stepped as single code points so astral letters still terminate the run, matching the
 * `u`-flag regex this replaces.
 */
function trailingPunctuationLength(value: string): number {
	let end = value.length;
	while (end > 0) {
		let start = end - 1;
		const unit = value.charCodeAt(start);
		if (unit >= 0xdc00 && unit <= 0xdfff && end >= 2) {
			const high = value.charCodeAt(end - 2);
			if (high >= 0xd800 && high <= 0xdbff) start = end - 2;
		}
		if (WORD_CHAR.test(value.slice(start, end))) break;
		end = start;
	}
	return value.length - end;
}

function escapeForRegex(value: string): string {
	return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Project a finding's prose onto the text its AUTHOR wrote, with the scan SUBJECT's own
 * data removed.
 *
 * Why this exists: `MISSING_CONTROL_REGEX` is an inference about what the check author
 * asserted ("this control is absent"). ~28 `high`/`critical` emission sites interpolate
 * runtime values into that same prose — the scanned domain, its nameserver and MX
 * hostnames, the policy URLs derived from it, tokens echoed out of its own records. Those
 * values are DATA ABOUT the subject, never an assertion about a control, so they must be
 * unable to arm (or disarm) the gate.
 *
 * Measured in production 2026-08-20: `github.com` and `missingkids.org` produced
 * byte-identical unsigned-zone DNSSEC findings and scored 60/passed vs 0/failed, purely
 * because `${target}` supplied the substring "missing" to a sentence whose static text
 * (`check-dnssec.ts:139-142`) deliberately avoided every trigger word. Since `dnssec` is a
 * critical category in every profile, that also tripped the 64 critical-gap ceiling and
 * published a D grade for the National Center for Missing & Exploited Children.
 *
 * The projection is used ONLY for the missing-control decision. Nothing customer-visible
 * changes: titles, details and metadata are emitted verbatim.
 *
 * Redacted: declared {@link SUBJECT_TERMS_METADATA_KEY} substrings, URLs, email
 * addresses, and DNS-name-shaped tokens. NOT redacted: bare single-label runtime values
 * (a DKIM selector, an SPF mechanism keyword, an upstream error phrase) — those are
 * indistinguishable from prose and must be declared via `subjectTerms` instead.
 */
export function redactSubjectData(text: string, subjectTerms?: readonly string[]): string {
	let working = text;

	if (subjectTerms) {
		for (const term of subjectTerms) {
			if (typeof term !== 'string') continue;
			const trimmed = term.trim();
			// Too short to be subject data worth hiding, long enough to dismantle a trigger
			// word from the inside. No MISSING_CONTROL_REGEX trigger is shorter than 6
			// characters, so a 2-3 character term cannot be the thing being concealed — but
			// `p=no` would strip the `no` out of a `not found` in the same finding's prose and
			// silently DISARM a genuine zeroing (measured: "Record not found" → "Record -t
			// found", gate true → false). The risk is one-directional: `-` substitution means
			// redaction can never splice a new match into existence, only destroy one. 4 matches
			// the `core.length < 4` floor applied to host/email tokens below.
			if (trimmed.length < 4) continue;
			working = working.replace(new RegExp(escapeForRegex(trimmed), 'gi'), REDACTED);
		}
	}

	return working
		.split(/(\s+)/)
		.map((token) => {
			if (token.length === 0 || /^\s+$/.test(token)) return token;
			const lead = LEADING_PUNCT.exec(token)?.[0] ?? '';
			const rest = token.slice(lead.length);
			if (URL_TOKEN.test(rest)) return `${lead}${REDACTED}`;
			const trailLength = trailingPunctuationLength(rest);
			const trail = rest.slice(rest.length - trailLength);
			const core = rest.slice(0, rest.length - trailLength);
			if (core.length < 4 || core.length > MAX_NAME_LENGTH) return token;
			if (EMAIL_TOKEN.test(core) || HOST_TOKEN.test(core)) return `${lead}${REDACTED}${trail}`;
			return token;
		})
		.join('');
}

function declaredSubjectTerms(finding: Finding): readonly string[] | undefined {
	const declared = finding.metadata?.[SUBJECT_TERMS_METADATA_KEY];
	if (!Array.isArray(declared)) return undefined;
	return declared.filter((v): v is string => typeof v === 'string');
}

/**
 * Determine whether findings for a category indicate a fundamentally missing control.
 * Requires both a missing-control text pattern AND deterministic/verified confidence
 * to avoid false zeroing from heuristic checks (e.g., DKIM selector probing).
 *
 * The pattern is tested against a SUBJECT-DATA-FREE projection of the prose — see
 * {@link redactSubjectData}. The regex and its semantics for authored prose are unchanged.
 */
export function scoreIndicatesMissingControl(findings: Finding[]): boolean {
	return findings.some((f) => {
		// Order matters for COST, not just clarity. The two cheap structural gates run
		// first so the projection — which walks attacker-controlled, unbounded prose — is
		// only ever computed for a finding that could actually zero a category. Evaluating
		// it eagerly made an `info` finding pay the full redaction cost.
		if (f.severity !== 'critical' && f.severity !== 'high') return false;
		// inferFindingConfidence already performs the validated declared-then-infer read
		// (isExplicitConfidence, else inference). Re-reading metadata.confidence here with a
		// bare cast let an out-of-union declared value — garbage from an unvalidated cache
		// re-read, or a non-string — silently disarm zeroing instead of falling through to
		// inference like an undeclared finding does.
		const confidence = inferFindingConfidence(f);
		if (confidence !== 'deterministic' && confidence !== 'verified') return false;

		const terms = declaredSubjectTerms(f);
		return MISSING_CONTROL_REGEX.test(redactSubjectData(f.detail, terms)) || MISSING_CONTROL_REGEX.test(redactSubjectData(f.title, terms));
	});
}

/**
 * Canonical missing-control decision for a set of findings.
 *
 * A check author may declare the state structurally with
 * `metadata.missingControl: true`; legacy checks may still express it through
 * deterministic/verified prose interpreted by {@link scoreIndicatesMissingControl}.
 * Every scoring layer must use this predicate so category zeroing, the email
 * bonus and the critical-gap ceiling cannot disagree about the same evidence.
 * Measurement status is intentionally not accepted here: callers operating on
 * whole check results must gate this predicate with `isCheckMeasured`.
 */
export function findingsIndicateMissingControl(findings: Finding[]): boolean {
	return scoreIndicatesMissingControl(findings) || findings.some((f) => f.metadata?.missingControl === true);
}

/**
 * Build a CheckResult from a category and its findings.
 * A check fails (passed=false) if the score is below 50, if findings indicate
 * a fundamentally missing security control (e.g., no SPF/DMARC record), or if
 * any finding carries explicit `missingControl: true` metadata.
 *
 * `recordPresent` is purely observational ("was a record published at all") and is NEVER read by
 * the scoring path — it exists so consumers can answer "is this control configured?" without
 * misusing `controlPresent` (which conflates absent with inactive) or a score band. See
 * {@link CheckResult.recordPresent}.
 */
export function buildCheckResult(
	category: CheckCategory,
	findings: Finding[],
	controlPresent?: boolean,
	recordPresent?: boolean,
): CheckResult {
	const normalizedFindings = findings.map(withConfidenceMetadata);
	const score = computeCategoryScore(normalizedFindings, category);
	const hasMissingControl = findingsIndicateMissingControl(normalizedFindings);
	const passed = score >= 50 && !hasMissingControl;
	return {
		category,
		passed,
		score: hasMissingControl ? 0 : score,
		findings: normalizedFindings,
		// Only set when the caller provides a determination; left absent (undefined) otherwise so
		// consumers can distinguish "definitively absent" (false) from "not determined" (undefined).
		...(controlPresent === undefined ? {} : { controlPresent }),
		...(recordPresent === undefined ? {} : { recordPresent }),
	};
}

/**
 * Create a finding object with the given parameters.
 */
export function createFinding(
	category: CheckCategory,
	title: string,
	severity: Severity,
	detail: string,
	metadata?: Record<string, unknown>,
): Finding {
	// Sanitize detail with the shared structured-string sanitizer used by metadata,
	// so both LLM-facing channels stay in lockstep.
	const sanitized = sanitizeStructuredString(detail);
	// F7 (OWASP LLM01): `title` is the THIRD LLM-facing channel out of this function, and until
	// now the only unsanitized one -- despite production code interpolating fully
	// attacker-controlled DNS data into it. `checks/check-dkim.ts` builds
	// `Unknown DKIM key type: ${keyTypeMatch[1]}` from a `k=` capture on the scanned domain's raw
	// DKIM TXT record, so whoever controls a domain submitted for scanning controls that
	// substring verbatim. The title reaches an LLM through BOTH the prose report and the MCP
	// `structuredContent` findings array; sanitizing here covers both at once, rather than at one
	// emission site where the two channels can silently drift apart.
	const sanitizedTitle = sanitizeStructuredString(title);
	// F7 (OWASP LLM01): metadata reaches the LLM verbatim via the MCP
	// `structuredContent` channel, so sanitize attacker-influenceable STRING values
	// here at the chokepoint (control bytes, code-fence/markdown injection, over-long
	// strings) while preserving numeric/boolean/enum fields scoring & formatters rely
	// on. Generalizes the per-tool F7 opt-ins (`src/lib/sanitize-upstream.ts`).
	const sanitizedMetadata = sanitizeFindingMetadata(metadata);
	return {
		category,
		title: sanitizedTitle,
		severity,
		detail: sanitized,
		...(sanitizedMetadata ? { metadata: sanitizedMetadata } : {}),
	};
}
