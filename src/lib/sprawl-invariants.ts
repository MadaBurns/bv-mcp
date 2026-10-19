// SPDX-License-Identifier: BUSL-1.1

/**
 * Runtime-agnostic invariants for Shadow IT (a.k.a. registrar-sprawl) items
 * emitted into `reports/*-discovery-report.json#registrarSprawl[]`.
 *
 * A sprawl item is the user-visible claim "this domain is owned by the
 * brand but registered at an off-primary registrar" — the highest-value output
 * of `brand_audit_single`. The classification pipeline assembles each item from
 * the candidate finding's `metadata` + RDAP/WHOIS registrar enrichment. There
 * is no schema-level enforcement of *quality* between that emission and the
 * sidecar serializer — a regression in any of the upstream stages (classifier
 * threshold change, registrar lookup degradation, signal counter bug) could
 * silently re-pollute Shadow IT with low-evidence claims.
 *
 * These invariants codify the *minimum* quality bar that historic fixtures
 * (54 items across 17 sidecars in `reports/`) already satisfy. The actual
 * historic minimums are stricter (e.g. min combined confidence 0.85, all
 * registrar sources `whois`/`rdap`); the floor enforced here intentionally
 * matches the bar surfaced in the task spec (combinedConfidence >= 0.5) so the
 * validator catches regressions without retro-condemning fixtures that drift
 * within the documented tolerance.
 *
 * Two surfaces:
 *   - `validateSprawlItem(item)` — non-throwing, returns a discriminated
 *     `{ ok: true } | { ok: false; reason: string }`. Use this on the pipeline
 *     hot path so failures can be downgraded to `indeterminate / manual_review`
 *     instead of crashing the audit.
 *   - `assertSprawlInvariants(item)` — throws on the first failed invariant.
 *     Use this in tests and one-off audits where loud failure is the desired
 *     contract.
 */

/**
 * Minimum-quality shape a sprawl item must satisfy. Matches the subset of
 * `DiscoveryReportCandidate` (in `test/helpers/discovery-report-model.ts`) that
 * any v4 sidecar carries — narrower than that interface so the validator stays
 * usable on partial / candidate-stage objects (e.g. pre-serialization in the
 * pipeline).
 */
export interface SprawlItemLike {
	domain?: unknown;
	bucket?: unknown;
	relationshipType?: unknown;
	evidence?: unknown;
	registrar?: unknown;
	registrarSource?: unknown;
	signals?: unknown;
	combinedConfidence?: unknown;
	reasons?: unknown;
}

export type SprawlValidationResult = { ok: true } | { ok: false; reason: string };

/**
 * Lower-bound combined confidence for a sprawl-quality claim. Historic fixtures
 * report a min of 0.85; the floor lives at 0.5 to leave room for future
 * classifier-threshold tuning without forcing fixture regen on every nudge.
 */
export const MIN_COMBINED_CONFIDENCE = 0.5;

/** Sprawl claims must back the registrar-sprawl story with at least N signals. */
export const MIN_SIGNALS = 2;

/**
 * Registrar-source markers indicating enrichment did not produce a usable
 * registrar identity. `lookup_failed` is the explicit failure marker; `unknown`
 * is the safe default when no source ran. Both disqualify the candidate from
 * the "owned at a *named* off-primary registrar" story.
 */
const UNUSABLE_REGISTRAR_SOURCES = new Set(['unknown', 'lookup_failed']);

function isNonEmptyString(value: unknown): value is string {
	return typeof value === 'string' && value.length > 0;
}

function isStringArray(value: unknown): value is string[] {
	return Array.isArray(value) && value.every((v) => typeof v === 'string');
}

/** One invariant: returns the failure reason, or null when the item satisfies it. */
type SprawlCheck = (item: SprawlItemLike) => string | null;

const checkDomain: SprawlCheck = (item) => (isNonEmptyString(item.domain) ? null : 'missing or empty `domain`');

const checkBucket: SprawlCheck = (item) =>
	item.bucket === 'shadowIt' ? null : `bucket must be 'shadowIt' (got ${JSON.stringify(item.bucket)})`;

const checkRelationshipType: SprawlCheck = (item) =>
	item.relationshipType === 'owned_off_primary_registrar'
		? null
		: `relationshipType must be 'owned_off_primary_registrar' (got ${JSON.stringify(item.relationshipType)})`;

const checkRegistrar: SprawlCheck = (item) =>
	isNonEmptyString(item.registrar) && item.registrar !== 'Unknown'
		? null
		: `registrar must be a named non-empty string (got ${JSON.stringify(item.registrar)})`;

const checkRegistrarSource: SprawlCheck = (item) =>
	isNonEmptyString(item.registrarSource) && !UNUSABLE_REGISTRAR_SOURCES.has(item.registrarSource)
		? null
		: `registrarSource must be a resolved source (got ${JSON.stringify(item.registrarSource)})`;

const checkEvidence: SprawlCheck = (item) => (isNonEmptyString(item.evidence) ? null : 'evidence must be a non-empty string');

function describeSignals(signals: unknown): string {
	return Array.isArray(signals) ? `length ${signals.length}` : typeof signals;
}

const checkSignals: SprawlCheck = (item) =>
	isStringArray(item.signals) && item.signals.length >= MIN_SIGNALS
		? null
		: `signals must be a string[] with length >= ${MIN_SIGNALS} (got ${describeSignals(item.signals)})`;

const checkConfidenceIsFinite: SprawlCheck = (item) =>
	typeof item.combinedConfidence === 'number' && Number.isFinite(item.combinedConfidence)
		? null
		: `combinedConfidence must be a finite number (got ${JSON.stringify(item.combinedConfidence)})`;

// Runs after checkConfidenceIsFinite, so combinedConfidence is a finite number here.
const checkConfidenceFloor: SprawlCheck = (item) =>
	(item.combinedConfidence as number) >= MIN_COMBINED_CONFIDENCE
		? null
		: `combinedConfidence must be >= ${MIN_COMBINED_CONFIDENCE} (got ${String(item.combinedConfidence)})`;

const checkReasons: SprawlCheck = (item) =>
	isStringArray(item.reasons) && item.reasons.length >= 1 ? null : 'reasons must be a non-empty string[]';

/** Invariants in evaluation order; the first failure is the reported reason. */
const SPRAWL_CHECKS: readonly SprawlCheck[] = [
	checkDomain,
	checkBucket,
	checkRelationshipType,
	checkRegistrar,
	checkRegistrarSource,
	checkEvidence,
	checkSignals,
	checkConfidenceIsFinite,
	checkConfidenceFloor,
	checkReasons,
];

/**
 * Non-throwing validator. Returns the first failed invariant so callers can
 * surface a useful reason in their downgrade path / log line.
 */
export function validateSprawlItem(item: SprawlItemLike): SprawlValidationResult {
	for (const check of SPRAWL_CHECKS) {
		const reason = check(item);
		if (reason !== null) return { ok: false, reason };
	}
	return { ok: true };
}

/**
 * Throwing wrapper for tests and one-off audits. Error message is prefixed so
 * a CI failure points straight at the invariant family without grepping.
 */
export function assertSprawlInvariants(item: SprawlItemLike): void {
	const result = validateSprawlItem(item);
	if (!result.ok) {
		const domain = typeof item.domain === 'string' ? item.domain : '<unknown>';
		throw new Error(`sprawl invariant violation for ${domain}: ${result.reason}`);
	}
}
