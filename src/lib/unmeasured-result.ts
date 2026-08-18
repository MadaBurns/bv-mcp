// SPDX-License-Identifier: BUSL-1.1

/**
 * Vocabulary and predicates for results that report NO MEASUREMENT.
 *
 * A `CheckResult` derives `passed`/`score` from finding severities
 * (`buildCheckResult`), so a lane that was never measured — whose only finding is
 * an `info` "unavailable" note — comes out as `score: 100, passed: true`. For a
 * security scanner that is the worst possible default: a consumer keying on the
 * scalars records "no findings" where nothing was observed (#695).
 *
 * This module is the SSOT for the marker vocabulary those builders already stamp
 * into finding metadata, so the honesty rule is applied in ONE place rather than
 * re-derived per tool. Two distinct classes, deliberately kept apart:
 *
 * - **Unmeasured** (`unprovisioned`, `upstreamUnavailable`) — nothing was read.
 *   The deployment lacks the capability, or the upstream did not answer. These get
 *   `checkStatus: 'error'`, which is what the formatter and the scoring engine
 *   already gate on to withhold a verdict.
 *
 * - **Access refusal** (`tierDenied`, `notOwned`) — the caller was refused. Also
 *   nothing measured, but the cause is authorization, not availability. These
 *   surface as a FAILED tool call (`isError`), matching what a free caller already
 *   receives from a paid-gated tool (HTTP 403 / -32003) instead of a green
 *   security verdict.
 *
 * ⚠️ Refusals deliberately do NOT get `checkStatus: 'error'`. That is the
 * documented RETRYABLE class — `scan_domain`'s transient-zero retry keys off it —
 * and an agentic caller that retries a permanent tier refusal will loop.
 *
 * ⚠️ Every marker below belongs to a `scanIncluded: false` tool. Stamping one onto
 * a SCORED check would make the scoring engine exclude that category as a
 * transient failure and re-grade every customer scanning that domain — a scoring
 * change, not a correctness fix. `test/audits/unmeasured-marker-scope.audit.test.ts`
 * fails the build if a marker reaches a scanned category, so the halt condition is
 * enforced rather than merely documented.
 */

import type { CheckResult, Finding } from './scoring';

/** Markers meaning "nothing was read" — availability, not authorization. */
export const UNMEASURED_MARKERS = ['unprovisioned', 'upstreamUnavailable'] as const;

/** Markers meaning "the caller was refused" — authorization, not availability. */
export const ACCESS_REFUSAL_MARKERS = ['tierDenied', 'notOwned'] as const;

function hasMarker(findings: readonly Finding[], markers: readonly string[]): boolean {
	return findings.some((f) => markers.some((m) => f.metadata?.[m] === true));
}

/** True when the result reports that nothing was measured (capability absent, or upstream silent). */
export function isUnmeasuredResult(result: Pick<CheckResult, 'findings'>): boolean {
	return hasMarker(result.findings ?? [], UNMEASURED_MARKERS);
}

/** True when the result reports an authorization refusal rather than a measurement. */
export function isAccessRefusal(result: Pick<CheckResult, 'findings'>): boolean {
	return hasMarker(result.findings ?? [], ACCESS_REFUSAL_MARKERS);
}

/**
 * Stamp `checkStatus: 'error'` onto a result that measured nothing, so every
 * downstream consumer that already distinguishes completed from non-completed
 * checks (the formatter's verdict abstention, the scoring engine's transient-failure
 * exclusion, `computeScanEvidence`) sees the truth without needing to know this
 * module's vocabulary.
 *
 * `score`/`passed` are deliberately LEFT ALONE. Zeroing them here would rank
 * "binding absent" as worse than a measured finding — these tool families emit
 * `info` on every branch INCLUDING success, so the surviving 100s would gain false
 * credibility from the contrast. The verdict is withheld, not inverted.
 *
 * Returns the input unchanged when it carries no marker, or already has a status.
 */
export function markUnmeasured(result: CheckResult): CheckResult {
	if (result.checkStatus || !isUnmeasuredResult(result)) return result;
	return { ...result, checkStatus: 'error' };
}

/**
 * Remove the reserved marker keys from an OPAQUE UPSTREAM payload before it is spread into
 * finding metadata.
 *
 * The markers above are a control channel: `markUnmeasured` and `isAccessRefusal` read them to
 * decide whether a result reports a measurement at all. Several recon tools spread the upstream
 * response verbatim into metadata (`{ ...s }`), and `sanitizeFindingMetadata` preserves booleans
 * — so without this, a compromised or simply buggy upstream returning `{"unprovisioned":true}`
 * alongside real data would flip a genuine result to "not measured".
 *
 * The failure is not dramatic (the findings still render; a verdict is withheld rather than
 * fabricated), but a control channel that an upstream can write to is not a control channel.
 * Reserved keys are OURS to set, at the builders, from local knowledge.
 */
export function stripReservedMarkers<T extends Record<string, unknown>>(upstream: T): T {
	const reserved = new Set<string>([...UNMEASURED_MARKERS, ...ACCESS_REFUSAL_MARKERS]);
	if (!Object.keys(upstream).some((k) => reserved.has(k))) return upstream;
	return Object.fromEntries(Object.entries(upstream).filter(([k]) => !reserved.has(k))) as T;
}
