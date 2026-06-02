// SPDX-License-Identifier: BUSL-1.1

/**
 * Scoring-model version + config fingerprint, stamped into scan output for
 * reproducibility. A dated client report once became unreproducible in two days
 * because nothing in the output recorded which scoring policy produced it. These
 * two stamps fix that: `SCORING_MODEL_VERSION` pins the policy, and
 * `computeScoringConfigHash()` fingerprints any active `SCORING_CONFIG` override.
 *
 * Runtime-agnostic, Workers-safe (no Node APIs, no `@blackveil/dns-checks` import).
 */

/**
 * Semver for the **scoring policy** — deliberately distinct from the package /
 * server version (`SERVER_VERSION`), which tracks the deployed code, not the
 * scoring model.
 *
 * BUMP THIS whenever scoring policy changes in a way that alters scores or grades:
 * category weights, profile weights, grade thresholds, severity penalties, the
 * `passed`/missing-control rule, a severity reclassification (e.g. the DNSSEC
 * severity decouple — `critical`→`high` with the penalty preserved via
 * `penaltyOverride`), or a change to how the scoring **profile** is detected (the
 * detected profile selects the per-profile weight table via `getProfileWeights`).
 * Bumping it lets a report consumer detect that two scans of the same domain ran
 * under different scoring policies.
 *
 * History:
 * - 1.0.0 — baseline policy as of v3.7.0 (DNSSEC decouple, profile-aware auto scoring).
 * - 1.1.0 — profile detection now requires an active observed control (`controlPresent`)
 *   instead of bare `passed`/finding prose. Corrects `enterprise_mail` over-fire and
 *   sparse-domain misdetection; per-domain score impact is bounded (~±2 pts).
 */
export const SCORING_MODEL_VERSION = '1.1.0';

/** Marker returned for an unset / default (un-overridden) scoring config. */
const DEFAULT_CONFIG_MARKER = 'default';

/**
 * Recursively serialize a value with sorted object keys at every level, so that
 * two semantically-identical configs with different key ordering serialize
 * identically. `ScoringConfig` is nested (weights, profileWeights, thresholds,
 * grades, baselineFailureRates), so top-level-only sorting is insufficient.
 */
function stableStringify(value: unknown): string {
	if (value === null || typeof value !== 'object') {
		return JSON.stringify(value) ?? 'null';
	}
	if (Array.isArray(value)) {
		return `[${value.map((v) => stableStringify(v)).join(',')}]`;
	}
	const entries = Object.keys(value as Record<string, unknown>)
		.sort()
		.map((key) => `${JSON.stringify(key)}:${stableStringify((value as Record<string, unknown>)[key])}`);
	return `{${entries.join(',')}}`;
}

/** FNV-1a 32-bit hash over a string → short lowercase hex. Standalone (no side effects). */
function fnv1a(input: string): string {
	let hash = 0x811c9dc5;
	for (let i = 0; i < input.length; i += 1) {
		hash ^= input.charCodeAt(i);
		hash = Math.imul(hash, 0x01000193);
	}
	return (hash >>> 0).toString(16);
}

/**
 * Deterministic short hex fingerprint of the **effective** scoring config.
 *
 * Hash the parsed/merged config object (not the raw env string), so that an
 * equivalent override with different whitespace or key order yields the same
 * fingerprint, and even a partial override produces a distinct full-config hash.
 * An unset / `null` / `undefined` config returns the fixed `'default'` marker —
 * the only fallback, used by un-threaded or test callers. Note the production
 * scan paths always pass a fully-populated effective config (even with no
 * `SCORING_CONFIG` override, `parseScoringConfigCached(undefined)` yields the
 * full default config), so they emit a hex hash, never `'default'`.
 */
export function computeScoringConfigHash(config?: unknown): string {
	if (config === undefined || config === null) return DEFAULT_CONFIG_MARKER;
	return fnv1a(stableStringify(config));
}
