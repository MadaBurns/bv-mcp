// SPDX-License-Identifier: BUSL-1.1

/**
 * Result and option types for the scan_domain orchestrator. Type-only module,
 * split out of scan-domain.ts (SQ-537); scan-domain.ts re-exports both.
 */

import type { CheckResult, DomainContext, ScanScore } from '../../lib/scoring';
import type { InteractionEffect } from '../../lib/category-interactions';
import type { MaturityStage } from './maturity-staging';
import type { ScanRuntimeOptions } from './post-processing';
import type { WebPostureSection } from './web-posture';

export interface ScanDomainResult {
	domain: string;
	score: ScanScore;
	checks: CheckResult[];
	maturity: MaturityStage;
	context: DomainContext;
	cached: boolean;
	timestamp: string;
	scoringNote: string | null;
	adaptiveWeightDeltas: Record<string, number> | null;
	/** Category interaction effects applied as post-scoring adjustments. Empty when no interactions triggered. */
	interactionEffects: InteractionEffect[];
	/**
	 * Tri-state resolution signal:
	 * - absent/`true` — domain resolves and was scored normally.
	 * - `false` — apex returned NXDOMAIN; the domain does not exist in DNS and was
	 *   not scored (no posture to assess).
	 * - `'broken'` — apex returned SERVFAIL; the zone exists but cannot be resolved
	 *   (DNSSEC-bogus or lame/broken delegation). Not scored — see
	 *   {@link buildDnsBrokenResult}.
	 * Aggregators should exclude `resolves === false` and `resolves === 'broken'`
	 * results rather than averaging an ungraded result into a population score.
	 */
	resolves?: boolean | 'broken';
	/**
	 * Fingerprint of the **effective** scoring config this result was produced
	 * under — `computeScoringConfigHash(runtimeOptions.scoringConfig)`.
	 *
	 * Stamped by `scanDomain` on every return path (including the non-resolving /
	 * DNS-broken short-circuits and the cached path, which carries the hash it was
	 * originally scored with) so that `buildStructuredScanResult` can report a
	 * TRUTHFUL `scoringConfigHash` without the caller having to thread it. Before
	 * this existed, any caller that did not pass an enrichment — every consumer of
	 * the exported `buildStructuredScanResult` from the npm package, and the
	 * batch error placeholders — stamped the literal `'default'` marker even while
	 * a live `SCORING_CONFIG` override was in force, i.e. the output claimed a
	 * reproducibility it could not back.
	 *
	 * Additive-optional: `undefined` only on hand-built results (tests) and on
	 * cache entries written before this field existed.
	 */
	scoringConfigHash?: string;
	/**
	 * NON-SCORING web posture section (US-16 T10): web content, CSP quality, HSTS preload, HTTP
	 * redirect chain, security.txt and certificate posture. Kept OUT of `checks`, so nothing here
	 * reaches `score`, the grade, the category scores, the finding counts or the evidence ratio.
	 *
	 * Present only when the caller passed `webPosture: true` (the scan_domain tool does; no other
	 * caller does) and `WEB_POSTURE_ENABLED` is not "false". A cache hit strips it for any other
	 * caller. Also absent on the non-resolving / DNS-broken short-circuits and on the
	 * `authoritative_dns_infra` profile. Cached with the result, so a cache hit replays the section
	 * attached with the score; `force_refresh` re-runs both. A check that had not finished 750 ms
	 * after the score was ready reads as not assessed (`notAssessedReason: 'deadline'`).
	 */
	webPosture?: WebPostureSection;
}

/** `scanDomain` options: the scan runtime options plus the scan_domain tool's web posture opt-in. */
export interface ScanDomainOptions extends ScanRuntimeOptions {
	/**
	 * Run the NON-SCORING web posture section (US-16). Default off: only the scan_domain tool
	 * handler sets it, because every other caller discards the section (SQ-487).
	 */
	webPosture?: boolean;
}
