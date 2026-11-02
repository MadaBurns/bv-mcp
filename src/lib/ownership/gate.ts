// SPDX-License-Identifier: BUSL-1.1

/** Ownership attribution: confidence, severity cap and non-owned gate finding. Split verbatim from `../ownership-attribution` (SQ-539). */

import type { CheckCategory, Finding, Severity } from '@blackveil/dns-checks/scoring';
import { createFinding } from '@blackveil/dns-checks/scoring';
import { MIN_ATTRIBUTION_LABEL_LENGTH, type OwnershipAssessment, type OwnershipVerdict } from './types';

/** {@link attributionConfidence} return type — deliberately not a boolean; see its JSDoc for why. */
export type AttributionConfidence = 'corroborated' | 'single_signal' | 'uncorroborated';

/**
 * D4 WORDING/CONFIDENCE classifier: does a non-owned candidate's brand-label
 * match meet the bar to be worded with full confidence in a report, versus
 * hedged/neutral wording? THIS FUNCTION MUST NEVER BE CONSULTED FOR
 * SEVERITY — that is `capAttributionSeverity()`'s job, and it takes
 * `verdict` alone. (Renamed from `passesAttributionGuard()` in fix round 1:
 * the original boolean-returning name/shape invited exactly the misuse this
 * rename and the `'corroborated' | 'uncorroborated'` return type resist —
 * see F3 in the fix-round report.)
 *
 * `owned_by_seed` is always `'corroborated'` — it is the strongest available
 * corroborating brand signal by construction. Any other verdict needs
 * EITHER a brand label at least `MIN_ATTRIBUTION_LABEL_LENGTH` characters
 * long, OR an explicit corroborating signal supplied by the caller
 * (MX/SPF overlap with the primary domain is the one wired in this slice —
 * cert-SAN is fetched by `discover_brand_domains` but is deliberately not an
 * input to this function (common cert buyer is not common owner, #1188); page-content
 * corroboration is not wired in, since neither tool fetches it today). Below the threshold with no corroboration, a short
 * brand label (e.g. `bnz`, 3 characters) collides with too much unrelated
 * global DNS for a bare label match to mean anything on its own — see spec
 * §5 D4. This is a WORDING signal only: whatever it returns, the finding is
 * still emitted, at the severity `capAttributionSeverity()` computed.
 *
 * #974 — `'corroborated'` means a second, independent signal actually agrees
 * (the caller's `corroborated` flag), not merely that the label is long. A
 * non-owned verdict whose only support is the verdict's own signal (e.g. NS
 * non-overlap) with a long-enough label is `'single_signal'`: it used to read
 * `'corroborated'`, over-claiming a one-signal `third_party`. Consumers that
 * gate on `!== 'uncorroborated'` (the #863 rollup) treat both the same.
 */
export function attributionConfidence(verdict: OwnershipVerdict, brandLabel: string, corroborated: boolean): AttributionConfidence {
	if (verdict === 'owned_by_seed' || corroborated) return 'corroborated';
	return brandLabel.length >= MIN_ATTRIBUTION_LABEL_LENGTH ? 'single_signal' : 'uncorroborated';
}

/**
 * THE single exported severity-decision surface (fix-round F1/F3). Every
 * non-owned candidate is capped at `'info'` — full stop, regardless of
 * brand-label length or corroboration. Those factors govern report WORDING
 * only, via `attributionConfidence()` above; they must never move the
 * severity ceiling. `owned_by_seed` is the only verdict exempt.
 *
 * DEMOTE, NEVER DELETE: this type has no falsy / null / undefined member,
 * so there is no value a caller could mistake for "omit this finding" —
 * every return is a concrete instruction to either leave the computed
 * severity alone (`'unbounded'`) or clamp it (`'info'`). The finding itself
 * is ALWAYS emitted by the caller; only its severity and wording change.
 *
 * Per the load-bearing safety property (controller amendment 2), `third_party`,
 * `unattributed` and `unmeasured` are capped identically — only `owned_by_seed`
 * is ever exempt.
 */
export function capAttributionSeverity(verdict: OwnershipVerdict): Severity | 'unbounded' {
	return verdict === 'owned_by_seed' ? 'unbounded' : 'info';
}

/**
 * Metadata shape every ownership-gated finding carries, owned or not.
 * Extracted (fix round 2, F1) after `check-lookalikes.ts` and
 * `check-shadow-domains.ts` each hand-built this same four-field object and
 * drifted apart within a single slice — see {@link buildNonOwnedGateFinding}.
 *
 * SQ-36 — `ownershipStrength` / `ownershipSignals` travel here too. They used to
 * appear ONLY on `buildOwnedBySeedFinding()` (`src/tools/lookalike-findings.ts`),
 * so a NON-owned finding published a verdict with no machine-readable trace of
 * WHICH arm reached it: a consumer auditing `third_party` on anz.co.nz saw an
 * absent signal list and could not tell "evaluated, every arm declined" from
 * "never evaluated". The arrays are the same ones `classifyOwnership()` already
 * returned — this surfaces them, it does not change a verdict, a signal or a
 * severity (`capAttributionSeverity()` still keys on `verdict` ALONE).
 */
export function buildOwnershipGateMetadata(
	finding: Finding,
	ownership: OwnershipAssessment,
	confidence: AttributionConfidence,
): Record<string, unknown> {
	return {
		...finding.metadata,
		ownershipVerdict: ownership.verdict,
		ownershipRationale: ownership.rationale,
		ownershipStrength: ownership.strength,
		ownershipSignals: ownership.signals,
		attributionConfidence: confidence,
		severityCappedBy: 'ownership_attribution',
	};
}

/**
 * Per-tool knobs for {@link buildNonOwnedGateFinding}. Everything ELSE about
 * the neutral non-owned rewrite — the title template, the hedge sentence,
 * the metadata shape — is shared and must stay byte-identical across
 * callers; these three fields are the only legitimate axis of variation.
 */
export interface NonOwnedGateOptions {
	/** Check category the rewritten finding belongs to (e.g. `'lookalikes'`, `'shadow_domains'`). */
	category: CheckCategory;
	/** `finding.metadata` key that carries this finding's own domain/variant string. */
	domainMetadataKey: string;
	/**
	 * Noun phrase describing what's being reported on (e.g. `'DNS/mail
	 * posture'`). Callers MUST pass the same value so the hedge sentence
	 * reads identically regardless of which tool emitted it — see F1
	 * (2026-07-27 fix round 2): `check-lookalikes.ts` and
	 * `check-shadow-domains.ts` had already drifted to `'DNS/mail posture'`
	 * vs `'mail posture'` within a single slice before this was noticed.
	 */
	postureNoun: string;
}

/**
 * Build the shared neutral, severity-capped finding for a NON-OWNED
 * (`third_party`/`unattributed`) candidate whose raw calibrated severity was
 * ABOVE `info`. THE single place that sentence and its metadata shape are
 * assembled — `check-lookalikes.ts` and `check-shadow-domains.ts` each used
 * to hand-roll their own copy of this text and had already drifted apart
 * (F1, fix round 2): `check-lookalikes.ts` said "Its DNS/mail posture" and
 * never quoted the brand label, `check-shadow-domains.ts` said "Its mail
 * posture" and quoted `"${brand}"`. Both tools now call this function with
 * the same `postureNoun`, so they emit byte-identical wording for the same
 * verdict — verified by `test/ownership-attribution.spec.ts`'s cross-tool
 * parity test.
 *
 * Callers are responsible for the `ceiling === 'unbounded'` passthrough (an
 * `owned_by_seed` finding is returned unchanged, never routed here) and, for
 * tools whose raw finding CAN be `'info'`-severity already (unlike
 * `check-lookalikes.ts`, where `calibrateLookalikeSeverity()` never returns
 * `'info'`), for their own local info-severity branch — see
 * `check-shadow-domains.ts`'s `NEUTRAL_INFO_TITLES` handling, which stays
 * tool-local by design (only the shared sentence and metadata shape moved
 * here, per the fix-round instruction).
 */
export function buildNonOwnedGateFinding(
	finding: Finding,
	ownership: OwnershipAssessment,
	brand: string,
	corroborated: boolean,
	ceiling: Severity,
	options: NonOwnedGateOptions,
): Finding {
	const confidence = attributionConfidence(ownership.verdict, brand, corroborated);
	const domainValue = finding.metadata?.[options.domainMetadataKey];
	const domain = typeof domainValue === 'string' ? domainValue : 'This domain';
	const metadata = buildOwnershipGateMetadata(finding, ownership, confidence);

	const relation =
		ownership.verdict === 'unmeasured'
			? 'could not be compared against the scanned organisation in this run — the lookups feeding the ownership comparison did not complete'
			: 'could not be attributed to the scanned organisation';
	const hedge =
		confidence === 'uncorroborated'
			? ` The shared label is under ${MIN_ATTRIBUTION_LABEL_LENGTH} characters and nothing else corroborates a link, so the name similarity alone means little.`
			: '';
	// #832: an `unmeasured` verdict must not be TITLED "Unrelated domain" — that
	// is the very third-party claim the degraded comparison failed to earn.
	// #1291: neither non-owned verdict verifies a different registrant.
	// Distinct nameservers establish infrastructure, not organisational identity.
	const title =
		ownership.verdict === 'unmeasured'
			? `Confusable label, ownership unmeasured this run: ${domain}`
			: `Confusable label, ownership not established: ${domain}`;
	return createFinding(
		options.category,
		title,
		ceiling,
		`${domain} shares the "${brand}" label with the scanned domain but ${relation}. ${ownership.rationale} Its ${options.postureNoun} is reported for awareness only: no action by the scanned organisation is implied, and this finding asserts no control over ${domain}.${hedge}`,
		metadata,
	);
}
