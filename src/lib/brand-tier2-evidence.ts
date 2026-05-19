// SPDX-License-Identifier: BUSL-1.1

/**
 * Tier 2 evidence lookup for brand discovery.
 *
 * Calls the `BV_INTEL_GATEWAY` service-binding RPC method `getDomainEvidence`
 * (cross-Worker contract § 1.2) and maps the response into brand-discovery
 * tier observations:
 *
 *   - Tier 2 (`gsi_evidence`) — declared/witnessed evidence for the seed
 *     itself: in-corpus + has a `latestScan`. Confidence 0.9.
 *   - Tier 4 (`score_alert_critical_drop`) — derived risk signal: any
 *     `scoreAlerts` row whose `previousThreatLevel` was `secure|low|medium`
 *     and `newThreatLevel` is `critical|high` ("becoming-critical").
 *     Confidence 0.5.
 *
 * # Auth
 *
 * `BV_INTEL_GATEWAY` is a Cloudflare service-binding to a `WorkerEntrypoint`.
 * Auth is enforced at the binding level (only Workers explicitly bound in
 * `wrangler.jsonc` can invoke the RPC). There is no per-call `Authorization`
 * header to plumb — unlike the Tier 1 / Tier 3 fetch wrappers (T2/T3),
 * this wrapper does NOT accept a bearer-token parameter.
 *
 * # Failure modes
 *
 * | Producer outcome                | Wrapper return                              |
 * | ------------------------------- | ------------------------------------------- |
 * | `ok: true` + `latestScan`       | Tier 2 obs (+ Tier 4 per matching alert)    |
 * | `ok: true` + `latestScan: null` | empty obs, `status: 'ok'`                   |
 * | `ok: false` (any reason)        | empty obs, `status: 'skipped'`              |
 * | RPC throws / Zod parse fails    | empty obs, `status: 'degraded'`             |
 * | binding undefined (unprovisioned) | empty obs, `status: 'skipped'`            |
 *
 * The wrapper NEVER throws — failures are surfaced via `status` so the caller
 * (the discovery planner) can fall back to other tiers and continue.
 *
 * # Privacy
 *
 * No PII is logged. Domain values, threat levels, and any auth material MUST
 * NOT appear in console output.
 */

import {
	DomainEvidenceResponseSchema,
	type DomainEvidenceResponse,
	type DomainEvidenceScoreAlert,
} from '../schemas/cross-worker-domain-evidence';

/**
 * Minimal binding shape sufficient for tests and the real
 * `BV_INTEL_GATEWAY` service binding (`WorkerEntrypoint` RPC). The full type
 * comes from the binding declaration in `wrangler.jsonc` once T7 lands; we
 * intentionally avoid importing bv-web types here.
 */
export interface IntelGatewayBinding {
	getDomainEvidence(params: { domain: string; includeHistory?: boolean }): Promise<unknown>;
}

/** Tier 2 observation — declared evidence the seed exists in the GSI corpus. */
export interface Tier2EvidenceObservation {
	candidate: string;
	source: 'gsi_evidence';
	tier: 2;
	confidence: 0.9;
	threatLevel: string;
	capturedAt: number;
}

/** Tier 4 observation — derived risk signal from a becoming-critical alert. */
export interface Tier4ScoreAlertObservation {
	candidate: string;
	source: 'score_alert_critical_drop';
	tier: 4;
	confidence: 0.5;
	alertType: string;
	transition: string;
}

export type Tier2or4Observation = Tier2EvidenceObservation | Tier4ScoreAlertObservation;

export interface Tier2Result {
	observations: Tier2or4Observation[];
	status: 'ok' | 'degraded' | 'partial' | 'timeout' | 'skipped';
}

const BECOMING_CRITICAL_FROM = new Set(['secure', 'low', 'medium']);
const BECOMING_CRITICAL_TO = new Set(['critical', 'high']);

function isBecomingCritical(alert: DomainEvidenceScoreAlert): boolean {
	return BECOMING_CRITICAL_FROM.has(alert.previousThreatLevel) && BECOMING_CRITICAL_TO.has(alert.newThreatLevel);
}

function buildObservations(domain: string, response: Extract<DomainEvidenceResponse, { ok: true }>): Tier2or4Observation[] {
	const out: Tier2or4Observation[] = [];

	if (response.latestScan && response.latestScan.threatLevel) {
		out.push({
			candidate: domain,
			source: 'gsi_evidence',
			tier: 2,
			confidence: 0.9,
			threatLevel: response.latestScan.threatLevel,
			capturedAt: response.latestScan.capturedAt,
		});
	}

	for (const alert of response.scoreAlerts) {
		if (!isBecomingCritical(alert)) continue;
		out.push({
			candidate: domain,
			source: 'score_alert_critical_drop',
			tier: 4,
			confidence: 0.5,
			alertType: alert.alertType,
			transition: `${alert.previousThreatLevel}->${alert.newThreatLevel}`,
		});
	}

	return out;
}

/**
 * Look up Tier 2 evidence (RDAP / DMARC / cert-witness, surfaced via
 * bv-intel-gateway's GSI corpus) for `domain`.
 *
 * @param domain   The seed/candidate domain to query.
 * @param binding  The `BV_INTEL_GATEWAY` service binding. When `undefined`
 *                 (e.g. binding not provisioned in this environment) the
 *                 wrapper returns `{ status: 'skipped', observations: [] }`.
 * @returns        Always resolves; never throws.
 */
export async function tier2EvidenceLookup(domain: string, binding: IntelGatewayBinding | undefined): Promise<Tier2Result> {
	if (!binding) {
		return { observations: [], status: 'skipped' };
	}

	let raw: unknown;
	try {
		raw = await binding.getDomainEvidence({ domain });
	} catch {
		// Binding-level failure (RPC disconnect, transient producer error).
		// Caller continues with other tiers — degraded, not fatal.
		return { observations: [], status: 'degraded' };
	}

	const parsed = DomainEvidenceResponseSchema.safeParse(raw);
	if (!parsed.success) {
		// Producer/consumer contract drift or malformed response. Surface as
		// degraded; contract test should already have caught real drift in CI.
		return { observations: [], status: 'degraded' };
	}

	const response = parsed.data;
	if (!response.ok) {
		// `not_in_corpus` and `opted_out` are both expected non-error outcomes.
		return { observations: [], status: 'skipped' };
	}

	return { observations: buildObservations(domain, response), status: 'ok' };
}
