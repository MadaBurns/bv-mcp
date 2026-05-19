// SPDX-License-Identifier: BUSL-1.1

/**
 * Pure freshness-fallback decision logic for cross-worker brand-discovery
 * service-binding responses.
 *
 * Both bv-infrastructure-graph (Tier 1) and bv-intel-gateway (Tier 2) surface
 * the same `freshness` shape on their responses; this module is the shared
 * pure function the wrappers consult before deciding whether to escalate to
 * a live-fetch fallback.
 *
 * Contract: docs/superpowers/plans/2026-05-20-brand-discovery-cross-worker-contract.md
 *   → "Fingerprint freshness contract"
 *
 * Decision:
 *   - fresh / partial / stale → trust the producer's response; no fallback.
 *   - very_stale              → trigger Tier 3 / live-sweep fallback for this seed.
 *
 * No I/O, no bindings, no network — pure on the input.
 */

import type { Freshness } from '../schemas/cross-worker-domain-related';

/** Type-only re-export so consumers don't have to know about the schema module. */
export type FreshnessResponse = Freshness;

/**
 * Returns true when the producer's data is so stale (>30d on any signal) that
 * the consumer should fall back to a live infrastructure sweep instead of
 * relying on the graph response.
 *
 * Stale (7d–30d) is intentionally NOT a fallback trigger — the producer's
 * recommended strategy there is "re-fetch all signals," handled by the
 * producer-side sweep cron, not by us synchronously.
 */
export function shouldTriggerLiveFallback(freshness: FreshnessResponse): boolean {
	return freshness.overallStaleness === 'very_stale';
}
