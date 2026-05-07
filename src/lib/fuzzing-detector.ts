// SPDX-License-Identifier: BUSL-1.1

/**
 * Pure fuzzing-detection logic. No I/O. The KV-backed counter and the
 * scheduled-cron alert dispatch are separate modules — this file is the
 * core decision logic and is unit-tested in isolation.
 *
 * See docs/plans/2026-05-07-fuzzing-detection-tdd-plan.md for the full plan.
 */

export type FuzzKind = 'unknown_tool' | 'unknown_method' | 'zod_arg' | 'auth_fail';

export interface FuzzEvent {
	kind: FuzzKind;
	/** Unix epoch seconds. The detector is deterministic with respect to this clock. */
	epochSec: number;
}

export interface FuzzThresholds {
	/** Sliding window width in seconds. */
	windowSeconds: number;
	unknown_tool: number;
	unknown_method: number;
	zod_arg: number;
	auth_fail: number;
}

export interface ClassifyInput {
	/** JSON-RPC error code from the response, if any (e.g. -32601). */
	jsonRpcCode?: number;
	/** Where in the dispatch tree the error fired: 'tools/call' for unknown tool, 'dispatch' for unknown method. */
	dispatchPath?: 'tools/call' | 'dispatch';
	/** Free-text error description (used to disambiguate -32602 zod errors). */
	description?: string;
	/** HTTP status — used only for auth_fail (401), since auth fails before JSON-RPC framing. */
	httpStatus?: number;
}

export interface FuzzVerdict {
	suspected: boolean;
	/** Single classification when one kind crosses; 'mixed' when no single kind crosses but combined errors exceed any single threshold. */
	kind?: FuzzKind | 'mixed';
	count?: number;
	windowSeconds?: number;
}

/**
 * Map a single error event to its FuzzKind, or null if not a fuzz-relevant signal.
 * Designed to be cheap — called on every error response.
 */
export function classifyError(input: ClassifyInput): FuzzKind | null {
	if (input.httpStatus === 401) return 'auth_fail';
	if (input.jsonRpcCode === -32601) {
		return input.dispatchPath === 'dispatch' ? 'unknown_method' : 'unknown_tool';
	}
	if (input.jsonRpcCode === -32602 && input.description?.startsWith('Invalid ')) {
		return 'zod_arg';
	}
	return null;
}

/**
 * Score a list of events against thresholds. Returns the highest-confidence verdict.
 *
 * Sliding-window: for each event, count how many events of the same kind fall within
 * `[event.epochSec - windowSeconds, event.epochSec]`. Take the max across all events.
 * If the max meets or exceeds the kind's threshold → suspected of that kind.
 *
 * If no single kind crosses but the aggregate event count in any window meets the
 * smallest single-kind threshold (defensive: a smart fuzzer rotates kinds), classify
 * as 'mixed'. This is the recall lever — tighten by raising thresholds, not by
 * adding kinds.
 */
export function scoreWindow(events: FuzzEvent[], thresholds: FuzzThresholds): FuzzVerdict {
	if (events.length === 0) return { suspected: false };

	// Single-kind sliding-window peak counts
	const kinds: FuzzKind[] = ['unknown_tool', 'unknown_method', 'zod_arg', 'auth_fail'];
	for (const kind of kinds) {
		const ofKind = events.filter((e) => e.kind === kind);
		const peak = slidingPeak(ofKind, thresholds.windowSeconds);
		if (peak >= thresholds[kind]) {
			return { suspected: true, kind, count: peak, windowSeconds: thresholds.windowSeconds };
		}
	}

	// Mixed: only fires when ≥2 distinct kinds are simultaneously present in the window
	// (otherwise a benign below-threshold stream of one kind would be flagged). Uses the
	// smallest single-kind threshold as the aggregate bar — a smart fuzzer rotating kinds
	// to stay under each individual cap should still trip this combined limit.
	const distinctKinds = new Set(events.map((e) => e.kind)).size;
	if (distinctKinds >= 2) {
		const aggregatePeak = slidingPeak(events, thresholds.windowSeconds);
		const smallestThreshold = Math.min(thresholds.unknown_tool, thresholds.unknown_method, thresholds.zod_arg, thresholds.auth_fail);
		if (aggregatePeak >= smallestThreshold) {
			return { suspected: true, kind: 'mixed', count: aggregatePeak, windowSeconds: thresholds.windowSeconds };
		}
	}

	return { suspected: false };
}

/** Maximum count of events in any window of `windowSeconds` ending at any event timestamp. */
function slidingPeak(events: FuzzEvent[], windowSeconds: number): number {
	if (events.length === 0) return 0;
	const sorted = [...events].sort((a, b) => a.epochSec - b.epochSec);
	let peak = 0;
	let lo = 0;
	for (let hi = 0; hi < sorted.length; hi++) {
		while (sorted[hi].epochSec - sorted[lo].epochSec > windowSeconds) lo++;
		const count = hi - lo + 1;
		if (count > peak) peak = count;
	}
	return peak;
}
