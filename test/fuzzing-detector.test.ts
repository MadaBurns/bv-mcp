// Unit tests for the fuzzing detector — pure functions, no I/O.
//
// `classifyError` maps a (jsonRpcCode, dispatchPath, errorDescription, httpStatus)
// tuple to a FuzzKind ('unknown_tool' | 'unknown_method' | 'zod_arg' | 'auth_fail')
// or null when the signal isn't fuzz-relevant.
//
// `scoreWindow` takes a list of timestamped events for a single principal and
// the configured thresholds and returns a verdict: { suspected, kind, count }.
// The window is sliding (not bucketed) — a stream of errors spread thin enough
// across time must NOT be flagged.

import { describe, it, expect } from 'vitest';
import { classifyError, scoreWindow, type FuzzEvent, type FuzzThresholds } from '../src/lib/fuzzing-detector';

const DEFAULT_THRESHOLDS: FuzzThresholds = {
	windowSeconds: 60,
	unknown_tool: 10,
	zod_arg: 20,
	unknown_method: 5,
	auth_fail: 30,
};

function makeEvents(kind: FuzzEvent['kind'], count: number, intervalSec: number, baseEpochSec = 1_700_000_000): FuzzEvent[] {
	return Array.from({ length: count }, (_, i) => ({ kind, epochSec: baseEpochSec + i * intervalSec }));
}

describe('classifyError', () => {
	it('returns "unknown_tool" for jsonRpc -32601 on tools/call dispatch', () => {
		expect(classifyError({ jsonRpcCode: -32601, dispatchPath: 'tools/call' })).toBe('unknown_tool');
	});

	it('returns "unknown_method" for jsonRpc -32601 on dispatch (top-level method routing)', () => {
		expect(classifyError({ jsonRpcCode: -32601, dispatchPath: 'dispatch' })).toBe('unknown_method');
	});

	it('returns "zod_arg" for -32602 with a description starting with "Invalid "', () => {
		expect(classifyError({ jsonRpcCode: -32602, dispatchPath: 'tools/call', description: 'Invalid domain: not a string' })).toBe('zod_arg');
	});

	it('returns "auth_fail" for an HTTP 401 (outside the JSON-RPC frame)', () => {
		expect(classifyError({ httpStatus: 401 })).toBe('auth_fail');
	});

	it('returns null for a generic invalid-request (-32600)', () => {
		expect(classifyError({ jsonRpcCode: -32600, dispatchPath: 'tools/call' })).toBeNull();
	});

	it('returns null for a parse error (-32700) — too noisy to be a useful fuzz signal', () => {
		expect(classifyError({ jsonRpcCode: -32700 })).toBeNull();
	});
});

describe('scoreWindow', () => {
	it('returns suspected=false for an empty event list', () => {
		expect(scoreWindow([], DEFAULT_THRESHOLDS).suspected).toBe(false);
	});

	it('returns suspected=false when below the unknown_tool threshold', () => {
		const events = makeEvents('unknown_tool', 9, 5); // 9 events in 45s
		expect(scoreWindow(events, DEFAULT_THRESHOLDS).suspected).toBe(false);
	});

	it('returns suspected=true with kind="unknown_tool" when threshold is met inside the window', () => {
		const events = makeEvents('unknown_tool', 10, 5); // 10 events in 50s — inside 60s window
		const v = scoreWindow(events, DEFAULT_THRESHOLDS);
		expect(v.suspected).toBe(true);
		expect(v.kind).toBe('unknown_tool');
		expect(v.count).toBeGreaterThanOrEqual(10);
	});

	it('uses a SLIDING window, not buckets — 10 events spread over 120s with no 60s slice ≥10 stays clean', () => {
		// 10 events, 13s apart → 9 events fit in any 60s slice
		const events = makeEvents('unknown_tool', 10, 13);
		expect(scoreWindow(events, DEFAULT_THRESHOLDS).suspected).toBe(false);
	});

	it('classifies as "mixed" when no single kind crosses but multiple kinds combined do', () => {
		const base = 1_700_000_000;
		const events: FuzzEvent[] = [
			...makeEvents('unknown_tool', 8, 1, base),
			...makeEvents('zod_arg', 6, 1, base + 10),
		];
		const v = scoreWindow(events, { ...DEFAULT_THRESHOLDS, unknown_tool: 10, zod_arg: 20 });
		expect(v.suspected).toBe(true);
		expect(v.kind).toBe('mixed');
	});
});
