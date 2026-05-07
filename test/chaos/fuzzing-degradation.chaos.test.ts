// Chaos hypotheses for the fuzzing-detection feature. Each test takes the
// form "Given [failure], system should [degrade gracefully]."
//
// Per testing-methodology.md principle 6, these are explicit failure
// hypotheses, not regression smoke tests. Run sparingly.

import { describe, it, expect } from 'vitest';
import { recordEvent, readWindow } from '../../src/lib/fuzzing-counter';
import { scoreWindow, type FuzzEvent } from '../../src/lib/fuzzing-detector';
import { FUZZ_THRESHOLDS } from '../../src/lib/config';

/** A KV stub that throws on every operation. */
function brokenKv(): KVNamespace {
	const fail = async () => {
		throw new Error('kv unavailable');
	};
	return {
		get: fail,
		put: fail,
		delete: fail,
		list: fail,
		getWithMetadata: fail,
	} as unknown as KVNamespace;
}

describe('fuzzing-detection chaos', () => {
	it('Hypothesis: when RATE_LIMIT KV is down, recordEvent silently no-ops without throwing', async () => {
		// recordEvent must never propagate KV errors — the request path must remain green.
		await expect(recordEvent(brokenKv(), 'p1', 'unknown_tool', 1_700_000_000)).resolves.toBeUndefined();
	});

	it('Hypothesis: when RATE_LIMIT KV is down, readWindow returns [] instead of throwing', async () => {
		// Scheduled scan must keep running even if a single principal\'s read fails.
		await expect(readWindow(brokenKv(), 'p1', 1_700_000_000, 60)).resolves.toEqual([]);
	});

	it('Hypothesis: a stream of legitimate traffic mixed with a sub-threshold error count is not flagged', async () => {
		// False-positive bound: 9 unknown_tool errors (one below threshold of 10 — using a tighter
		// override to make the test deterministic against future threshold bumps) inside a 60s
		// window must NOT yield a suspected verdict, regardless of how many successes happened.
		// Successes don\'t enter the counter; we\'re asserting that the detector reasons only over
		// errors and a bare-below-threshold run stays clean.
		const events: FuzzEvent[] = Array.from({ length: 9 }, (_, i) => ({
			kind: 'unknown_tool',
			epochSec: 1_700_000_000 + i * 5,
		}));
		const verdict = scoreWindow(events, { ...FUZZ_THRESHOLDS, unknown_tool: 10 });
		expect(verdict.suspected).toBe(false);
	});
});
