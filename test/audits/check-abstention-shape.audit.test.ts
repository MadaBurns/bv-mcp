// SPDX-License-Identifier: BUSL-1.1

/**
 * Worker-side abstention audit (#900 follow-up) — the direct-call twin of
 * packages/dns-checks/src/__tests__/checks/abstention-shape.audit.test.ts.
 *
 * The package audit proves every package check abstains in the not-assessed shape. The
 * Worker wrappers in src/tools/check-*.ts add their own catches (the twelve
 * `buildDnsErrorResult` sites, the fetch-budget cuts, the WAF handling), so the shape that
 * actually reaches a client — and the 5-minute per-check cache in handlers/tools.ts — is
 * theirs. This audit drives every directly-callable `check_*` tool through the SAME
 * registry `handleToolsCall` dispatches from (`TOOL_REGISTRY`), with the platform `fetch`
 * (DoH and HTTPS probes alike) rejecting, and asserts the contract on whatever comes back:
 *
 *     checkStatus ∈ { 'error', 'timeout' }  ⇒  score === 0 && passed === false && partial === true
 *                                            and no finding carries `missingControl: true`
 *
 * Why each clause matters (CLAUDE.md "DNS-failure resilience"):
 *   - `score === 0` — scan_domain's transient-zero retry is `checkStatus === 'error' && score === 0`;
 *   - `passed === false` — `passed` is read as a verdict by four surfaces already (#705 #706 #725 #809);
 *   - `partial === true` — both cache predicates are `!partial`; without it the non-answer is
 *     served for the TTL;
 *   - no `missingControl` — a probe that never completed cannot claim absence (#638 law).
 *
 * Enumeration is derived, not hand-listed: every SCORED category in `SCAN_CATEGORIES` (the
 * keys of scan_domain's dispatch table) must have a `check_<category>` entry in
 * `TOOL_REGISTRY`, and every other `check_*` registry entry is swept too. A new scored check
 * that is not directly callable fails the parity assertion; a new directly-callable check is
 * swept automatically.
 *
 * Non-scored tools have ONE documented exemption: a result carrying an unmeasured marker
 * (`unprovisioned` / `upstreamUnavailable` / `upstreamNotFound`, src/lib/unmeasured-result.ts)
 * belongs to the #695 class, where the scalars are deliberately left alone and only
 * `checkStatus` is stamped. Scored categories get no exemption at all — an unmeasured marker
 * on one is already a build failure (unmeasured-marker-scope.audit.test.ts).
 */

import { describe, it, expect, afterEach, vi } from 'vitest';
import { TOOL_REGISTRY } from '../../src/handlers/tools';
import { SCAN_CATEGORIES } from '../../src/tools/scan-domain';
import { isUnmeasuredResult } from '../../src/lib/unmeasured-result';
import type { CheckResult } from '../../src/lib/scoring';

const savedFetch = globalThis.fetch;
afterEach(() => {
	globalThis.fetch = savedFetch;
});

/** The failure classes a transient probe can raise. `name` drives the timeout classifiers. */
const FAILURES = [
	{ kind: 'error', make: () => new Error('transient resolver failure') },
	{
		kind: 'timeout',
		make: () => {
			const e = new Error('The operation timed out');
			e.name = 'TimeoutError';
			return e;
		},
	},
] as const;

const SCORED_TOOLS = SCAN_CATEGORIES.map((category) => `check_${category}`).sort();
const OTHER_CHECK_TOOLS = Object.keys(TOOL_REGISTRY)
	.filter((name) => name.startsWith('check_') && !SCORED_TOOLS.includes(name))
	.sort();

/**
 * Violations of the not-assessed contract on a result that abstained. Empty for a
 * completed result (no `checkStatus`) — the vacuous branch of the implication.
 */
function abstentionViolations(result: CheckResult): string[] {
	if (result.checkStatus !== 'error' && result.checkStatus !== 'timeout') return [];
	const violations: string[] = [];
	if (result.score !== 0) violations.push(`score ${result.score} (expected 0 — scan_domain's transient-zero retry never fires)`);
	if (result.passed !== false) violations.push(`passed ${result.passed} (expected false — an unmeasured control did not pass)`);
	if (result.partial !== true) violations.push(`partial ${result.partial} (expected true — the non-answer would be cached for the TTL)`);
	if (result.findings.some((f) => f.metadata?.missingControl === true)) {
		violations.push('missingControl: true alongside checkStatus — a probe that never completed cannot claim absence');
	}
	return violations;
}

async function runTool(name: string, make: () => Error): Promise<CheckResult | 'throws'> {
	globalThis.fetch = vi.fn().mockImplementation(async () => {
		throw make();
	});
	try {
		return await TOOL_REGISTRY[name].execute('example.com', {}, undefined);
	} catch {
		// A throw surfaces as a failed tool call (no cached, no scored, no `passed` result), which
		// is outside this audit's claim. scan_domain's safeCheck converts it to the same shape.
		return 'throws';
	}
}

describe('check abstention shape (Worker direct-call registry)', () => {
	it('every scored category is directly callable through TOOL_REGISTRY — the enumeration cannot go stale', () => {
		expect(SCAN_CATEGORIES.length).toBeGreaterThanOrEqual(19);
		const missing = SCORED_TOOLS.filter((name) => !(name in TOOL_REGISTRY));
		expect(missing).toEqual([]);
		// Guard against the second sweep silently covering nothing.
		expect(OTHER_CHECK_TOOLS.length).toBeGreaterThan(5);
	});

	describe.each(FAILURES)('$kind: scored checks — every abstention is score 0 / passed false / partial true', ({ kind, make }) => {
		it.each(SCORED_TOOLS)('%s', async (name) => {
			const result = await runTool(name, make);
			if (result === 'throws') return;
			expect(abstentionViolations(result), `${name} (${kind}) → ${JSON.stringify(result)}`).toEqual([]);
		});
	});

	describe.each(FAILURES)('$kind: other directly-callable checks — same contract, #695 unmeasured class exempt', ({ kind, make }) => {
		it.each(OTHER_CHECK_TOOLS)('%s', async (name) => {
			const result = await runTool(name, make);
			if (result === 'throws') return;
			if (isUnmeasuredResult(result)) return;
			expect(abstentionViolations(result), `${name} (${kind}) → ${JSON.stringify(result)}`).toEqual([]);
		});
	});

	describe('positive control — the predicate discriminates', () => {
		it('rejects the pre-#900 shape and accepts the buildDnsErrorResult shape', async () => {
			const { buildCheckResult, createFinding } = await import('../../src/lib/scoring');
			const { buildDnsErrorResult } = await import('../../src/lib/dns-error-result');
			const info = createFinding('spf', 'SPF not assessed', 'info', 'resolver failed');
			const offender: CheckResult = { ...buildCheckResult('spf', [info]), checkStatus: 'error' };
			expect(offender).toMatchObject({ score: 100, passed: true });
			expect(abstentionViolations(offender)).toHaveLength(3);

			const zeroedButCached: CheckResult = { ...buildCheckResult('spf', [info]), score: 0, passed: false, checkStatus: 'error' };
			expect(abstentionViolations(zeroedButCached)).toEqual([expect.stringContaining('partial')]);

			expect(abstentionViolations(buildDnsErrorResult('spf', 'SPF', new Error('DNS query failed')))).toEqual([]);
			expect(abstentionViolations(buildCheckResult('spf', [info]))).toEqual([]);
		});
	});
});
