// SPDX-License-Identifier: BUSL-1.1

/**
 * Package-level abstention audit (#900 follow-up).
 *
 * The defect class: a check "abstains" by spreading `checkStatus: 'error' | 'timeout'`
 * over an ordinary `buildCheckResult(...)`. An info-only finding set derives `score: 100,
 * passed: true`, and nothing sets `partial`, so the non-answer
 *   - is never retried — scan_domain's transient-zero pass keys on
 *     `checkStatus === 'error' && score === 0`;
 *   - is written to the 5-minute per-check cache — both cache predicates are `!partial`;
 *   - reads as a PASS to any consumer that looks at `score`/`passed` without `checkStatus`
 *     (bv-web-prod consumes these package exports directly).
 *
 * #927 fixed caa/mx/ns, #936 fixed dnssec — each by hand, each after the site had already
 * shipped. This audit makes the contract structural: EVERY check the package exports is
 * driven with a resolver and a fetch that always throw, and any result that carries
 * `checkStatus: 'error' | 'timeout'` MUST have the not-assessed shape
 * (`buildNotAssessedResult` in check-utils.ts):
 *
 *     score === 0 && passed === false && partial === true
 *
 * and MUST NOT also stamp `missingControl: true` on a finding — a probe that never reached
 * the origin measured nothing, so it cannot claim the control is absent (#638 law).
 *
 * The check list is DERIVED from the `checks` barrel (every `check*` function export) and
 * cross-checked against the `check-*.ts` files on disk, so a new check cannot silently
 * miss the audit: an unexported one fails the file/export parity assertion, an exported one
 * is swept automatically.
 *
 * A check that THROWS on a transient failure is fine — that is the documented contract for
 * e.g. `checkDANE`, whose Worker wrapper (`buildDnsErrorResult`) / `safeCheck` converts the
 * throw into the same shape. A check that swallows the failure and returns a COMPLETED
 * result (no `checkStatus`) is outside this audit's claim: it is the separate "transient
 * failure scored as a deficiency" class pinned per-check by transient-inconclusive.test.ts.
 */

import { describe, it, expect } from 'vitest';
import * as checks from '../../checks';
import { buildCheckResult, buildNotAssessedResult, createFinding } from '../../check-utils';
import type { CheckResult } from '../../types';

type CheckFn = (domain: string, injected: unknown, options?: Record<string, unknown>) => Promise<CheckResult>;

/** Every `check*` function the package barrel exports — the audit's enumeration source. */
const CHECK_FUNCTIONS: Array<[string, CheckFn]> = Object.entries(checks)
	.filter((entry): entry is [string, CheckFn] => /^check[A-Z]/.test(entry[0]) && typeof entry[1] === 'function')
	.sort(([a], [b]) => a.localeCompare(b));

/**
 * The `check-*.ts` implementation files on disk — the parity control for the enumeration.
 * Vite's glob is resolved at transform time (no `node:fs` — the package tsconfig carries no
 * Node types, and the same idiom serves the Worker-pool audits).
 */
interface GlobbingImportMeta {
	glob(patterns: string[]): Record<string, () => Promise<unknown>>;
}
const CHECK_FILES = Object.keys((import.meta as unknown as GlobbingImportMeta).glob(['../../checks/check-*.ts'])).sort();

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

/**
 * Violations of the not-assessed contract on a result that abstained. Empty for a
 * completed result (no `checkStatus`) — that is the vacuous branch of the implication.
 */
function abstentionViolations(result: CheckResult): string[] {
	if (result.checkStatus !== 'error' && result.checkStatus !== 'timeout') return [];
	const violations: string[] = [];
	if (result.score !== 0) violations.push(`score ${result.score} (expected 0 — scan_domain's transient-zero retry never fires)`);
	if (result.passed !== false) violations.push(`passed ${result.passed} (expected false — an unmeasured control did not pass)`);
	if (result.partial !== true) violations.push(`partial ${result.partial} (expected true — the non-answer would be cached for 5 min)`);
	if (result.findings.some((f) => f.metadata?.missingControl === true)) {
		violations.push('missingControl: true alongside checkStatus — a probe that never completed cannot claim absence');
	}
	return violations;
}

describe('check abstention shape (package)', () => {
	it('enumerates every check on disk — a new check-*.ts without a barrel export fails here', () => {
		// Guard against the audit silently covering nothing after a barrel or layout change.
		expect(CHECK_FUNCTIONS.length).toBeGreaterThanOrEqual(17);
		expect(CHECK_FUNCTIONS.length).toBe(CHECK_FILES.length);
	});

	describe.each(FAILURES)('$kind: every abstention is score 0 / passed false / partial true', ({ kind, make }) => {
		it.each(CHECK_FUNCTIONS)('%s', async (_name, run) => {
			const thrower = async () => {
				throw make();
			};
			// Every check takes `(domain, <queryDNS | fetchFn>, options)`; the raw resolver and
			// the fetch used by the DNS-first checks ride in on `options`. Extra option keys are
			// ignored by checks that do not read them.
			let result: CheckResult;
			try {
				result = await run('example.com', thrower, { rawQueryDNS: thrower, fetchFn: thrower, timeout: 50 });
			} catch {
				// Throwing is the documented "let the caller convert it" contract (checkDANE).
				return;
			}
			expect(abstentionViolations(result), `${_name} (${kind}) → ${JSON.stringify(result)}`).toEqual([]);
		});
	});

	describe('positive control — the predicate discriminates', () => {
		const info = createFinding('spf', 'SPF not assessed', 'info', 'resolver failed');

		it('rejects the pre-#900 shape: checkStatus spread over an info-only buildCheckResult', () => {
			const offender: CheckResult = { ...buildCheckResult('spf', [info]), checkStatus: 'error' };
			expect(offender).toMatchObject({ score: 100, passed: true }); // what the shape reads as
			expect(abstentionViolations(offender)).toHaveLength(3);
		});

		it('rejects a zeroed result that still claims absence', () => {
			const contradictory = buildNotAssessedResult('spf', createFinding('spf', 'x', 'high', 'y', { missingControl: true }));
			expect(abstentionViolations(contradictory)).toEqual([expect.stringContaining('missingControl')]);
		});

		it('accepts the canonical not-assessed shape and a completed result', () => {
			expect(abstentionViolations(buildNotAssessedResult('spf', info))).toEqual([]);
			expect(abstentionViolations(buildNotAssessedResult('spf', info, 'timeout'))).toEqual([]);
			expect(abstentionViolations(buildCheckResult('spf', [info]))).toEqual([]);
		});
	});
});
