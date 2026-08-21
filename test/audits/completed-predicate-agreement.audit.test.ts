// SPDX-License-Identifier: BUSL-1.1

/**
 * The completed-check predicate has THREE deliberate spellings, in modules that
 * cannot import each other:
 *
 *   1. `packages/dns-checks/src/scoring/evidence.ts` (`computeScanEvidence`) —
 *      `checkStatus === undefined || checkStatus === 'completed'` (the package
 *      cannot depend on Worker code);
 *   2. `src/lib/ungraded-display.ts` (`isCompletedCheck`/`hasCompletedEvidence`)
 *      — the zero-import leaf every `src/tools/` formatter shares;
 *   3. `src/tools/map-compliance.ts` — the NEGATIVE spelling
 *      `checkStatus !== 'timeout' && checkStatus !== 'error'`, at both the
 *      per-control filter and the report-level `assessed` computation.
 *
 * Spellings 1–2 name the statuses that COUNT; spelling 3 names the statuses
 * that DON'T. They agree today only because `CheckStatus` has exactly three
 * members. Add a fourth (say `'skipped'`) and the two styles silently diverge:
 * the positive spellings call it not-completed while the negative one calls it
 * completed — the evidence gate would abstain on a scan whose compliance report
 * confidently grades the very same checks. This audit iterates EVERY
 * `CheckStatus` union member (parsed from the type declaration itself, so a new
 * member joins automatically) through all three shipped code paths and fails on
 * the first disagreement.
 */

import { describe, it, expect } from 'vitest';
import type { CheckResult, CheckStatus } from '../../src/lib/scoring';

// The union is a TYPE — erased at runtime — so the member list is recovered from
// the declaration source itself (same import.meta.glob raw mechanism as
// `ungraded-representation.audit.test.ts`; the Workers pool has no `fs`). A
// fourth member added to the union is therefore in the iteration set with no
// edit to this file.
const TYPES_SOURCE = import.meta.glob('../../packages/dns-checks/src/types.ts', {
	eager: true,
	query: '?raw',
	import: 'default',
}) as Record<string, string>;

function parseCheckStatusMembers(): string[] {
	const source = Object.values(TYPES_SOURCE)[0] ?? '';
	const match = source.match(/export type CheckStatus\s*=\s*([^;]+);/);
	if (!match) return [];
	return match[1]
		.split('|')
		.map((m) => m.trim().replace(/^'|'$/g, ''))
		.filter((m) => m.length > 0);
}

/** A minimal but valid CheckResult carrying the status under test. */
function dmarcResult(status: string | undefined): CheckResult {
	return {
		category: 'dmarc',
		passed: false,
		score: 0,
		findings: [{ category: 'dmarc', title: 'DMARC finding', severity: 'high', detail: 'x' }],
		...(status === undefined ? {} : { checkStatus: status as CheckStatus }),
	} as CheckResult;
}

describe('completed-predicate agreement across the three spellings', () => {
	it('parsed the CheckStatus union non-vacuously', () => {
		const members = parseCheckStatusMembers();
		// If parsing breaks (the declaration moves or is reformatted), fail loudly
		// rather than iterating an empty set and passing on nothing.
		expect(members).toEqual(expect.arrayContaining(['completed', 'timeout', 'error']));
		expect(members.length).toBeGreaterThanOrEqual(3);
	});

	it('every CheckStatus member (and the absent-status legacy shape) classifies identically in all three modules', async () => {
		const { computeScanEvidence } = await import('@blackveil/dns-checks/scoring');
		const { isCompletedCheck, hasCompletedEvidence } = await import('../../src/lib/ungraded-display');
		const { evaluateCompliance } = await import('../../src/tools/map-compliance');

		const statuses: Array<string | undefined> = [...parseCheckStatusMembers(), undefined];
		expect(statuses.length).toBeGreaterThanOrEqual(4);

		for (const status of statuses) {
			const result = dmarcResult(status);
			const label = `checkStatus: ${status ?? '(absent)'}`;

			// Spelling 1 — the package's evidence accounting.
			const byEvidence = computeScanEvidence([result]).completed === 1;
			// Spelling 2 — the shared leaf predicate (single-check and some() forms).
			const byLeaf = isCompletedCheck(result);
			const byLeafSome = hasCompletedEvidence([result]);
			// Spelling 3a — map_compliance's report-level `assessed` (:~367).
			const report = evaluateCompliance([result], 'predicate-agreement.example', null, null);
			const byComplianceAssessed = report.assessed;
			// Spelling 3b — map_compliance's per-control transient partition (:~272).
			// NIST 800-177 §4.3.3 maps solely to `dmarc`: with `passed: false` a
			// completed result grades it `fail`; a non-completed one must abstain
			// to `not_assessed`. Either graded verdict means "counted as completed".
			const control = report.frameworks.nist_800_177.mappings.find((m) => m.controlId === '§4.3.3');
			expect(control, `${label}: NIST §4.3.3 control missing — fixture no longer reaches the per-control filter`).toBeDefined();
			const byComplianceControl = control!.status !== 'not_assessed';

			expect(byLeaf, `${label}: ungraded-display vs dns-checks evidence`).toBe(byEvidence);
			expect(byLeafSome, `${label}: hasCompletedEvidence vs isCompletedCheck`).toBe(byEvidence);
			expect(byComplianceAssessed, `${label}: map_compliance assessed vs dns-checks evidence`).toBe(byEvidence);
			expect(byComplianceControl, `${label}: map_compliance per-control filter vs dns-checks evidence`).toBe(byEvidence);
		}

		// Known-value anchors: agreement alone would also hold if every spelling
		// drifted the same wrong way. Pin the semantics for the three current
		// members plus the legacy absent-status shape.
		expect(computeScanEvidence([dmarcResult(undefined)]).completed).toBe(1);
		expect(computeScanEvidence([dmarcResult('completed')]).completed).toBe(1);
		expect(computeScanEvidence([dmarcResult('timeout')]).completed).toBe(0);
		expect(computeScanEvidence([dmarcResult('error')]).completed).toBe(0);
	});
});
