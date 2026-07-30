// SPDX-License-Identifier: BUSL-1.1

/**
 * "Did this check produce usable evidence?" must have exactly ONE implementation
 * ACROSS the `src/` ↔ `packages/dns-checks` package boundary.
 *
 * WHY THIS FILE EXISTS SEPARATELY FROM
 * `completed-evidence-predicate-ssot.audit.test.ts`:
 *
 * That sibling audit is a TEXT scanner whose scope is `src/` BY DESIGN — it
 * globs `../../src/**` and its own doc states it "does not, and must not, reach
 * into `packages/dns-checks`", because its job is to stop the many `src/`
 * surfaces from drifting from EACH OTHER. That decision is still correct and is
 * deliberately left intact: widening its glob to `packages/` would silently
 * change the corpus its anti-vacuity guard (`paths.length > 200`) and its
 * `KNOWN_DIFFERENT_PURPOSE` exact-occurrence-count assertion are calibrated
 * against, and would make a package-side edit fail an audit whose whole
 * vocabulary (SSOT_PATH, the `src/`-relative exclusions) is `src/`-shaped.
 *
 * So the cross-boundary leg lives HERE instead, and it is deliberately a
 * different KIND of check: a BEHAVIOURAL parity contract plus a delegation
 * lock, not a text scan. Text scanning cannot prove two independent
 * implementations agree; calling both with the same inputs can.
 *
 * WHAT DRIFT THIS CLOSES. Before PR #578 the two sides were an acknowledged,
 * hand-maintained twin: `isCompletedCheck` in `src/lib/ungraded-display.ts`
 * re-derived `checkStatus === undefined || checkStatus === 'completed'`
 * independently of `computeScanEvidence`'s identical accounting in
 * `packages/dns-checks/src/scoring/evidence.ts`, and NOTHING in CI compared
 * them. Both spellings were allowlist-shaped, so both failed safe — this was a
 * drift RISK, not a live bug. The risk is concrete: `CheckStatus` is a closed
 * three-member union today, and a future member added to the package's
 * `isCheckMeasured` but not to the worker's hand-copy (or vice versa) would
 * reach only one side. A scan carrying that new status would then be
 * "incomplete evidence" to the scoring engine and "completed evidence" to the
 * report formatter — the exact split-brain the evidence campaign exists to
 * prevent, shipping green.
 *
 * PR #578 removed the excuse: it extracted the package side into the exported
 * `isCheckMeasured`, on the `@blackveil/dns-checks/scoring` subpath `src/`
 * ALREADY consumes (`src/lib/adaptive-weights.ts`,
 * `src/lib/category-interactions.ts`, `src/lib/scoring.ts`). The dependency
 * direction is `src/` → package, which is the direction that already exists;
 * no cycle is created (`packages/dns-checks/src` imports nothing outside
 * relative paths, `zod` and `vitest` — verified, see the leaf-module test
 * below). `isCompletedCheck` therefore now DELEGATES, and this audit pins that.
 *
 * THREE LEGS, each catching a different failure:
 *   1. BEHAVIOURAL PARITY — the two predicates agree on every `CheckStatus`
 *      member, on `undefined`, and on out-of-union values a version-skewed
 *      cache read can produce. Type-level exhaustiveness (`Record<CheckStatus, …>`)
 *      makes adding a union member a COMPILE error here, so the sweep can never
 *      silently narrow.
 *   2. DELEGATION LOCK — `isCompletedCheck` must literally call the package
 *      export, not re-derive an extensionally-equal copy. Leg 1 alone cannot
 *      catch a re-derived-but-currently-identical copy (it passes), which is
 *      precisely how the pre-#578 twin looked on the day it was written; leg 2
 *      is what makes a future divergence impossible rather than merely
 *      detectable-in-hindsight.
 *   3. LEAF-MODULE PRESERVATION — `ungraded-display.ts` is documented as a tiny
 *      module with no edge to the scan orchestrator, so every formatter in
 *      `src/tools/` can import it cycle-free. The new import must stay confined
 *      to the external package.
 *
 * The negative control below proves leg 1 has teeth: a deliberately drifted
 * re-derivation is run through the SAME parity sweep and MUST be reported as
 * divergent. Without it, a parity assertion over a domain that happens to
 * contain no distinguishing input would pass vacuously forever.
 */

import { describe, expect, it } from 'vitest';
import ungradedDisplaySource from '../../src/lib/ungraded-display.ts?raw';
import { isCompletedCheck } from '../../src/lib/ungraded-display';
import { isCheckMeasured } from '@blackveil/dns-checks/scoring';
import type { CheckStatus } from '@blackveil/dns-checks/scoring';

/**
 * Type-level exhaustiveness lock. Adding a member to the package's `CheckStatus`
 * union without adding it here is a COMPILE error (`npx tsc --noEmit`), so the
 * parity sweep below can never silently stop covering the full domain — the
 * single most likely way this audit would rot into a vacuous green.
 */
const CHECK_STATUS_TABLE: Record<CheckStatus, true> = {
	completed: true,
	timeout: true,
	error: true,
};

const ALL_CHECK_STATUSES = Object.keys(CHECK_STATUS_TABLE) as CheckStatus[];

/**
 * Values outside the declared union. These are not hypothetical: `isCheckMeasured`'s
 * own doc calls out a `CheckResult` re-read from an untrusted source (a `JSON.parse`
 * of a cached KV entry with no Zod revalidation, or a version-skewed deploy) carrying
 * a status outside the union at runtime. They are also the closest stand-in available
 * for "a `CheckStatus` member that exists on one side of the boundary and not the
 * other" — the exact drift this audit exists to catch — so parity MUST hold here too,
 * not just on the three declared members.
 */
const OUT_OF_UNION_STATUSES = ['skipped', 'partial', 'pending', 'COMPLETED', '', 'unknown-future-member'] as const;

/** Every input both predicates must agree on: the declared union, `undefined`, and out-of-union noise. */
const PARITY_DOMAIN: ReadonlyArray<CheckStatus | string | undefined> = [...ALL_CHECK_STATUSES, undefined, ...OUT_OF_UNION_STATUSES];

/**
 * Run an arbitrary per-check predicate against the package's `isCheckMeasured`
 * over the whole parity domain and report every input the two disagree on.
 *
 * Parameterised on the candidate rather than hard-coding `isCompletedCheck` so
 * the SAME sweep can be pointed at the negative control below — a divergence
 * detector that has never been shown to detect a divergence is not evidence.
 */
function divergences(candidate: (check: { readonly checkStatus?: CheckStatus }) => boolean): Array<{
	input: string;
	candidate: boolean;
	packageSide: boolean;
}> {
	const found: Array<{ input: string; candidate: boolean; packageSide: boolean }> = [];
	for (const status of PARITY_DOMAIN) {
		// The cast is the point: these inputs model values that reach the predicate
		// at RUNTIME from an unvalidated source, which the compile-time union cannot
		// express. `isCheckMeasured` accepts a widened `string` for the same reason.
		const candidateAnswer = candidate({ checkStatus: status as CheckStatus });
		const packageAnswer = isCheckMeasured(status);
		if (candidateAnswer !== packageAnswer) {
			found.push({ input: String(status), candidate: candidateAnswer, packageSide: packageAnswer });
		}
	}
	return found;
}

/**
 * NEGATIVE CONTROL — what the worker side looked like if a maintainer had
 * "simplified" the allowlist into the denylist form while the package kept the
 * allowlist. Extensionally identical on all three CURRENT union members, and
 * divergent the instant any other value appears. This is not dead code: the
 * test below asserts the sweep REPORTS it as divergent, which is the only proof
 * that a green parity result on the real predicate means anything.
 */
function driftedDenylistReDerivation(check: { readonly checkStatus?: CheckStatus }): boolean {
	const status: string | undefined = check.checkStatus;
	return status !== 'timeout' && status !== 'error';
}

describe('completed-evidence predicate parity across the src/ ↔ packages/dns-checks boundary', () => {
	it('is not vacuous: the parity domain covers the full CheckStatus union, undefined, and out-of-union values', () => {
		// If CHECK_STATUS_TABLE and the runtime array ever drift, every parity
		// assertion below silently narrows. Both are pinned.
		expect(ALL_CHECK_STATUSES.slice().sort()).toEqual(['completed', 'error', 'timeout']);
		expect(PARITY_DOMAIN.length).toBe(ALL_CHECK_STATUSES.length + 1 + OUT_OF_UNION_STATUSES.length);
		expect(PARITY_DOMAIN).toContain(undefined);
	});

	it('LEG 1 — isCompletedCheck agrees with the package isCheckMeasured on every input', () => {
		expect(
			divergences(isCompletedCheck),
			'src/lib/ungraded-display.ts isCompletedCheck has diverged from @blackveil/dns-checks/scoring isCheckMeasured',
		).toEqual([]);
	});

	it('LEG 1 (negative control) — the sweep actually DETECTS a drifted re-derivation', () => {
		// Proof of teeth. A denylist re-derivation agrees on all three declared
		// members but disagrees on every out-of-union value, which is exactly the
		// shape a future-CheckStatus-member drift takes.
		const found = divergences(driftedDenylistReDerivation);
		expect(found.length).toBeGreaterThan(0);
		// It must agree on the three CURRENT members — otherwise the control is
		// detecting something cruder than the drift class this audit models.
		for (const status of ALL_CHECK_STATUSES) {
			expect(driftedDenylistReDerivation({ checkStatus: status })).toBe(isCheckMeasured(status));
		}
		// …and disagree on an unknown future member, awarding it "measured".
		expect(found.map((d) => d.input)).toContain('unknown-future-member');
		expect(found.every((d) => d.candidate === true && d.packageSide === false)).toBe(true);
	});

	it('LEG 2 — isCompletedCheck DELEGATES to the package export rather than re-deriving it', () => {
		// Leg 1 passes for a re-derived-but-currently-identical copy (that is what
		// the pre-#578 twin was). Only this leg makes divergence impossible instead
		// of merely detectable.
		expect(ungradedDisplaySource).toMatch(/import\s*\{[^}]*\bisCheckMeasured\b[^}]*\}\s*from\s*'@blackveil\/dns-checks\/scoring'/);
		expect(ungradedDisplaySource).toMatch(/export function isCompletedCheck\([^)]*\)\s*:\s*boolean\s*\{\s*return isCheckMeasured\(check\.checkStatus\);\s*\}/);
	});

	it('LEG 2 — the file no longer claims the two sides are an un-shareable hand-maintained twin', () => {
		// PR #578 invalidated that rationale by exporting the predicate on a subpath
		// src/ already consumes. A doc left asserting "kept in semantic lockstep by
		// hand, not by a shared import" would be actively false and would invite the
		// next maintainer to re-derive rather than import.
		expect(ungradedDisplaySource).not.toMatch(/semantic lockstep by hand/);
		expect(ungradedDisplaySource).not.toMatch(/DELIBERATE, KNOWN twin/);
		expect(ungradedDisplaySource).not.toMatch(/A deliberately tiny leaf module \(no imports\)/);
	});

	it('LEG 3 — stays a leaf module: its ONLY import is the external package, no edge into src/', () => {
		// The documented reason ungraded-display.ts avoids imports is to keep every
		// formatter in src/tools/ able to depend on it without a cycle through the
		// scan orchestrator. An EXTERNAL-package import cannot create that cycle —
		// packages/dns-checks/src imports nothing outside relative paths, zod and
		// vitest — but the property is only preserved if no src/-relative import is
		// ever added here, which is what this pins.
		const importSpecifiers = [...ungradedDisplaySource.matchAll(/from\s*'([^']+)'/g)].map((m) => m[1]);
		expect(importSpecifiers.length).toBeGreaterThan(0);
		expect(importSpecifiers.filter((s) => s.startsWith('.'))).toEqual([]);
		expect([...new Set(importSpecifiers)]).toEqual(['@blackveil/dns-checks/scoring']);
	});
});
