// SPDX-License-Identifier: BUSL-1.1

/**
 * Hand-built `ScanScore` test literals must carry the `evidence` field.
 *
 * `ScanScore.evidence` is REQUIRED by the type — but `test/` is excluded from
 * `tsconfig.json`, so an `{ ... } as ScanScore` literal in a spec is never
 * typechecked and silently drops the field. During the evidence-gate slice,
 * 21+ fixture sites were found (by grep) feeding evidence-less scores into
 * formatters and comparators — fixtures that no longer model what production
 * produces, exercising code against a shape the engine cannot emit. The cast
 * can't enforce the contract, so this audit does.
 *
 * Rules:
 *   - `{ ... } as ScanScore` — the literal must contain an `evidence:` key, or
 *     a spread (`...`) that can carry one from an audited-elsewhere source.
 *   - `as unknown as ScanScore` — the DOCUMENTED escape hatch for fixtures
 *     that are deliberately malformed (defensive-handling tests). Skipped, on
 *     the same logic as an eslint-disable: the double cast is a visible,
 *     greppable declaration of intent where a plain cast is an accident.
 *   - `as ScanScore['...']` (indexed access) and identifier casts
 *     (`value as ScanScore`, no closing brace before the cast) are not object
 *     literals and are skipped.
 */

import { describe, it, expect } from 'vitest';

// The Workers pool has no `fs`; the corpus is inlined at build time (same
// mechanism as `ungraded-representation.audit.test.ts`). BOTH un-typechecked
// test trees: `test/**` (excluded by root tsconfig) and the vendored core's
// `__tests__/**` (excluded by the package tsconfig).
const SOURCES = import.meta.glob(['../**/*.ts', '../../packages/dns-checks/src/__tests__/**/*.ts'], {
	eager: true,
	query: '?raw',
	import: 'default',
}) as Record<string, string>;

/** This file names the pattern it hunts, so it must not scan itself. */
const SELF = '../audits/scanscore-fixture-evidence.audit.test.ts';

/**
 * Given the index of the closing `}` of an object literal, walk backwards to
 * the matching `{` and return the literal's text. Depth counting only — good
 * enough for test fixtures, where braces inside strings are balanced or absent.
 */
function extractLiteralEndingAt(source: string, closeBraceIndex: number): string | null {
	let depth = 0;
	for (let i = closeBraceIndex; i >= 0; i--) {
		const ch = source[i];
		if (ch === '}') depth++;
		else if (ch === '{') {
			depth--;
			if (depth === 0) return source.slice(i, closeBraceIndex + 1);
		}
	}
	return null;
}

describe('ScanScore fixture evidence audit', () => {
	it('every plain `as ScanScore` object literal in the un-typechecked test trees carries `evidence`', () => {
		const CAST = /\bas\s+(unknown\s+as\s+)?ScanScore\b(?!\s*\[)/g;
		const offenders: string[] = [];
		let literalsChecked = 0;
		let escapeHatches = 0;

		for (const [path, source] of Object.entries(SOURCES)) {
			if (path === SELF) continue;
			for (const match of source.matchAll(CAST)) {
				if (match[1] !== undefined) {
					// `as unknown as ScanScore` — deliberate malformed fixture.
					escapeHatches++;
					continue;
				}
				// Find the last non-whitespace char before the cast; only a `}`
				// means the cast is applied to an object literal.
				let i = match.index - 1;
				while (i >= 0 && /\s/.test(source[i])) i--;
				if (i < 0 || source[i] !== '}') continue;

				const literal = extractLiteralEndingAt(source, i);
				const line = source.slice(0, match.index).split('\n').length;
				if (literal === null) {
					offenders.push(`${path}:${line} — unbalanced braces before \`as ScanScore\` (audit could not extract the literal)`);
					continue;
				}
				literalsChecked++;
				if (!/\bevidence\s*:/.test(literal) && !literal.includes('...')) {
					offenders.push(
						`${path}:${line} — \`as ScanScore\` literal without an \`evidence\` field. ` +
							`Add \`evidence: { attempted, completed, ratio }\` (or \`computeScanEvidence(checks)\`); ` +
							`use \`as unknown as ScanScore\` ONLY for a deliberately malformed fixture.`,
					);
				}
			}
		}

		// Non-vacuity: the corpus and both branches of the classifier must have
		// real work to do, or every assertion above passes on nothing.
		expect(Object.keys(SOURCES).length).toBeGreaterThan(250);
		expect(literalsChecked).toBeGreaterThanOrEqual(10);
		expect(escapeHatches).toBeGreaterThanOrEqual(1);

		expect(offenders).toEqual([]);
	});
});
