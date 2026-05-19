// SPDX-License-Identifier: BUSL-1.1

/**
 * Phase 2a of registrar-coverage-tdd-plan.md — audit test pinning the
 * registrar metadata invariant in brand-audit-pipeline.ts.
 *
 * Invariant: every finding builder that sets `registrar` in metadata MUST also
 * set `registrarSource`. When `registrarSource === 'lookup_failed'` the same
 * builder MUST also set `registrarFailureReason` (consumed by Phase 2b retry
 * detection and Phase 3 classification).
 *
 * Per testing methodology principle 4: audit tests replace review checklists.
 * Recurring code review catch → write an audit test. This codifies the
 * Phase 1 contract (lookup_failed always carries a reason) into a structural
 * guard so future finding builders don't silently drop the reason field.
 */

import { describe, it, expect } from 'vitest';

/**
 * Scoped to brand-audit-pipeline.ts where all finding builders are routed
 * through `createFinding(...)` with metadata literals that follow this file's
 * conventions. `check-rdap-lookup.ts` has its own contract pinned by
 * `test/check-rdap-lookup-signal.test.ts` (pre-aborted block carries
 * registrarFailureReason) and `test/check-rdap-lookup-lookup-failed.test.ts`
 * (every lookup_failed branch); it uses a different internal type
 * (`{ source, failureReason }`) that this regex would misread as builder sites.
 */
const trackedSources = import.meta.glob('../../src/lib/brand-audit-pipeline.ts', {
	query: '?raw',
	import: 'default',
	eager: true,
}) as Record<string, string>;

const sourceEntries: Array<readonly [string, string]> = Object.entries(trackedSources).map(
	([path, content]) => [path.split('/').pop()!, content] as const,
);

describe('registrar-finding-metadata (audit)', () => {
	it('every createFinding that sets `registrar` also sets `registrarSource`', () => {
		// Combine the source bodies into one corpus annotated by file so a
		// violation reports the originating file.
		const corpus = sourceEntries.map(([file, body]) => ({ file, lines: body.split('\n') }));
		const violations: Array<{ file: string; line: number; snippet: string }> = [];
		for (const { file, lines } of corpus) {
			lines.forEach((text, idx) => {
				// Match lines like `registrar: lookup.registrar,` or `targetRegistrar: targetLookup.registrar,`
				// — the source key, not the IanaId/Source/Family/Failure variants.
				const m = text.match(/\b(registrar|targetRegistrar)\s*:/);
				if (!m) return;
				const keyName = m[1];
				if (/registrar(IanaId|Source|Family|FailureReason)/.test(text)) return;
				// 15-line window in either direction covers any metadata object.
				const window = lines.slice(Math.max(0, idx - 5), idx + 15).join('\n');
				// Exempt the classifier-input struct `TargetContext` — its block declares
				// `registrarFamily:` which a finding-metadata object never does.
				if (/registrarFamily\s*:/.test(window)) return;
				const sourceKey = keyName === 'targetRegistrar' ? 'targetRegistrarSource' : 'registrarSource';
				if (!new RegExp(`\\b${sourceKey}\\s*:`).test(window)) {
					violations.push({ file, line: idx + 1, snippet: text.trim().slice(0, 120) });
				}
			});
		}
		const msg = violations.map((v) => `  ${v.file}:${v.line}  ${v.snippet}`).join('\n');
		expect(
			violations,
			`metadata invariant: every 'registrar'-bearing builder must also set 'registrarSource':\n${msg}`,
		).toEqual([]);
	});

	it('every site that sets `registrarSource: ...lookup_failed...` also sets `registrarFailureReason`', () => {
		const violations: Array<{ file: string; line: number; snippet: string }> = [];
		for (const [file, body] of sourceEntries) {
			const lines = body.split('\n');
			lines.forEach((text, idx) => {
				// We only care about *builder* sites — places that ASSIGN
				// `'lookup_failed'` as the value of a metadata key (e.g.
				// `registrarSource: 'lookup_failed'`). Comparison sites
				// (`x === 'lookup_failed'`) and enum declarations are predicates,
				// not builders.
				if (!/:\s*'lookup_failed'/.test(text)) return;
				const window = lines.slice(Math.max(0, idx - 2), idx + 6).join('\n');
				if (/registrarFailureReason/.test(window)) return;
				violations.push({ file, line: idx + 1, snippet: text.trim().slice(0, 120) });
			});
		}
		const msg = violations.map((v) => `  ${v.file}:${v.line}  ${v.snippet}`).join('\n');
		expect(
			violations,
			`metadata invariant: every 'lookup_failed' branch must also propagate 'registrarFailureReason':\n${msg}`,
		).toEqual([]);
	});
});
