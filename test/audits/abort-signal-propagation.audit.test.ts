// SPDX-License-Identifier: BUSL-1.1

/**
 * Audit test pinning the AbortSignal-into-fetch contract (.dev/abort-signal-plan.md).
 *
 * Replaces a manual-review checklist: once we plumbed `signal` through every
 * top-level fetch in the discovery pipeline so audit-budget aborts actually
 * cancel in-flight work, this test fires whenever a future change adds a new
 * `fetch(url, { ... })` call without a `signal:` field. Pre-existing call
 * sites that already accept signal are immune; new arrivals must follow suit.
 *
 * Per testing methodology principle 4: audit tests replace review checklists.
 * Recurring code review catch → write an audit test.
 */

import { describe, it, expect } from 'vitest';

const discoveryModules = import.meta.glob('../../src/tenants/discovery/*.ts', {
	query: '?raw',
	import: 'default',
	eager: true,
}) as Record<string, string>;

const FILES: ReadonlyArray<readonly [string, string]> = Object.entries(discoveryModules)
	.map(([path, content]) => [path.split('/').pop()!, content] as const)
	.sort(([a], [b]) => a.localeCompare(b));

/**
 * Files exempt from the signal-required rule. Each entry has a one-line
 * reviewer-blessed reason. The list is intentionally empty at landing —
 * any future addition needs an explicit justification.
 */
const EXEMPT: ReadonlySet<string> = new Set<string>([]);

describe('abort-signal-propagation (audit)', () => {
	it('every fetch() call in src/tenants/discovery passes a signal in the RequestInit', () => {
		// Match `fetch|safeFetch|fetchFn|dohFn(<arg>, {` patterns at the start of
		// a RequestInit object. Bare `fetch(url)` with no init is exempt — there's
		// no init to thread signal through and most of those are local mocks.
		const violations: Array<{ file: string; line: number; snippet: string }> = [];
		for (const [name, content] of FILES) {
			if (EXEMPT.has(name)) continue;
			const lines = content.split('\n');
			lines.forEach((text, idx) => {
				const m = text.match(/\b(?:fetch|safeFetch|fetchFn|dohFn)\s*\([^,)]+,\s*\{/);
				if (!m) return;
				// `signal:` may span subsequent lines in the RequestInit. Read 12
				// lines forward — far enough for any reasonable init block.
				const window = lines.slice(idx, idx + 12).join('\n');
				if (/signal\s*:/.test(window)) return;
				violations.push({ file: name, line: idx + 1, snippet: text.trim().slice(0, 120) });
			});
		}
		const msg = violations
			.map((v) => `  ${v.file}:${v.line}  ${v.snippet}`)
			.join('\n');
		expect(
			violations,
			`abort-signal-propagation audit failed — found ${violations.length} fetch call(s) without 'signal:':\n${msg}\n\n` +
				`Fix: thread the caller's AbortSignal into the RequestInit, e.g. fetch(url, { signal: opts?.signal, ... }).\n` +
				`If the call genuinely cannot accept a caller signal, add the file to EXEMPT with a one-line reason.`,
		).toEqual([]);
	});
});
