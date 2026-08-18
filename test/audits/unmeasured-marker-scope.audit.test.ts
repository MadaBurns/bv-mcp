// SPDX-License-Identifier: BUSL-1.1
/**
 * The halt condition for #695's fix, enforced rather than documented.
 *
 * `markUnmeasured` (the dispatch chokepoint in `src/handlers/tools.ts`) stamps
 * `checkStatus: 'error'` onto any result whose findings carry an unmeasured marker.
 * For the recon families that is exactly right — they are `scanIncluded: false`, so
 * nothing downstream scores them.
 *
 * On a SCANNED check the same stamp would be a scoring change: the engine excludes
 * `checkStatus`-tagged categories as transient failures and renormalises the
 * remaining weights, so every customer scanning that domain would be re-graded.
 * That is an operator decision (`SCORING_MODEL_VERSION`), never a side effect of a
 * correctness fix — and prose did not hold the line last time, which is why this is
 * a test.
 *
 * Fails the build if an unmeasured/refusal marker appears in a tool that
 * `scan_domain` runs.
 */
import { describe, expect, it } from 'vitest';
import { SCAN_CATEGORIES } from '../../src/tools/scan-domain';
import { UNMEASURED_MARKERS, ACCESS_REFUSAL_MARKERS } from '../../src/lib/unmeasured-result';

// The Workers test pool sandboxes `node:fs`, so sources are read the way the sibling
// metadata audit reads them: Vite's raw glob, resolved at transform time.
interface GlobbingImportMeta {
	glob(patterns: string[], options: { eager: true; query: '?raw'; import: 'default' }): Record<string, string>;
}

const SOURCES = (import.meta as unknown as GlobbingImportMeta).glob(['../../src/tools/**/*.ts'], {
	eager: true,
	query: '?raw',
	import: 'default',
});

const MARKERS = [...UNMEASURED_MARKERS, ...ACCESS_REFUSAL_MARKERS];

/** Strip comments so a marker NAMED in an explanatory comment is not read as an emission. */
function stripComments(src: string): string {
	return src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
}

describe('unmeasured-marker scope', () => {
	it('no scan-included tool emits an unmeasured or refusal marker', () => {
		// SCAN_CATEGORIES is the set scan_domain actually dispatches (keys of CHECK_DISPATCH),
		// which is the set whose scores would move — a stronger anchor than the declared
		// `scanIncluded` flag.
		const scanned = new Set<string>(SCAN_CATEGORIES as unknown as string[]);

		const offenders: string[] = [];

		for (const [path, raw] of Object.entries(SOURCES)) {
			const file = path.split('/').pop() ?? path;
			const slug = file
				.replace(/^check-/, '')
				.replace(/\.ts$/, '')
				.replace(/-/g, '_');
			if (!scanned.has(slug)) continue;
			const src = stripComments(raw);
			for (const marker of MARKERS) {
				if (new RegExp(`\\b${marker}\\s*:\\s*true`).test(src)) {
					offenders.push(`${file} emits \`${marker}: true\` — stamping checkStatus on a SCORED category re-grades customers`);
				}
			}
		}

		// Guard against the guard silently covering nothing (a glob or naming change).
		expect(Object.keys(SOURCES).length).toBeGreaterThan(20);

		expect(offenders).toEqual([]);
	});

	it('the marker vocabulary is non-empty and the two classes stay disjoint', () => {
		// A merge that emptied either list would silently disable the guard above.
		expect(UNMEASURED_MARKERS.length).toBeGreaterThan(0);
		expect(ACCESS_REFUSAL_MARKERS.length).toBeGreaterThan(0);
		const overlap = UNMEASURED_MARKERS.filter((m) => (ACCESS_REFUSAL_MARKERS as readonly string[]).includes(m));
		// The classes drive DIFFERENT handling — checkStatus vs isError. A marker in both
		// would get an availability shape applied to an authorization refusal, which is the
		// retry-loop the refusal path exists to avoid.
		expect(overlap).toEqual([]);
	});
});
