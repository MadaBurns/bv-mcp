// SPDX-License-Identifier: BUSL-1.1

/// <reference types="vite/client" />

/**
 * Structural audit: the scoring weight tables must live in exactly ONE place, and the
 * constants that are NOT read at runtime must not quietly acquire readers.
 *
 * WHY A RAW-SOURCE AUDIT AND NOT JUST A VALUE COMPARISON.
 * `DEFAULT_SCORING_CONFIG.profileWeights` used to restate all 324 per-profile weights as
 * literals, hand-synced with `PROFILE_WEIGHTS` in `scoring/profiles.ts` and guarded only by a
 * test comparing the two tables' VALUES. That guard is necessary but not sufficient: it fails
 * only AFTER someone has re-introduced the duplication and then edited one side, and the
 * obvious way to make it pass again is to copy the number across — which restores the
 * duplication permanently. A value test polices drift; it cannot police the SHAPE that makes
 * drift possible. The shape check has to read the source text.
 *
 * The duplication was a live score-divergence hazard, not an aesthetic one:
 * `getProfileWeights(profile, config)` reads the CONFIG copy while `getProfileWeights(profile)`
 * and `detectDomainContext` read the PROFILES copy, so a one-sided edit would make a domain's
 * score depend on which call site reached it.
 *
 * The value-equivalence half of this contract lives in `scoring-config.suite.ts`, where it
 * runs against BOTH the source and the built (`dist`/DTS) module surfaces. This file is the
 * structural half and reads source text only.
 */

import { describe, expect, it } from 'vitest';
import configSource from '../../scoring/config.ts?raw';
import profilesSource from '../../scoring/profiles.ts?raw';
import engineSource from '../../scoring/engine.ts?raw';
import { DEFAULT_SCORING_CONFIG, PROFILE_WEIGHTS } from '../../scoring';
import { CATEGORY_TIERS } from '../../types';

/** The 6 profile names, i.e. the keys a restated weight table would have to use. */
const PROFILE_NAMES = ['mail_enabled', 'enterprise_mail', 'non_mail', 'web_only', 'minimal', 'authoritative_dns_infra'] as const;

/**
 * A profile name in OBJECT-KEY position opening a table — `mail_enabled: {`.
 *
 * This is the exact shape a restated weight table takes, and the only shape it can take:
 * `Record<DomainProfile, …>` forces every profile name to appear as a key, and a weight table
 * is an object literal. Deliberately NOT a blanket ban on the profile NAMES appearing in
 * config.ts — they legitimately appear there in prose (the doc comment listing the 6 profiles)
 * and would appear in any future type annotation, neither of which can produce `name: {`.
 *
 * The `(?!\s*importance\b)` lookahead resolves the one genuine ambiguity: `authoritative_dns_infra`
 * is BOTH a `DomainProfile` and a `CheckCategory`, so `authoritative_dns_infra: { importance: 0 }`
 * — a single category ENTRY inside `IMPORTANCE_WEIGHTS`/`PROFILE_WEIGHTS` — is not a profile
 * table and must not be flagged. A real weight table's first key is always a category name,
 * never `importance`.
 */
const PROFILE_WEIGHT_TABLE = new RegExp(String.raw`^\s*(${PROFILE_NAMES.join('|')})\s*:\s*\{(?!\s*importance\b)`, 'gm');

/**
 * Every non-test source file in the package, keyed by path, so the "no new readers" sweep
 * covers files that do not exist yet. A named-import list would silently miss them.
 *
 * The `__tests__` tree is excluded via a NEGATIVE GLOB rather than a path filter: Vite
 * normalizes glob keys relative to this file, so a sibling suite resolves to `./x.suite.ts`
 * with no `__tests__` segment left in the key to filter on. Test files legitimately name the
 * dead constants (that is what they assert about), so leaving them in makes every sweep below
 * fail on its own fixtures.
 */
const PACKAGE_SOURCES = import.meta.glob(['../../**/*.ts', '!../../__tests__/**'], {
	query: '?raw',
	import: 'default',
	eager: true,
}) as Record<string, string>;

/** Path suffix match — glob keys are relative to this test file. */
function sourcesExcept(...allowedSuffixes: string[]): Array<[string, string]> {
	return Object.entries(PACKAGE_SOURCES).filter(([path]) => !allowedSuffixes.some((suffix) => path.endsWith(suffix)));
}

describe('profile-weight SSOT', () => {
	it('sweeps a non-empty set of package sources', () => {
		// Non-vacuity guard: a glob that resolves to nothing would make every sweep below pass
		// for the wrong reason.
		const swept = sourcesExcept();
		expect(swept.length).toBeGreaterThan(10);
		expect(swept.map(([p]) => p).some((p) => p.endsWith('/scoring/config.ts'))).toBe(true);
	});

	it('detects a profile weight table where one really is declared (regex is not vacuous)', () => {
		// profiles.ts holds the single real table. If this stops matching, the ban below has
		// silently become a no-op and would not catch a restatement in config.ts either.
		const declared = profilesSource.match(PROFILE_WEIGHT_TABLE) ?? [];
		const names = new Set(declared.map((m) => m.trim().split(':')[0]));
		for (const profile of PROFILE_NAMES) {
			expect(names, `profiles.ts should declare a ${profile} table`).toContain(profile);
		}
	});

	it('config.ts restates NO profile weight table — it derives them', () => {
		const restated = configSource.match(PROFILE_WEIGHT_TABLE) ?? [];
		expect(
			restated,
			`config.ts must not restate per-profile weight tables (found: ${restated.join(', ')}). ` +
				'Derive from PROFILE_WEIGHTS in scoring/profiles.ts instead — a second copy is how the two ' +
				'getProfileWeights() call paths start scoring the same domain differently.',
		).toEqual([]);
	});

	it('config.ts derives profileWeights from the PROFILE_WEIGHTS import', () => {
		expect(configSource).toMatch(/import\s*\{\s*PROFILE_WEIGHTS\s*\}\s*from\s*'\.\/profiles'/);
		expect(configSource).toContain('profileWeights: deriveDefaultProfileWeights()');
	});

	it('no OTHER package source declares a profile weight table', () => {
		for (const [path, source] of sourcesExcept('/scoring/profiles.ts')) {
			const restated = source.match(PROFILE_WEIGHT_TABLE) ?? [];
			expect(restated, `${path} must not declare per-profile weight tables`).toEqual([]);
		}
	});

	it('the derived table is complete — every category, every profile', () => {
		const categories = Object.keys(CATEGORY_TIERS).sort();
		for (const profile of PROFILE_NAMES) {
			const derived = DEFAULT_SCORING_CONFIG.profileWeights[profile];
			expect(Object.keys(derived).sort(), `${profile} must weight every CheckCategory`).toEqual(categories);
			for (const [category, weight] of Object.entries(derived)) {
				expect(typeof weight, `${profile}.${category} must be a number`).toBe('number');
				expect(weight, `${profile}.${category} must be finite`).toBe(
					PROFILE_WEIGHTS[profile][category as keyof typeof CATEGORY_TIERS].importance,
				);
			}
		}
	});
});

describe('dead scoring constants gain no new readers', () => {
	/**
	 * These are exported on a PUBLISHED npm surface (`@blackveil/dns-checks/scoring`) but read
	 * by nothing at runtime. They were kept rather than deleted because removal is a breaking
	 * change for external consumers; the cost of keeping them is that a future edit can wire
	 * one back in and get scoring behaviour that only fires on some call paths. This sweep
	 * fails if a reader appears outside the declaration site and the barrel re-export.
	 */
	const DEAD_EXPORTS: Array<{ name: string; allowed: string[] }> = [
		{ name: 'CORE_WEIGHTS', allowed: ['/scoring/engine.ts', '/scoring/index.ts'] },
		{ name: 'PROTECTIVE_WEIGHTS', allowed: ['/scoring/engine.ts', '/scoring/index.ts'] },
	];

	it.each(DEAD_EXPORTS)('$name is referenced only by its declaration and the barrel', ({ name, allowed }) => {
		// Word-boundary match, so PROTECTIVE_WEIGHTS never counts as a CORE_WEIGHTS hit and
		// vice-versa (`CORE_WEIGHTS` is not a substring of `PROTECTIVE_WEIGHTS`, but a future
		// `X_CORE_WEIGHTS` would be).
		const pattern = new RegExp(String.raw`\b${name}\b`);
		const offenders = sourcesExcept(...allowed)
			.filter(([, source]) => pattern.test(source))
			.map(([path]) => path);
		expect(offenders, `${name} is NOT read at runtime — a new reference in ${offenders.join(', ')} needs a deliberate decision`).toEqual(
			[],
		);
	});

	it('ScoringConfig.providerDkimConfidence is touched only by config.ts', () => {
		const offenders = sourcesExcept('/scoring/config.ts')
			.filter(([, source]) => /\bproviderDkimConfidence\b/.test(source))
			.map(([path]) => path);
		expect(
			offenders,
			'providerDkimConfidence is parsed and returned but never consumed — provider confidence reaches ' +
				'the scorer via finding.metadata.providerConfidence. New readers in: ' +
				offenders.join(', '),
		).toEqual([]);
	});

	it('ScoringConfig.weights is read only by the legacy migration in config.ts', () => {
		const pattern = /\b(?:config|cfg|DEFAULT_SCORING_CONFIG|parsed)\.weights\b/;
		const offenders = sourcesExcept('/scoring/config.ts')
			.filter(([, source]) => pattern.test(source))
			.map(([path]) => path);
		expect(
			offenders,
			`ScoringConfig.weights has no reader outside parseScoringConfig's migration. Found in: ${offenders.join(', ')}`,
		).toEqual([]);
	});

	it('the false "used by the three-tier scoring formula" claim is gone and both are marked deprecated', () => {
		// The original doc comments asserted these drive scoring. They do not, and that claim is
		// precisely what would make a future maintainer edit them expecting a score to move.
		expect(engineSource).not.toMatch(/CORE_WEIGHTS[\s\S]{0,400}?Used by the three-tier scoring formula/);
		expect(engineSource).not.toContain('Used by the three-tier scoring formula');

		for (const name of ['CORE_WEIGHTS', 'PROTECTIVE_WEIGHTS']) {
			const declIndex = engineSource.indexOf(`export const ${name}`);
			expect(declIndex, `${name} declaration not found`).toBeGreaterThan(-1);
			// The doc block immediately preceding the declaration must carry the deprecation.
			const docBlock = engineSource.slice(Math.max(0, declIndex - 1200), declIndex);
			expect(docBlock, `${name} must be marked @deprecated`).toContain('@deprecated');
			expect(docBlock, `${name} must say plainly that it is not read at runtime`).toContain('NOT read at runtime');
		}
	});

	it('IMPORTANCE_WEIGHTS is documented as fix-plan ordering, NOT scoring', () => {
		// It is genuinely live (generate-fix-plan.ts ranks remediation by it) but misnamed, and
		// its old @deprecated note pointed at the two constants that are actually dead.
		const declIndex = engineSource.indexOf('export const IMPORTANCE_WEIGHTS');
		expect(declIndex).toBeGreaterThan(-1);
		const docBlock = engineSource.slice(Math.max(0, declIndex - 1200), declIndex);
		expect(docBlock).toMatch(/REMEDIATION ORDERING|remediation/i);
		expect(docBlock).not.toMatch(/@deprecated\s+Use CORE_WEIGHTS/);
	});
});
