// SPDX-License-Identifier: BUSL-1.1

/**
 * The SPF trust-surface multi-tenant platform catalog exists TWICE, and nothing
 * compared the two copies until this audit:
 *
 *   CORE   — `packages/dns-checks/src/checks/spf-trust-surface.ts`
 *   WORKER — `src/tools/spf-trust-surface.ts`
 *
 * The worker copy is a deliberate augmentation (issue #566): `check-spf.ts` runs
 * it as a post-processor that REPLACES the core-produced trust-surface findings,
 * because it carries a generic "unrecognized shared sender" heuristic the core
 * deliberately does not adopt (adopting it moves the multi-platform emission
 * threshold corpus-wide — an operator call). Two catalogs are therefore the
 * intended state for now; two catalogs that DRIFT are not.
 *
 * WHAT WENT WRONG (issue #572). Mailjet was added to the WORKER catalog in
 * PR #570 and was missing from the CORE catalog until release 3.42.0. Callers of
 * the bv-mcp worker were fine. DIRECT consumers of the published package were
 * not: bv-web-prod calls the package's `checkSPF`, never the worker wrapper, so
 * for months it silently under-counted the SPF trust surface for every Mailjet
 * sender. Nothing tripped, because no test compared the two catalogs. This file
 * is that test.
 *
 * HOW THE TWO CATALOGS ARE COMPARED, AND WHY.
 *
 * Enumeration is STATIC, comparison is BEHAVIOURAL — deliberately split, because
 * neither technique alone is sufficient:
 *
 *   - `MULTI_TENANT_PLATFORMS` is a module-private `const` Map on both sides. It
 *     is not exported and not enumerable through the public API, so a purely
 *     behavioural audit would have to guess candidate keys from a hand-written
 *     corpus — and a hand-written corpus is exactly the thing that fails to
 *     mention the ONE platform someone just added. That is the #572 failure mode
 *     reproduced inside its own regression test. So the keys are read out of the
 *     two source files (Vite `?raw`, the same technique as
 *     `completed-evidence-cross-package-parity.audit.test.ts`), which enumerates
 *     the catalogs COMPLETELY and needs no maintenance when one grows.
 *
 *   - The keys are then fed through each side's EXPORTED `analyzeTrustSurface`
 *     rather than compared as parsed text. Text equality of two Map literals
 *     would be brittle (formatting, comment drift, key ORDER — the maps are
 *     iterated in insertion order) and, worse, it would prove nothing about what
 *     a caller actually observes: it is recognition, not source text, that
 *     bv-web-prod depends on. Behaviour also covers the suffix-matching rule
 *     (`endsWith('.' + key)`), so a sub-host regression on one side is caught
 *     too. Exporting the private Maps purely to let a test read them was
 *     rejected: it widens the module's public API for a test's convenience, and
 *     it would still compare declarations rather than behaviour.
 *
 * Recognition means recognition BY NAME — a finding whose `metadata.platform` is
 * the platform's brand, not the worker's `unrecognized shared sender` sentinel.
 * This matters: the worker's generic heuristic matches any host carrying an
 * `spf` / `_spf` label, which covers a majority of the catalog keys
 * (`_spf.google.com`, `spf.protection.outlook.com`, …). A weaker "did the worker
 * emit any trust-surface finding?" assertion would therefore stay green if those
 * platforms were deleted from the worker catalog outright — the heuristic would
 * paper over the hole while the output silently degraded from a named provider
 * to an anonymous one. Comparing the NAME keeps the heuristic from masking
 * catalog drift, while still allowing the worker to recognise strictly more
 * hosts than the core does.
 *
 * TWO DIRECTIONS, and both are load-bearing:
 *
 *   LEG 1 (CORE ⊆ WORKER) — every platform the core names, the worker must name
 *     identically. This is a SUPERSET relation, not equality: the worker is
 *     allowed to recognise more (that is what the #566 heuristic is for), so
 *     asserting equality of BEHAVIOUR would fail by design.
 *
 *   LEG 2 (WORKER catalog ⊆ CORE catalog) — this is the direction #572 actually
 *     travelled, and leg 1 cannot see it. A platform added worker-side only is
 *     invisible to leg 1 forever while every direct package consumer under-counts.
 *     Leg 2 is still not behavioural equality: it sweeps only the worker's
 *     CATALOGED keys, so the generic heuristic (which owns no catalog entry) is
 *     untouched and stays free to recognise more. The worker file's own header
 *     frames its catalog as a temporary lead over the core "until the core
 *     catalog is updated + re-vendored" — leg 2 is what makes that lead a
 *     deliberate, test-breaking decision instead of a silent months-long gap.
 *
 * A negative control runs the SAME sweep against a deliberately drifted catalog
 * and requires it to be REPORTED. Without it, a parity assertion could sit green
 * forever because it compares nothing.
 */

import { describe, expect, it } from 'vitest';
import coreSource from '../../packages/dns-checks/src/checks/spf-trust-surface.ts?raw';
import workerSource from '../../src/tools/spf-trust-surface.ts?raw';
import { analyzeTrustSurface as coreAnalyzeTrustSurface } from '../../packages/dns-checks/src/checks/spf-trust-surface';
import { analyzeTrustSurface as workerAnalyzeTrustSurface } from '../../src/tools/spf-trust-surface';
import { createFinding } from '@blackveil/dns-checks/scoring';

/**
 * Structural shape both sides satisfy. Typed structurally rather than against
 * either side's `Finding` import so the audit never has to pick a "winning"
 * type — the point of the file is that neither side is authoritative over the
 * other.
 */
type TrustSurfaceAnalyzer = (spfRecord: string) => ReadonlyArray<{ readonly metadata?: Record<string, unknown> }>;

/** The worker's placeholder for a shared sender matched by heuristic rather than by catalog entry. */
const UNRECOGNIZED_SENTINEL = 'unrecognized shared sender';

/** Anti-vacuity floor: the catalogs have carried ~19 platforms since #572; a parse yielding far fewer is a broken parse. */
const MIN_EXPECTED_PLATFORMS = 15;

/**
 * Anchors that must survive any refactor of either catalog. Their job is to fail
 * a parse that "succeeds" with plausible-looking garbage, and to keep the #572
 * platform itself explicitly pinned on both sides.
 */
const REQUIRED_ANCHOR_KEYS = ['_spf.google.com', 'spf.protection.outlook.com', 'sendgrid.net', 'mailjet.com'] as const;

/**
 * Extract the `MULTI_TENANT_PLATFORMS` Map keys from a module's source text.
 *
 * Scoped to the Map literal (not the whole file) so an unrelated tuple elsewhere
 * in the module can never be mistaken for a catalog entry. Handles both the
 * single-line entry form and the prettier-wrapped multi-line form.
 */
function parseCatalogKeys(source: string, label: string): { keys: string[]; entryCount: number } {
	const blockMatch = /const MULTI_TENANT_PLATFORMS[\s\S]*?\n\]\);/.exec(source);
	if (!blockMatch) {
		throw new Error(
			`${label}: could not locate the MULTI_TENANT_PLATFORMS Map literal — this audit's source parse is broken, not the catalog`,
		);
	}
	const block = blockMatch[0];
	const keys = [...block.matchAll(/\[\s*'([^']+)'\s*,\s*\{/g)].map((m) => m[1]);
	// Independent count of the PlatformInfo records in the same block. If this
	// disagrees with the key count, the key regex missed an entry and every
	// downstream sweep is quietly incomplete.
	const entryCount = [...block.matchAll(/\brisk:\s*'/g)].length;
	return { keys, entryCount };
}

const core = parseCatalogKeys(coreSource, 'CORE packages/dns-checks/src/checks/spf-trust-surface.ts');
const worker = parseCatalogKeys(workerSource, 'WORKER src/tools/spf-trust-surface.ts');

/**
 * The brand name a given analyzer attaches to a host, or `undefined` when it does
 * not recognise it as a NAMED platform. The worker's generic-heuristic sentinel
 * counts as "not recognised" on purpose — see the header.
 */
function namedPlatformFor(analyze: TrustSurfaceAnalyzer, host: string): string | undefined {
	const findings = analyze(`v=spf1 include:${host} -all`);
	const named = findings.find((f) => f.metadata?.trustSurface === true && f.metadata?.platform !== UNRECOGNIZED_SENTINEL);
	const platform = named?.metadata?.platform;
	return typeof platform === 'string' ? platform : undefined;
}

/**
 * Every host form a catalog key must be recognised in: the key itself, and a
 * sub-host of it (the `endsWith('.' + key)` suffix rule both sides implement).
 */
function hostFormsFor(key: string): string[] {
	return [key, `eu.${key}`];
}

/**
 * Compare two analyzers over a key set and describe every disagreement in prose
 * that names the platform, the side that is missing it, and why it matters.
 *
 * Parameterised on the analyzers so the negative control below can point the
 * IDENTICAL sweep at a deliberately drifted catalog.
 */
function describeDivergences(
	keys: readonly string[],
	reference: TrustSurfaceAnalyzer,
	subject: TrustSurfaceAnalyzer,
	referenceLabel: string,
	subjectLabel: string,
	subjectFile: string,
	consequence: string,
): string[] {
	const messages: string[] = [];
	for (const key of keys) {
		for (const host of hostFormsFor(key)) {
			const expected = namedPlatformFor(reference, host);
			const actual = namedPlatformFor(subject, host);
			if (expected === actual) continue;
			if (expected === undefined) {
				// The reference does not name its own catalog key — a parse/matcher
				// fault in this audit or in the reference, not a drift finding.
				messages.push(
					`${host}: ${referenceLabel} does not recognise its own catalog key '${key}' (audit parse or matcher fault, investigate before trusting this file)`,
				);
				continue;
			}
			if (actual === undefined) {
				messages.push(
					`'${key}' (${expected}) is recognised by the ${referenceLabel} catalog but NOT by the ${subjectLabel} catalog — add it to ${subjectFile}. ${consequence} (failing host form: ${host})`,
				);
				continue;
			}
			messages.push(
				`'${key}' is named '${expected}' by ${referenceLabel} but '${actual}' by ${subjectLabel} — the two catalogs disagree on the platform's display name; reconcile them in ${subjectFile}. (host form: ${host})`,
			);
		}
	}
	return messages;
}

const CORE_CONSUMER_CONSEQUENCE =
	'Direct consumers of the published @blackveil/dns-checks package (bv-web-prod calls checkSPF, never the bv-mcp worker wrapper) will under-count the SPF trust surface until both catalogs carry it — that is issue #572, fixed in 3.42.0.';

const WORKER_OUTPUT_CONSEQUENCE =
	'check_spf output would stop naming this platform, degrading it to an anonymous "unrecognized shared sender" or dropping it from the trust surface entirely.';

describe('SPF trust-surface catalog parity (CORE ↔ WORKER, #572)', () => {
	it('LEG 0 — the source parse actually found both catalogs (anti-vacuity)', () => {
		// Every leg below sweeps these key lists. A silently empty or truncated
		// parse would make the whole file pass while comparing nothing.
		expect(
			core.keys.length,
			'CORE catalog parse returned too few keys — the regex no longer matches the Map literal',
		).toBeGreaterThanOrEqual(MIN_EXPECTED_PLATFORMS);
		expect(
			worker.keys.length,
			'WORKER catalog parse returned too few keys — the regex no longer matches the Map literal',
		).toBeGreaterThanOrEqual(MIN_EXPECTED_PLATFORMS);

		// Independent entry count per side: keys parsed must equal PlatformInfo
		// records present, or the key regex skipped an entry.
		expect(core.keys.length, 'CORE: parsed key count disagrees with the number of PlatformInfo records in the same Map literal').toBe(
			core.entryCount,
		);
		expect(worker.keys.length, 'WORKER: parsed key count disagrees with the number of PlatformInfo records in the same Map literal').toBe(
			worker.entryCount,
		);

		// No duplicate keys — a duplicate would make a Map entry unreachable and
		// would also inflate the counts above into a false match.
		expect([...new Set(core.keys)]).toHaveLength(core.keys.length);
		expect([...new Set(worker.keys)]).toHaveLength(worker.keys.length);

		for (const anchor of REQUIRED_ANCHOR_KEYS) {
			expect(core.keys, `CORE catalog lost the anchor key '${anchor}'`).toContain(anchor);
			expect(worker.keys, `WORKER catalog lost the anchor key '${anchor}'`).toContain(anchor);
		}
	});

	it('LEG 1 — every platform the CORE catalog names is named identically by the WORKER catalog', () => {
		// SUPERSET, not equality: the worker may recognise more hosts (the #566
		// generic heuristic). It may not recognise fewer of the CORE's platforms,
		// and it may not rename them.
		const divergences = describeDivergences(
			core.keys,
			coreAnalyzeTrustSurface as TrustSurfaceAnalyzer,
			workerAnalyzeTrustSurface as TrustSurfaceAnalyzer,
			'CORE (packages/dns-checks)',
			'WORKER (src/tools)',
			'src/tools/spf-trust-surface.ts',
			WORKER_OUTPUT_CONSEQUENCE,
		);
		expect(divergences, 'CORE→WORKER SPF trust-surface catalog drift').toEqual([]);
	});

	it('LEG 2 — every platform the WORKER catalog names is named identically by the CORE catalog (the #572 direction)', () => {
		// This is the leg that would have caught Mailjet in PR #570. Leg 1 cannot:
		// a worker-only entry is invisible to it, which is precisely how #572
		// survived for months. Only CATALOGED worker keys are swept, so the generic
		// heuristic — which has no catalog entry — remains free to match more.
		const divergences = describeDivergences(
			worker.keys,
			workerAnalyzeTrustSurface as TrustSurfaceAnalyzer,
			coreAnalyzeTrustSurface as TrustSurfaceAnalyzer,
			'WORKER (src/tools)',
			'CORE (packages/dns-checks)',
			'packages/dns-checks/src/checks/spf-trust-surface.ts',
			CORE_CONSUMER_CONSEQUENCE,
		);
		expect(divergences, 'WORKER→CORE SPF trust-surface catalog drift — package consumers under-count').toEqual([]);
	});

	it('NEGATIVE CONTROL — the sweep detects, and usefully names, a platform present on only one side', () => {
		// Reproduces the #572 shape in miniature: a catalog entry one side has and
		// the other does not. If this sweep cannot report that, legs 1 and 2 are
		// decoration.
		const driftedKey = 'esp-not-in-the-other-catalog.example';
		const driftedCatalogAnalyzer: TrustSurfaceAnalyzer = (record) => {
			const base = workerAnalyzeTrustSurface(record) as ReadonlyArray<{ readonly metadata?: Record<string, unknown> }>;
			if (!record.includes(driftedKey)) return base;
			return [
				...base,
				createFinding(
					'spf',
					'SPF delegates to shared platform: Example ESP',
					'info',
					'Synthetic entry used only by the negative control in this audit.',
					{
						trustSurface: true,
						platform: 'Example ESP',
					},
				),
			];
		};

		const found = describeDivergences(
			[driftedKey],
			driftedCatalogAnalyzer,
			coreAnalyzeTrustSurface as TrustSurfaceAnalyzer,
			'WORKER (src/tools)',
			'CORE (packages/dns-checks)',
			'packages/dns-checks/src/checks/spf-trust-surface.ts',
			CORE_CONSUMER_CONSEQUENCE,
		);

		expect(found.length).toBeGreaterThan(0);
		// The failure text must be actionable on its own: it has to name the
		// platform, name the file that is missing it, and say what breaks.
		expect(found[0]).toContain(driftedKey);
		expect(found[0]).toContain('Example ESP');
		expect(found[0]).toContain('packages/dns-checks/src/checks/spf-trust-surface.ts');
		expect(found[0]).toContain('under-count');
	});

	it('NEGATIVE CONTROL — the generic "unrecognized shared sender" heuristic cannot mask a missing catalog entry', () => {
		// The masking risk the header describes, pinned as behaviour rather than
		// prose. `spf.some-unknown-esp.example` carries an `spf` label, so the
		// worker's heuristic emits a trust-surface finding for it — yet it must NOT
		// count as a NAMED platform, or every `spf`-labelled catalog key could be
		// deleted from the worker with legs 1 and 2 still green.
		const heuristicOnlyHost = 'spf.some-unknown-esp.example';
		const emitted = workerAnalyzeTrustSurface(`v=spf1 include:${heuristicOnlyHost} -all`);
		expect(emitted.some((f) => f.metadata?.trustSurface === true)).toBe(true);
		expect(namedPlatformFor(workerAnalyzeTrustSurface as TrustSurfaceAnalyzer, heuristicOnlyHost)).toBeUndefined();
	});
});
