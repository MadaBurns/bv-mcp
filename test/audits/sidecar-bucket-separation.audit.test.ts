// SPDX-License-Identifier: BUSL-1.1

/**
 * Audit: brand-discovery sidecar reports must keep the Option-3 vendor split
 * disjoint from the Option-2 legacy `buckets.shadowIt` compat surface.
 *
 * Schema-v4 sidecars (`reports/*-discovery-report.json`) carry BOTH:
 *   - Top-level Option-3 buckets:  `registrarSprawl[]`, `vendorDependencies[]`
 *   - Legacy Option-2 compat:      `buckets.{shadowIt,consolidated,indeterminate,impersonation}`
 *
 * Per the v4 design, vendor dependencies live in `buckets.indeterminate` and
 * MUST NOT leak into `buckets.shadowIt`. The legacy `shadowIt` bucket exists
 * solely to mirror the new top-level `registrarSprawl[]`. If those two ever
 * diverge — or a vendor appears in shadowIt — downstream PDF/Markdown rendering
 * and customer-visible categorisation regress to the pre-split shape.
 *
 * Invariants enforced (per file):
 *   1. `vendorDependencies` and `buckets.shadowIt` are disjoint by domain.
 *   2. The domain set of `buckets.shadowIt` equals the domain set of `registrarSprawl`.
 *   3. Both buckets are present (arrays, never null) in every sidecar.
 *
 * Empty arrays (e.g. blackveilsecurity.com, example.com, smoke fixtures) satisfy
 * all three invariants trivially.
 *
 * Per testing-methodology.md principle 4 — audit tests replace review checklists.
 */

import { describe, expect, it } from 'vitest';

const SIDECAR_FILES = import.meta.glob('/reports/*-discovery-report.json', {
	query: '?raw',
	eager: true,
}) as Record<string, { default: string }>;

interface CandidateLike {
	domain?: unknown;
}

interface SidecarShape {
	target?: unknown;
	registrarSprawl?: unknown;
	vendorDependencies?: unknown;
	buckets?: {
		shadowIt?: unknown;
		consolidated?: unknown;
		indeterminate?: unknown;
		impersonation?: unknown;
	};
}

function rel(absKey: string): string {
	return absKey.startsWith('/') ? absKey.slice(1) : absKey;
}

function domainSet(arr: unknown): Set<string> {
	if (!Array.isArray(arr)) return new Set();
	const out = new Set<string>();
	for (const item of arr as CandidateLike[]) {
		if (item && typeof item.domain === 'string' && item.domain.length > 0) {
			out.add(item.domain.toLowerCase());
		}
	}
	return out;
}

const entries = Object.entries(SIDECAR_FILES).map(([path, mod]) => {
	const parsed = JSON.parse(mod.default) as SidecarShape;
	return { path: rel(path), parsed };
});

describe('sidecar vendor / shadowIt bucket separation', () => {
	it('finds at least one discovery-report sidecar to audit', () => {
		expect(
			entries.length,
			'expected reports/*-discovery-report.json sidecars on disk (run brand-discovery first)',
		).toBeGreaterThan(0);
	});

	for (const { path, parsed } of entries) {
		describe(path, () => {
			it('exposes registrarSprawl[] and vendorDependencies[] as arrays (invariant 3)', () => {
				expect(
					Array.isArray(parsed.registrarSprawl),
					`${path}: registrarSprawl must be an array (got ${typeof parsed.registrarSprawl})`,
				).toBe(true);
				expect(
					Array.isArray(parsed.vendorDependencies),
					`${path}: vendorDependencies must be an array (got ${typeof parsed.vendorDependencies})`,
				).toBe(true);
				expect(
					parsed.buckets && Array.isArray(parsed.buckets.shadowIt),
					`${path}: buckets.shadowIt must be an array (got ${typeof parsed.buckets?.shadowIt})`,
				).toBe(true);
			});

			it('keeps vendorDependencies disjoint from legacy buckets.shadowIt (invariant 1)', () => {
				const vendors = domainSet(parsed.vendorDependencies);
				const shadow = domainSet(parsed.buckets?.shadowIt);
				const overlap = [...vendors].filter((d) => shadow.has(d));
				expect(
					overlap,
					`${path}: vendor domains leaked into buckets.shadowIt — Option-3 split broken: ${overlap.join(', ')}`,
				).toEqual([]);
			});

			it('mirrors buckets.shadowIt onto registrarSprawl by domain (invariant 2)', () => {
				const sprawl = domainSet(parsed.registrarSprawl);
				const shadow = domainSet(parsed.buckets?.shadowIt);
				const onlyInSprawl = [...sprawl].filter((d) => !shadow.has(d));
				const onlyInShadow = [...shadow].filter((d) => !sprawl.has(d));
				expect(
					onlyInSprawl,
					`${path}: domains in registrarSprawl missing from buckets.shadowIt: ${onlyInSprawl.join(', ')}`,
				).toEqual([]);
				expect(
					onlyInShadow,
					`${path}: domains in buckets.shadowIt missing from registrarSprawl: ${onlyInShadow.join(', ')}`,
				).toEqual([]);
			});
		});
	}
});
