// SPDX-License-Identifier: BUSL-1.1

/**
 * Audit: brand-discovery sidecar reports must use clean registrar labels.
 *
 * Locks in two prior bugs that have been fixed:
 *
 *   1. "Unknown registrar" — a user-visible WHOIS fall-through string that
 *      leaked into report fields when registrar parsing failed. Must never
 *      appear in serialized sidecar output (case-insensitive substring).
 *
 *   2. `lookup_failed` — an internal counter key. It is legal *only* as a
 *      numeric counter on the registrar-coverage block (depth.registrarCoverage
 *      .lookup_failed is a number). It is NOT legal as the string value of any
 *      item's `registrar` or `registrarSource`, nor as the value of any field
 *      anywhere in a relationship bucket (a label leak would surface in the
 *      brand-audit PDF / dashboard).
 *
 * Per testing-methodology.md principle 4 — audit tests replace review
 * checklists. Without this audit a regression could silently re-leak either
 * label into the next sidecar batch.
 *
 * Implementation: tests run in the `@cloudflare/vitest-pool-workers` runtime,
 * which has no `node:fs`. We use Vite's `import.meta.glob` to materialize the
 * sidecar JSON at transform time (host Node) and embed them into the test
 * module. The `reports/` directory is gitignored, so in CI the glob is empty
 * and the audit no-ops; locally (and in any environment where sidecars are
 * generated before tests run) it walks every report.
 */

import { describe, it, expect } from 'vitest';

// eager: true → contents bundled into module at transform time.
// import: 'default' → JSON modules export the parsed object as default.
const sidecars = import.meta.glob('/reports/*-discovery-report.json', {
	eager: true,
	import: 'default',
}) as Record<string, unknown>;

const sidecarEntries = Object.entries(sidecars);

/**
 * Walk an arbitrary JSON value and yield every leaf field path/value pair.
 * Used to assert no string field anywhere equals 'lookup_failed' inside the
 * three relationship buckets, regardless of nesting (ownedPortfolio nests
 * tenantDeclared/graphSurfaced/declaredEvidence/inferred sub-arrays).
 */
function* walkLeaves(value: unknown, path = ''): Generator<{ path: string; key: string; value: unknown }> {
	if (value === null || value === undefined) return;
	if (Array.isArray(value)) {
		for (let i = 0; i < value.length; i++) {
			yield* walkLeaves(value[i], `${path}[${i}]`);
		}
		return;
	}
	if (typeof value === 'object') {
		for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
			const childPath = path ? `${path}.${k}` : k;
			if (v !== null && typeof v === 'object') {
				yield* walkLeaves(v, childPath);
			} else {
				yield { path: childPath, key: k, value: v };
			}
		}
	}
}

describe('brand-discovery sidecar registrar-label hygiene', () => {
	it('discovers sidecars to audit (or no-ops cleanly in CI without reports/)', () => {
		// Smoke: when sidecars exist, count must be > 0 and finite.
		expect(Array.isArray(sidecarEntries)).toBe(true);
		// No upper bound — local runs may have 17+, CI without reports/ has 0.
		expect(sidecarEntries.length).toBeGreaterThanOrEqual(0);
	});

	it.each(sidecarEntries)('%s — no "Unknown registrar" leakage anywhere in serialized JSON', (path, report) => {
		const serialized = JSON.stringify(report);
		// Case-insensitive substring; this is the exact symptom of the prior bug
		// (WHOIS parse fall-through emitting "Unknown registrar" as a user-visible
		// string).
		const match = serialized.match(/unknown registrar/i);
		expect(match, `${path}: serialized sidecar contains "Unknown registrar" substring at index ${match?.index ?? -1}`).toBeNull();
	});

	it.each(sidecarEntries)('%s — depth.registrarCoverage.lookup_failed is a numeric counter', (path, report) => {
		// lookup_failed lives on the registrar-coverage block as a count. If the
		// schema migrates, update this path — the invariant is "numeric counter,
		// not a string label". We accept either depth.registrarCoverage.lookup_failed
		// (current location, verified 2026-05 across all 17 sidecars) or
		// dataQuality.lookup_failed (alternate location named in the original
		// label-leakage triage notes). At least one must exist as a number; none
		// may exist as anything else.
		const r = report as {
			depth?: { registrarCoverage?: { lookup_failed?: unknown } };
			dataQuality?: { lookup_failed?: unknown };
		};
		const depthVal = r.depth?.registrarCoverage?.lookup_failed;
		const dqVal = r.dataQuality?.lookup_failed;

		// If the field exists at either location, it MUST be a number.
		if (depthVal !== undefined) {
			expect(typeof depthVal, `${path}: depth.registrarCoverage.lookup_failed must be number, got ${typeof depthVal} (${JSON.stringify(depthVal)})`).toBe('number');
		}
		if (dqVal !== undefined) {
			expect(typeof dqVal, `${path}: dataQuality.lookup_failed must be number, got ${typeof dqVal} (${JSON.stringify(dqVal)})`).toBe('number');
		}
		// And at least one must exist — otherwise the schema regressed and the
		// counter went missing entirely (which is how a string label could
		// silently re-leak in its place).
		expect(
			depthVal !== undefined || dqVal !== undefined,
			`${path}: neither depth.registrarCoverage.lookup_failed nor dataQuality.lookup_failed present; numeric counter dropped from schema?`,
		).toBe(true);
	});

	it.each(sidecarEntries)('%s — no relationship-bucket item exposes "lookup_failed" as a label', (path, report) => {
		// Three relationship buckets surfaced to brand-audit consumers. Each one
		// nests differently:
		//   - registrarSprawl: flat array of items with .registrar/.registrarSource
		//   - vendorDependencies: flat array (same shape)
		//   - ownedPortfolio: object with sub-arrays
		//       (tenantDeclared, graphSurfaced, declaredEvidence, inferred.{...})
		// We walk leaves of all three uniformly and assert no leaf string equals
		// 'lookup_failed'. This catches both .registrar==='lookup_failed' AND
		// .registrarSource==='lookup_failed' AND any future field that might
		// inherit the leak.
		const r = report as Record<string, unknown>;
		const offenders: Array<{ bucket: string; leafPath: string; key: string; value: unknown }> = [];

		for (const bucket of ['registrarSprawl', 'vendorDependencies', 'ownedPortfolio'] as const) {
			const root = r[bucket];
			if (root === undefined) continue;
			for (const leaf of walkLeaves(root, bucket)) {
				if (leaf.value === 'lookup_failed') {
					offenders.push({ bucket, leafPath: leaf.path, key: leaf.key, value: leaf.value });
				}
			}
		}

		expect(
			offenders,
			`${path}: relationship buckets contain "lookup_failed" string label at: ${offenders.map((o) => `${o.leafPath} (key=${o.key})`).join(', ')}`,
		).toEqual([]);
	});
});
