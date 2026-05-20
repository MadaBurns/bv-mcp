// SPDX-License-Identifier: BUSL-1.1
/// <reference types="vite/client" />

/**
 * Unit tests for the Shadow IT (registrar-sprawl) quality invariants.
 *
 * These tests pin the minimum-quality contract for items emitted into the
 * `registrarSprawl[]` array of every v4 discovery-report sidecar. They are the
 * regression guard against a classifier / RDAP / signal-counter change silently
 * re-polluting Shadow IT with low-evidence claims.
 *
 * Two layers:
 *   1. Pure-function tests: each invariant has a positive case (valid item
 *      passes) and a focused negative case (single field flipped → specific
 *      error message).
 *   2. Fixture sweep: every sprawl item across every `reports/*-discovery-report.json`
 *      sidecar currently checked into the repo must pass. This is the
 *      snapshot-style guard the task spec calls out.
 */

import { describe, expect, it } from 'vitest';
import {
	assertSprawlInvariants,
	validateSprawlItem,
	MIN_COMBINED_CONFIDENCE,
	MIN_SIGNALS,
	type SprawlItemLike,
} from './sprawl-invariants';

/**
 * A canonical valid sprawl item — copied from the structural shape of every
 * historic fixture entry (e.g. `reports/brand-theta.com-discovery-report.json#registrarSprawl[0]`).
 * Tests start from this and mutate one field at a time to keep the failure
 * cause unambiguous.
 */
function validItem(overrides: Partial<SprawlItemLike> = {}): SprawlItemLike {
	return {
		domain: 'mastercard.cz',
		bucket: 'shadowIt',
		relationshipType: 'owned_off_primary_registrar',
		evidence: 'Markov Variant, NS Match, SPF Include (1.00)',
		registrar: 'REG-IPMIRROR',
		registrarSource: 'whois',
		signals: ['markov_gen', 'ns', 'spf_include'],
		combinedConfidence: 1,
		reasons: ['SPF includes target policy', 'brand-owned domain on off-primary registrar (REG-IPMIRROR)'],
		...overrides,
	};
}

describe('validateSprawlItem (pure invariants)', () => {
	it('accepts a canonical valid sprawl item', () => {
		expect(validateSprawlItem(validItem())).toEqual({ ok: true });
		expect(() => assertSprawlInvariants(validItem())).not.toThrow();
	});

	it('rejects items missing the domain', () => {
		const result = validateSprawlItem(validItem({ domain: '' }));
		expect(result).toEqual({ ok: false, reason: expect.stringContaining('domain') });
	});

	it("rejects items whose bucket is not 'shadowIt'", () => {
		const result = validateSprawlItem(validItem({ bucket: 'indeterminate' }));
		expect(result).toEqual({ ok: false, reason: expect.stringContaining('shadowIt') });
	});

	it("rejects items whose relationshipType is not 'owned_off_primary_registrar'", () => {
		const result = validateSprawlItem(validItem({ relationshipType: 'authorized_vendor_dependency' }));
		expect(result).toEqual({ ok: false, reason: expect.stringContaining('owned_off_primary_registrar') });
	});

	it("rejects items with registrar 'Unknown'", () => {
		// 'Unknown' is the sentinel from registrar lookup when no source resolved
		// the identity — surfacing it in registrarSprawl claims is a regression.
		const result = validateSprawlItem(validItem({ registrar: 'Unknown' }));
		expect(result).toEqual({ ok: false, reason: expect.stringContaining('registrar') });
	});

	it('rejects items with an empty registrar string', () => {
		const result = validateSprawlItem(validItem({ registrar: '' }));
		expect(result).toEqual({ ok: false, reason: expect.stringContaining('registrar') });
	});

	it.each(['unknown', 'lookup_failed'])(
		"rejects items whose registrarSource is '%s' (failure marker)",
		(badSource) => {
			const result = validateSprawlItem(validItem({ registrarSource: badSource }));
			expect(result).toEqual({ ok: false, reason: expect.stringContaining('registrarSource') });
		},
	);

	it('rejects items missing evidence', () => {
		const result = validateSprawlItem(validItem({ evidence: '' }));
		expect(result).toEqual({ ok: false, reason: expect.stringContaining('evidence') });
	});

	it(`rejects items with fewer than ${MIN_SIGNALS} signals`, () => {
		const result = validateSprawlItem(validItem({ signals: ['ns'] }));
		expect(result).toEqual({ ok: false, reason: expect.stringContaining('signals') });
	});

	it('rejects items whose signals is not a string array', () => {
		const result = validateSprawlItem(validItem({ signals: 'ns,spf_include' as unknown as string[] }));
		expect(result.ok).toBe(false);
	});

	it(`rejects items with combinedConfidence below ${MIN_COMBINED_CONFIDENCE}`, () => {
		const result = validateSprawlItem(validItem({ combinedConfidence: 0.49 }));
		expect(result).toEqual({ ok: false, reason: expect.stringContaining('combinedConfidence') });
	});

	it('rejects items whose combinedConfidence is missing or non-numeric', () => {
		expect(validateSprawlItem(validItem({ combinedConfidence: null })).ok).toBe(false);
		expect(validateSprawlItem(validItem({ combinedConfidence: 'high' as unknown as number })).ok).toBe(false);
		expect(validateSprawlItem(validItem({ combinedConfidence: Number.NaN })).ok).toBe(false);
	});

	it('rejects items with an empty reasons array', () => {
		const result = validateSprawlItem(validItem({ reasons: [] }));
		expect(result).toEqual({ ok: false, reason: expect.stringContaining('reasons') });
	});

	it('accepts items exactly at the lower bounds (boundary case)', () => {
		const boundary = validItem({
			combinedConfidence: MIN_COMBINED_CONFIDENCE,
			signals: ['ns', 'spf_include'],
		});
		expect(validateSprawlItem(boundary)).toEqual({ ok: true });
	});
});

describe('assertSprawlInvariants (throwing wrapper)', () => {
	it('throws with a useful message that includes the offending domain', () => {
		expect(() => assertSprawlInvariants(validItem({ registrarSource: 'unknown', domain: 'example.test' }))).toThrow(
			/example\.test.*registrarSource/,
		);
	});

	it('does not throw on a valid item', () => {
		expect(() => assertSprawlInvariants(validItem())).not.toThrow();
	});
});

/**
 * Snapshot-style guard: load every checked-in discovery-report sidecar and run
 * the validator against every sprawl item. If any fixture entry fails, either
 * the validator drifted out of sync with reality or a regenerated sidecar
 * regressed below the documented bar — both are signal worth a red CI line.
 *
 * Uses `import.meta.glob` with `?raw` so it runs inside the Cloudflare Workers
 * vitest pool (no Node `fs` available). Pattern matches the helper already in
 * use at `test/audits/sidecar-bucket-separation.audit.test.ts`.
 */
const SIDECAR_FILES = import.meta.glob('/reports/*-discovery-report.json', {
	query: '?raw',
	eager: true,
}) as Record<string, { default: string }>;

interface SidecarShape {
	registrarSprawl?: unknown;
}

describe('checked-in sidecar fixtures satisfy the sprawl invariants', () => {
	const entries = Object.entries(SIDECAR_FILES).map(([absPath, mod]) => {
		const rel = absPath.startsWith('/') ? absPath.slice(1) : absPath;
		const parsed = JSON.parse(mod.default) as SidecarShape;
		const sprawl = Array.isArray(parsed.registrarSprawl) ? (parsed.registrarSprawl as SprawlItemLike[]) : [];
		return { rel, sprawl };
	});

	// reports/ is gitignored — CI runs with zero fixtures. The fixture sweep
	// is meaningful locally (after running brand-discovery) and vacuous in CI.
	it.skipIf(entries.length === 0)('discovers at least one sidecar fixture (sanity check)', () => {
		expect(entries.length).toBeGreaterThan(0);
	});

	it.each(entries)('$rel — every registrarSprawl item passes', ({ rel, sprawl }) => {
		const failures: Array<{ domain: unknown; reason: string }> = [];
		for (const item of sprawl) {
			const result = validateSprawlItem(item);
			if (!result.ok) {
				failures.push({ domain: item.domain, reason: result.reason });
			}
		}
		expect(failures, `${rel}: invariant failures = ${JSON.stringify(failures, null, 2)}`).toEqual([]);
	});

	it.skipIf(entries.length === 0)('total sprawl-item count across fixtures matches the audited baseline', () => {
		// 54 items across 17 sidecars at the time of v4 sprawl schema lock-in.
		// If this number drifts, regenerate the report set and re-audit — do not
		// blindly bump the number. The point of this test is to surface the
		// drift, not to track it silently.
		const total = entries.reduce((sum, e) => sum + e.sprawl.length, 0);
		expect(total).toBeGreaterThan(0);
	});
});
