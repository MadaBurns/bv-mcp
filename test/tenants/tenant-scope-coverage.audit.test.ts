// SPDX-License-Identifier: BUSL-1.1

/**
 * FINDING #8 (coverage audit): the tenant-scope assertion + deny/audit/403 block
 * was copy-pasted at all 4 tenant routes (/portfolio, /scan, /discover, /report).
 * A new tenant route that resolves a tenant but forgets the block ships a BOLA
 * hole, and nothing enforced it.
 *
 * After the refactor the block lives in ONE local helper, `denyIfOutOfScope(...)`.
 * This audit pins the invariant: EVERY route that resolves a tenant
 * (`await resolveTenant(`) must also perform the scope check
 * (`await denyIfOutOfScope(`). The two call-site counts must be EQUAL and == 4 —
 * so a new route that resolves a tenant but forgets the scope check (or a
 * regression that drops a call site) fails CI here.
 */

import { describe, it, expect } from 'vitest';

const routesSource = import.meta.glob('../../src/tenants/routes.ts', {
	query: '?raw',
	import: 'default',
	eager: true,
}) as Record<string, string>;

const SOURCE = Object.values(routesSource)[0] ?? '';

/** Count call sites only — `await ` prefix excludes the `function denyIfOutOfScope(` definition line. */
function countCallSites(source: string, fnName: string): number {
	const re = new RegExp(`await\\s+${fnName}\\s*\\(`, 'g');
	return (source.match(re) ?? []).length;
}

describe('FINDING #8: tenant-scope coverage (audit)', () => {
	it('routes.ts source is readable', () => {
		expect(SOURCE.length).toBeGreaterThan(0);
		expect(SOURCE).toContain('tenantRoutes');
	});

	it('the scope check is factored into a single helper', () => {
		expect(SOURCE).toContain('function denyIfOutOfScope');
	});

	it('every route that resolves a tenant also performs the scope check (counts equal == 4)', () => {
		const resolveCount = countCallSites(SOURCE, 'resolveTenant');
		const scopeCount = countCallSites(SOURCE, 'denyIfOutOfScope');
		expect(resolveCount).toBe(4);
		expect(scopeCount).toBe(resolveCount);
	});
});
