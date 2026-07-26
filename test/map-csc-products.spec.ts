// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect } from 'vitest';
import type { CheckResult } from '../src/lib/scoring';
import type { LockPosture } from '../src/tools/check-rdap-lookup';
import { evaluateCscProducts, extractLockPosture, formatCscProducts } from '../src/tools/map-csc-products';
import type { CscProductReport, CscProductRecommendation } from '../src/tools/map-csc-products';

/** Minimal CheckResult fixture. */
function makeCheck(category: string, passed: boolean, findings: Array<{ title: string; severity: string }> = []): CheckResult {
	return {
		category,
		passed,
		score: passed ? 100 : 0,
		findings: findings.map((f) => ({ category, title: f.title, severity: f.severity, detail: '' })),
	} as CheckResult;
}

/** LockPosture literal builder. */
function lp(over: Partial<LockPosture>): LockPosture {
	return {
		level: 'unknown',
		transferLocked: false,
		deleteLocked: false,
		updateLocked: false,
		registryLevel: false,
		registrarLevel: false,
		...over,
	};
}

/** All three scan products passing. */
function allPassing(): CheckResult[] {
	return [makeCheck('dmarc', true), makeCheck('ssl', true), makeCheck('dnssec', true)];
}

function recFor(report: CscProductReport, key: CscProductRecommendation['product']): CscProductRecommendation {
	const r = report.recommendations.find((x) => x.product === key);
	if (!r) throw new Error(`no recommendation for ${key}`);
	return r;
}

describe('evaluateCscProducts — CSC MultiLock (reads booleans, not level)', () => {
	it('registry-lock posture (registryLevel true) → not recommended, none', () => {
		const r = evaluateCscProducts(allPassing(), lp({ level: 'registry-lock', registryLevel: true, transferLocked: true }), 'a.com', 90, 'A');
		const m = recFor(r, 'csc_multilock');
		expect(m.recommended).toBe(false);
		expect(m.priority).toBe('none');
	});

	it('unlocked posture → recommended high, gap mentions transfer', () => {
		const r = evaluateCscProducts(allPassing(), lp({ level: 'unlocked', transferLocked: false }), 'a.com', 90, 'A');
		const m = recFor(r, 'csc_multilock');
		expect(m.recommended).toBe(true);
		expect(m.priority).toBe('high');
		expect(m.justifyingGap.toLowerCase()).toContain('transfer');
	});

	it('registrar-lock posture (registrarLevel true, registryLevel false) → recommended medium', () => {
		const r = evaluateCscProducts(allPassing(), lp({ level: 'registrar-lock', registrarLevel: true, transferLocked: true }), 'a.com', 90, 'A');
		const m = recFor(r, 'csc_multilock');
		expect(m.recommended).toBe(true);
		expect(m.priority).toBe('medium');
	});

	it('null posture → not recommended, gap mentions unobservable', () => {
		const r = evaluateCscProducts(allPassing(), null, 'a.com', 90, 'A');
		const m = recFor(r, 'csc_multilock');
		expect(m.recommended).toBe(false);
		expect(m.priority).toBe('none');
		expect(m.justifyingGap.toLowerCase()).toContain('unobservable');
	});

	it('unknown level → treated like null (unknown is never a gap)', () => {
		const r = evaluateCscProducts(allPassing(), lp({ level: 'unknown' }), 'a.com', 90, 'A');
		const m = recFor(r, 'csc_multilock');
		expect(m.recommended).toBe(false);
		expect(m.priority).toBe('none');
	});

	it('BOOLEANS guard: level=unlocked but registryLevel=true (server delete lock, no transfer lock) → NOT recommended', () => {
		const r = evaluateCscProducts(allPassing(), lp({ level: 'unlocked', registryLevel: true, transferLocked: false, deleteLocked: true }), 'a.com', 90, 'A');
		const m = recFor(r, 'csc_multilock');
		expect(m.recommended).toBe(false);
	});
});

describe('evaluateCscProducts — scan-driven products', () => {
	it('dmarc passing → managed_dmarc not recommended', () => {
		const r = evaluateCscProducts(allPassing(), lp({ level: 'registry-lock', registryLevel: true }), 'a.com', 90, 'A');
		expect(recFor(r, 'managed_dmarc').recommended).toBe(false);
	});

	it('dmarc failing with a high finding → recommended high, relatedFindings carries title', () => {
		const checks = [makeCheck('dmarc', false, [{ title: 'No DMARC record', severity: 'high' }]), makeCheck('ssl', true), makeCheck('dnssec', true)];
		const m = recFor(evaluateCscProducts(checks, null, 'a.com', 50, 'F'), 'managed_dmarc');
		expect(m.recommended).toBe(true);
		expect(m.priority).toBe('high');
		expect(m.relatedFindings).toContain('No DMARC record');
	});

	it('dmarc failing with only medium findings → priority medium', () => {
		const checks = [makeCheck('dmarc', false, [{ title: 'Weak DMARC policy', severity: 'medium' }]), makeCheck('ssl', true), makeCheck('dnssec', true)];
		expect(recFor(evaluateCscProducts(checks, null, 'a.com', 60, 'D'), 'managed_dmarc').priority).toBe('medium');
	});

	it('dmarc absent from checks → recommended low, gap "not observed"', () => {
		const checks = [makeCheck('ssl', true), makeCheck('dnssec', true)];
		const m = recFor(evaluateCscProducts(checks, null, 'a.com', 60, 'D'), 'managed_dmarc');
		expect(m.recommended).toBe(true);
		expect(m.priority).toBe('low');
		expect(m.justifyingGap.toLowerCase()).toContain('not observed');
	});

	it('ssl failing → digital_certificates recommended; ssl passing → not', () => {
		const fail = [makeCheck('dmarc', true), makeCheck('ssl', false, [{ title: 'Certificate expired', severity: 'high' }]), makeCheck('dnssec', true)];
		expect(recFor(evaluateCscProducts(fail, null, 'a.com', 60, 'D'), 'digital_certificates').recommended).toBe(true);
		expect(recFor(evaluateCscProducts(allPassing(), null, 'a.com', 90, 'A'), 'digital_certificates').recommended).toBe(false);
	});

	it('dnssec failing → dnssec_management medium; absent → low', () => {
		const fail = [makeCheck('dmarc', true), makeCheck('ssl', true), makeCheck('dnssec', false, [{ title: 'DNSSEC not enabled', severity: 'medium' }])];
		expect(recFor(evaluateCscProducts(fail, null, 'a.com', 70, 'C'), 'dnssec_management').priority).toBe('medium');
		const absent = [makeCheck('dmarc', true), makeCheck('ssl', true)];
		expect(recFor(evaluateCscProducts(absent, null, 'a.com', 70, 'C'), 'dnssec_management').priority).toBe('low');
	});

	it('relatedFindings excludes info-severity findings', () => {
		const checks = [makeCheck('dmarc', false, [{ title: 'Real gap', severity: 'high' }, { title: 'Just info', severity: 'info' }]), makeCheck('ssl', true), makeCheck('dnssec', true)];
		const m = recFor(evaluateCscProducts(checks, null, 'a.com', 50, 'F'), 'managed_dmarc');
		expect(m.relatedFindings).toContain('Real gap');
		expect(m.relatedFindings).not.toContain('Just info');
	});
});

describe('evaluateCscProducts — report shape', () => {
	it('exactly 4 recommendations in fixed order; recommendedCount matches; passthrough fields', () => {
		const posture = lp({ level: 'unlocked', transferLocked: false });
		const r = evaluateCscProducts([makeCheck('dmarc', false, [{ title: 'x', severity: 'high' }]), makeCheck('ssl', true), makeCheck('dnssec', true)], posture, 'shape.com', 42, 'F');
		expect(r.recommendations.map((x) => x.product)).toEqual(['csc_multilock', 'managed_dmarc', 'digital_certificates', 'dnssec_management']);
		expect(r.recommendedCount).toBe(r.recommendations.filter((x) => x.recommended).length);
		expect(r.recommendedCount).toBe(2); // multilock high + dmarc high
		expect(r.lockPosture).toEqual(posture);
		expect(r.domain).toBe('shape.com');
		expect(r.score).toBe(42);
		expect(r.grade).toBe('F');
	});

	it('all-clean: all-pass checks + registry-lock posture → recommendedCount 0, every priority none', () => {
		const r = evaluateCscProducts(allPassing(), lp({ level: 'registry-lock', registryLevel: true, transferLocked: true }), 'clean.com', 98, 'A+');
		expect(r.recommendedCount).toBe(0);
		expect(r.recommendations.every((x) => x.priority === 'none')).toBe(true);
		expect(r.recommendations.every((x) => x.recommended === false)).toBe(true);
	});
});

describe('extractLockPosture', () => {
	it('returns the posture from a finding carrying metadata.lockPosture', () => {
		const posture = lp({ level: 'registrar-lock', registrarLevel: true, transferLocked: true });
		const rdap = {
			category: 'rdap',
			passed: true,
			score: 100,
			findings: [{ category: 'rdap', title: 'Registration details', severity: 'info', detail: '', metadata: { lockPosture: posture } }],
		} as unknown as CheckResult;
		expect(extractLockPosture(rdap)).toEqual(posture);
	});

	it('returns null when no finding carries lock metadata (lookup_failed shape)', () => {
		const rdap = {
			category: 'rdap',
			passed: false,
			score: 0,
			findings: [{ category: 'rdap', title: 'RDAP lookup failed', severity: 'low', detail: '', metadata: { registrarSource: 'lookup_failed' } }],
		} as unknown as CheckResult;
		expect(extractLockPosture(rdap)).toBeNull();
	});
});

describe('formatCscProducts', () => {
	function sampleReport(): CscProductReport {
		return evaluateCscProducts(
			[makeCheck('dmarc', false, [{ title: 'No DMARC record', severity: 'high' }]), makeCheck('ssl', true), makeCheck('dnssec', true)],
			lp({ level: 'unlocked', transferLocked: false }),
			'fmt.com',
			55,
			'F',
		);
	}

	it('full output names every product and shows justifyingGap for recommended lines', () => {
		const out = formatCscProducts(sampleReport(), 'full');
		expect(out).toContain('CSC MultiLock');
		expect(out).toContain('Managed DMARC');
		expect(out).toContain('Digital Certificates');
		expect(out).toContain('DNSSEC management');
		expect(out).toContain('fmt.com');
		// recommended MultiLock + DMARC gaps surfaced
		expect(out).toContain('Domain transfer not locked');
		expect(out).toContain('DMARC present but not passing');
	});

	it('compact output is shorter than full and still names the products', () => {
		const report = sampleReport();
		const full = formatCscProducts(report, 'full');
		const compact = formatCscProducts(report, 'compact');
		expect(compact.length).toBeLessThan(full.length);
		expect(compact).toContain('CSC MultiLock');
	});

	it('renders "not measured" instead of null/100 (null) for an ungraded scan', async () => {
		const { evaluateCscProducts: evaluate, formatCscProducts: fmt } = await import('../src/tools/map-csc-products');
		const report = evaluate([], null, 'never-measured.example', null, null);
		const text = fmt(report, 'full');

		expect(text).toContain('not measured');
		expect(text).not.toContain('null');
	});

	it('still renders the real score for a measured scan (control)', async () => {
		const { formatCscProducts: fmt } = await import('../src/tools/map-csc-products');
		// Without this the assertion above would hold under a formatter that printed
		// the ungraded token unconditionally.
		const text = fmt(sampleReport(), 'full');
		expect(text).toContain('55/100 (F)');
		expect(text).not.toContain('not measured');
	});
});

/**
 * `map_csc_products` sold three products for a domain nobody measured.
 *
 * `evaluateCscProducts` set `assessed: isMeasured(checkResults)` and
 * `formatCscProducts` never read it, so an NXDOMAIN domain rendered
 * "**Score:** not measured | **3** recommended" followed by three priority-tagged
 * upsells justified by "DMARC not observed" — every one of them derived from
 * having observed nothing. `prioritize_csc_leads` suppresses exactly this from the
 * SAME producer output ("printing them under a 'not measured' score would sell
 * products for a domain nobody looked at"); two tools, one input, opposite answers.
 *
 * Both directions are pinned here: abstain when nothing ran, and never suppress a
 * product gap that rests on real evidence.
 */
describe('formatCscProducts — a domain where no check ran', () => {
	/** The exact producer output for a domain that does not resolve: no checks, no RDAP posture. */
	async function unassessed(domain = 'never-measured-domain.com') {
		const { evaluateCscProducts: evaluate } = await import('../src/tools/map-csc-products');
		return evaluate([], null, domain, null, null);
	}

	it('emits no priced product gap on the wire', async () => {
		const report = await unassessed();

		// Fixture-reachability guard: this is the state under test.
		expect(report.assessed).toBe(false);
		// Was 3, each `recommended: true, priority: 'low'`, on the strength of
		// non-observation. A consumer reading `recommendations` without consulting
		// `assessed` could not tell those apart from measured gaps.
		expect(report.recommendedCount).toBe(0);
		expect(report.recommendations.every((r) => r.recommended === false)).toBe(true);
		expect(report.recommendations.every((r) => r.priority === 'none')).toBe(true);
		// The four products still appear in fixed order — the shape is unchanged, only
		// the verdict abstains.
		expect(report.recommendations.map((r) => r.product)).toEqual([
			'csc_multilock',
			'managed_dmarc',
			'digital_certificates',
			'dnssec_management',
		]);
	});

	it.each(['compact', 'full'] as const)('prints the honest note and no recommendation list [%s]', async (format) => {
		const { formatCscProducts: fmt, UNASSESSED_CSC_NOTE } = await import('../src/tools/map-csc-products');
		const text = fmt(await unassessed(), format);

		expect(text, format).toContain('not measured');
		// The established wording, shared with prioritize_csc_leads — not a third
		// vocabulary for the same state.
		expect(text, format).toContain(UNASSESSED_CSC_NOTE);
		// No product line, and no count claim about products.
		expect(text, format).not.toContain('Managed DMARC');
		expect(text, format).not.toContain('Digital Certificates');
		expect(text, format).not.toContain('DNSSEC management');
		expect(text, format).not.toContain('recommended');
		expect(text, format).not.toContain('upsell');
		// The banked defect verbatim, in each format's own phrasing.
		expect(text, format).not.toContain('not observed');
		expect(text, format).not.toMatch(/\[low\]|— LOW/);
	});

	it.each(['compact', 'full'] as const)('still lists every product for a MEASURED domain [%s] (control)', async (format) => {
		const { evaluateCscProducts: evaluate, formatCscProducts: fmt, UNASSESSED_CSC_NOTE } = await import('../src/tools/map-csc-products');
		// Without this control every assertion above would hold under a formatter that
		// suppressed the product list unconditionally.
		const report = evaluate(
			[makeCheck('dmarc', false, [{ title: 'No DMARC record', severity: 'high' }]), makeCheck('ssl', true), makeCheck('dnssec', true)],
			lp({ level: 'unlocked', transferLocked: false }),
			'measured-domain.com',
			55,
			'F',
		);
		const text = fmt(report, format);

		expect(report.assessed).toBe(true);
		expect(report.recommendedCount).toBe(2);
		expect(text, format).toContain('Managed DMARC');
		expect(text, format).toContain('CSC MultiLock');
		expect(text, format).not.toContain(UNASSESSED_CSC_NOTE);
		expect(text, format).toContain('55/100 (F)');
	});

	it('does NOT suppress a real RDAP lock gap just because the scan measured nothing (mirror)', async () => {
		const { evaluateCscProducts: evaluate, formatCscProducts: fmt } = await import('../src/tools/map-csc-products');
		// A registered domain whose zone is broken still has an observable registrar
		// lock status: RDAP is fetched independently of the scan. That gap is a real
		// measurement, and abstaining on it would be the over-abstain mirror of the
		// defect above.
		const report = evaluate([], lp({ level: 'unlocked', transferLocked: false }), 'broken-zone-domain.com', null, null);

		expect(report.assessed).toBe(false);
		expect(report.recommendedCount).toBe(1);
		const full = fmt(report, 'full');
		expect(full).toContain('CSC MultiLock');
		expect(full).toContain('Domain transfer not locked');
		// …while the three CHECK-derived products stay suppressed.
		expect(full).not.toContain('Managed DMARC');
		expect(full).not.toContain('DNSSEC management');
	});
});
