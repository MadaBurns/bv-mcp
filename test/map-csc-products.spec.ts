// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect } from 'vitest';
import type { CheckResult } from '../src/lib/scoring';
import type { LockPosture } from '../src/tools/check-rdap-lookup';
import { evaluateCscProducts } from '../src/tools/map-csc-products';
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
