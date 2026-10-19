// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect } from 'vitest';
import { classifyDanePresence } from '../src/checks/dane-analysis';

describe('classifyDanePresence (package copy)', () => {
	it('reports only the MX gap, at medium, when HTTPS has TLSA', () => {
		const findings = classifyDanePresence(false, true);
		expect(findings).toHaveLength(1);
		expect(findings[0]).toMatchObject({ category: 'dane', title: 'No DANE TLSA for MX servers', severity: 'medium' });
		expect(findings[0]!.detail).toContain('_25._tcp');
	});

	it('reports only the HTTPS gap, at low, when MX has TLSA', () => {
		const findings = classifyDanePresence(true, false);
		expect(findings).toHaveLength(1);
		expect(findings[0]).toMatchObject({ category: 'dane', title: 'No DANE TLSA for HTTPS', severity: 'low' });
		expect(findings[0]!.detail).toContain('_443._tcp');
	});

	it('reports both gaps, MX first then HTTPS, when neither has TLSA', () => {
		const findings = classifyDanePresence(false, false);
		expect(findings.map((f) => f.title)).toEqual(['No DANE TLSA for MX servers', 'No DANE TLSA for HTTPS']);
	});

	it('reports nothing when both have TLSA', () => {
		expect(classifyDanePresence(true, true)).toEqual([]);
	});
});
