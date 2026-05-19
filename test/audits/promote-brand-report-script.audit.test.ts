// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import source from '../../scripts/promote-brand-report.mjs?raw';

describe('brand report promotion script safety', () => {
	it('accepts domains from argv and runs QA before copying reports into ignored .csc', () => {
		expect(source).toContain('process.argv.slice(2)');
		expect(source).toContain('brand-report-qa.mjs');
		expect(source).toContain('.csc');
		expect(source).toContain('copyFileSync');
		expect(source).not.toMatch(/amazon\.com|apple\.com|disney\.com|google\.com|microsoft\.com|paypal\.com|stripe\.com|walmart\.com|nike\.com|github\.com/i);
	});
});
