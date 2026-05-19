// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import source from '../../scripts/brand-audit-depth-baseline.mjs?raw';

describe('brand audit depth baseline script safety', () => {
	it('writes only to ignored .reports and does not hard-code real brands', () => {
		expect(source).toContain('.reports/brand-audit-depth-baseline.json');
		expect(source).not.toMatch(/const\s+domains\s*=\s*\[/);
		expect(source).toContain('process.argv.slice(2)');
	});

	it('records missing domains in a failures array instead of crashing the whole batch', () => {
		expect(source).toContain('failures');
		expect(source).toContain('existsSync');
		expect(source).toContain('missingReport');
	});
});
