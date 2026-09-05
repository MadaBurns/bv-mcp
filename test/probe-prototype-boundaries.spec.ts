// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import { CATEGORY_TIERS } from '@blackveil/dns-checks';
import { TOOLS } from '../src/schemas/tool-definitions';

describe('probe prototype boundaries', () => {
	it('does not register, scan, or score either beta prototype', () => {
		const names = new Set(TOOLS.map((tool) => tool.name));
		for (const prototype of ['audit_csp_coverage', 'inspect_smtp_starttls']) {
			expect(names.has(prototype)).toBe(false);
			expect(prototype in CATEGORY_TIERS).toBe(false);
		}
		expect(TOOLS.some((tool) => tool.scanIncluded && ['audit_csp_coverage', 'inspect_smtp_starttls'].includes(tool.name))).toBe(false);
	});
});
