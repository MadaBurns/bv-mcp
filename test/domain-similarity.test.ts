// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import { domainLabelSimilarity } from '../src/lib/domain-similarity';

describe('domainLabelSimilarity', () => {
	it('scores close typo labels higher than unrelated labels', () => {
		expect(domainLabelSimilarity('example.com', 'examp1e.com')).toBeGreaterThanOrEqual(0.85);
		expect(domainLabelSimilarity('example.com', 'totallydifferent.net')).toBeLessThan(0.5);
	});
});
