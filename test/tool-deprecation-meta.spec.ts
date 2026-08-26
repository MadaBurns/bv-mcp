// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import { INTERNAL_ONLY_TOOLS } from '../src/lib/config';
import { TOOLS } from '../src/schemas/tool-definitions';

describe('deprecated tool lifecycle metadata', () => {
	it('marks exactly query_ual as deprecated', () => {
		const deprecated = TOOLS.filter((tool) => tool.lifecycle?.status === 'deprecated').map((tool) => tool.name);
		expect(deprecated).toEqual(['query_ual']);
	});

	it('retains query_ual only as a hidden, read-only, non-recommended compatibility tombstone', () => {
		const tool = TOOLS.find((candidate) => candidate.name === 'query_ual');
		expect(tool).toBeDefined();
		expect(INTERNAL_ONLY_TOOLS.has('query_ual')).toBe(true);
		expect(tool!.scanIncluded).toBe(false);
		expect(tool!.recommended).toBeUndefined();
		expect(tool!.annotations).toMatchObject({
			readOnlyHint: true,
			destructiveHint: false,
			idempotentHint: true,
		});
	});
});
