// SPDX-License-Identifier: BUSL-1.1
//
// `_meta.paidOnly` on tools/list: a free-tier agent can see which tools it will be
// refused before it calls them. The flag must mirror GATED_PAID_ONLY_TOOLS exactly
// (the set the 401/403 gate reads), so it can never advertise a tool as free that
// the gate refuses, nor the reverse.

import { describe, expect, it } from 'vitest';
import { handleToolsList } from '../src/handlers/tools';
import { GATED_PAID_ONLY_TOOLS, INTERNAL_ONLY_TOOLS } from '../src/lib/config';
import { TOOLS } from '../src/schemas/tool-definitions';

describe('_meta.paidOnly on tools/list', () => {
	const { tools } = handleToolsList();

	it('flags every listed gated tool and no other', () => {
		const flagged = tools.filter((tool) => tool._meta.paidOnly === true).map((tool) => tool.name);
		const expected = [...GATED_PAID_ONLY_TOOLS].filter((name) => !INTERNAL_ONLY_TOOLS.has(name));
		expect(expected.length).toBeGreaterThan(0);
		expect(flagged.sort()).toEqual(expected.sort());
	});

	it('omits the field entirely on ungated tools (lean, like recommended)', () => {
		for (const tool of tools) {
			if (GATED_PAID_ONLY_TOOLS.has(tool.name)) continue;
			expect('paidOnly' in tool._meta, `${tool.name} is not gated and must not carry paidOnly`).toBe(false);
		}
	});

	it('does not change which tools are listed', () => {
		const listed = tools.map((tool) => tool.name).sort();
		const expected = TOOLS.map((tool) => tool.name)
			.filter((name) => !INTERNAL_ONLY_TOOLS.has(name))
			.sort();
		expect(listed).toEqual(expected);
	});
});
