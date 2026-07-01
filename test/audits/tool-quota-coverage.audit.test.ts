// Audit test: every MCP tool must have explicit per-tool free-tier quota
// coverage decision — either an entry in FREE_TOOL_DAILY_LIMITS, or explicit
// membership in INTENTIONALLY_UNLIMITED_TOOLS (covered by per-IP only).
//
// Background: prior to v2.10.8, tools omitted from FREE_TOOL_DAILY_LIMITS
// silently fell back to per-IP rate limiting. That was sometimes intended,
// sometimes a bug (e.g. check_dane_https / check_svcb_https shipped without
// quotas because nobody noticed). This audit forces the decision to be
// explicit and visible in code review.
//
// Per testing-methodology.md principle 4 — audit tests replace review checklists.

import { describe, it, expect } from 'vitest';
import { TOOLS } from '../../src/schemas/tool-definitions';
import { FREE_TOOL_DAILY_LIMITS, INTENTIONALLY_UNLIMITED_TOOLS, INTERNAL_ONLY_TOOLS } from '../../src/lib/config';

describe('tool-quota-coverage audit', () => {
	it('every public TOOL_DEFS entry is either quota-limited or explicitly unlimited (never neither, never both)', () => {
		const limited = new Set(Object.keys(FREE_TOOL_DAILY_LIMITS));
		const unlimited = INTENTIONALLY_UNLIMITED_TOOLS;

		const missing: string[] = [];
		const both: string[] = [];

		for (const tool of TOOLS) {
			// Internal-only tools are removed from the public surface (rejected on /mcp),
			// so they carry no public free-tier quota — exempt from the coverage requirement.
			if (INTERNAL_ONLY_TOOLS.has(tool.name)) continue;
			const inLimited = limited.has(tool.name);
			const inUnlimited = unlimited.has(tool.name);
			if (!inLimited && !inUnlimited) missing.push(tool.name);
			if (inLimited && inUnlimited) both.push(tool.name);
		}

		expect(missing, `tools missing from BOTH FREE_TOOL_DAILY_LIMITS and INTENTIONALLY_UNLIMITED_TOOLS: ${missing.join(', ')}`).toEqual([]);
		expect(both, `tools listed in BOTH (must pick one): ${both.join(', ')}`).toEqual([]);
	});

	it('INTENTIONALLY_UNLIMITED_TOOLS membership is a non-empty subset of TOOL_DEFS names', () => {
		const validNames = new Set(TOOLS.map((t) => t.name));
		const stale = [...INTENTIONALLY_UNLIMITED_TOOLS].filter((name) => !validNames.has(name));
		expect(stale, `INTENTIONALLY_UNLIMITED_TOOLS contains names not in TOOL_DEFS: ${stale.join(', ')}`).toEqual([]);
	});
});
