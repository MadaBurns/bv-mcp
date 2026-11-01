// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import readme from '../../README.md?raw';
import clientSetup from '../../docs/client-setup.md?raw';
import troubleshooting from '../../docs/troubleshooting.md?raw';
import vscodeReadme from '../../extensions/vscode/README.md?raw';
import { FREE_TOOL_DAILY_LIMITS, GATED_PAID_ONLY_TOOLS, TIER_AGGREGATE_DAILY_LIMITS, TIER_DAILY_LIMITS } from '../../src/lib/config';
import { handleResourcesRead } from '../../src/handlers/resources';

const fmt = (n: number): string => n.toLocaleString('en-US');

function readResource(uri: string): string {
	const result = handleResourcesRead({ uri });
	expect(result.contents).toHaveLength(1);
	return result.contents[0].text;
}

describe('public quota surface audit', () => {
	it('keeps README pricing aligned with runtime limits', () => {
		expect(readme).toContain(`| **Scans/day**  | ${FREE_TOOL_DAILY_LIMITS.scan_domain}`);
		expect(readme).toContain('| **Checks/day** | Tool-specific limits');
		expect(readme).not.toContain('| **Scans/day**  | 5');
		expect(readme).not.toContain('| **Checks/day** | 25         | 5,000');
	});

	it('keeps client setup tier quotas aligned with runtime limits', () => {
		const agg = TIER_AGGREGATE_DAILY_LIMITS;
		expect(clientSetup).toContain(
			`| **agent** | **${TIER_DAILY_LIMITS.agent} scans/day per tool, ${fmt(agg.agent)} tool calls/day in total, 5 concurrent**`,
		);
		expect(clientSetup).toContain(
			`| developer | ${TIER_DAILY_LIMITS.developer} scans/day per tool, ${fmt(agg.developer)} tool calls/day in total, 10 concurrent`,
		);
		expect(clientSetup).toContain(
			`| enterprise | ${fmt(TIER_DAILY_LIMITS.enterprise)} scans/day per tool, ${fmt(agg.enterprise)} tool calls/day in total, 25 concurrent`,
		);
		expect(clientSetup).toContain(`With a free key: ${TIER_DAILY_LIMITS.free}/day per tool, with no separate total across tools.`);
		expect(agg.free).toBe(Infinity);
	});

	it('keeps the README per-key totals across tools aligned with TIER_AGGREGATE_DAILY_LIMITS (SQ-494)', () => {
		const agg = TIER_AGGREGATE_DAILY_LIMITS;
		expect(readme).toContain(`${TIER_DAILY_LIMITS.developer} per tool, ${fmt(agg.developer)} across all tools`);
		expect(readme).toContain(`${fmt(TIER_DAILY_LIMITS.enterprise)}+ per tool, ${fmt(agg.enterprise)} across all tools`);
		expect(readme).toContain(
			`Agent, developer and enterprise keys also have a daily total across all tools combined (${fmt(agg.agent)}, ${fmt(agg.developer)} and ${fmt(agg.enterprise)} calls respectively)`,
		);
		expect(readme).toContain('`TIER_AGGREGATE_DAILY_LIMITS`');
	});

	it('keeps hosted static-key auth docs on Bearer/OAuth, not query-string credentials', () => {
		expect(clientSetup).toContain('Hosted production rejects `?api_key=` credentials');
		expect(clientSetup).toContain('Static API keys via `Authorization: Bearer` authenticate as a specific tier');
		expect(clientSetup).not.toContain('https://dns-mcp.blackveilsecurity.com/mcp?api_key=');
		expect(clientSetup).not.toContain('"url": "https://dns-mcp.blackveilsecurity.com/mcp?api_key=');
		expect(readme).toContain('BlackVeil hosted production sets `REJECT_QUERY_API_KEY=true`');
		expect(readme).not.toContain('Query Param');
		expect(troubleshooting).toContain('Hosted production rejects `?api_key=` URL credentials');
	});

	it('keeps MCP resources aligned with free high-cost tool limits', () => {
		const text = readResource('dns-security://guides/agent-workflows');

		expect(text).toContain('check_lookalikes/check_shadow_domains: paid plan required (developer tier or higher)');
		expect(text).not.toContain('check_lookalikes`/`check_shadow_domains`: 20/day limit');
		expect(text).not.toContain('/day limit (unauth)');
	});

	it('keeps VS Code README free-tier copy aligned with runtime limits', () => {
		expect(vscodeReadme).toContain(`${FREE_TOOL_DAILY_LIMITS.scan_domain} scans/day`);
		expect(vscodeReadme).not.toContain('No API key needed. 5 scans/day, 25 checks/day, 50 req/min.');
	});

	it('never advertises an unauthenticated daily allowance for a paid-only tool', () => {
		// Paid-only tools answer anonymous callers with a 401 (OAuth challenge) or 403, not a quota; docs/client-setup.md once promised 3-5/day for three of them.
		for (const tool of GATED_PAID_ONLY_TOOLS) {
			expect(FREE_TOOL_DAILY_LIMITS[tool as keyof typeof FREE_TOOL_DAILY_LIMITS] ?? 0).toBe(0);
			for (const doc of [readme, clientSetup, troubleshooting]) expect(doc).not.toMatch(new RegExp(`\x60${tool}\x60 (?:to|at) \\d+\\/day`));
		}
	});
});
