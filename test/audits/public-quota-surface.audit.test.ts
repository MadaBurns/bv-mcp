// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import readme from '../../README.md?raw';
import clientSetup from '../../docs/client-setup.md?raw';
import vscodeReadme from '../../extensions/vscode/README.md?raw';
import { FREE_TOOL_DAILY_LIMITS, TIER_DAILY_LIMITS } from '../../src/lib/config';
import { handleResourcesRead } from '../../src/handlers/resources';

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
		expect(clientSetup).toContain(`| **agent** | **${TIER_DAILY_LIMITS.agent} scans/day, 5 concurrent**`);
		expect(clientSetup).toContain(`| developer | ${TIER_DAILY_LIMITS.developer} scans/day, 10 concurrent`);
		expect(clientSetup).toContain(`| enterprise | ${TIER_DAILY_LIMITS.enterprise.toLocaleString('en-US')} scans/day, 25 concurrent`);
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
});
