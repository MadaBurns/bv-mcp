// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import githubSettings from '../../docs/github-settings.md?raw';
import scoringDocs from '../../docs/scoring.md?raw';
import troubleshootingDocs from '../../docs/troubleshooting.md?raw';
import packageReadme from '../../packages/dns-checks/README.md?raw';
import readme from '../../README.md?raw';
import { TOOLS } from '../../src/schemas/tool-definitions';

describe('README tool surface', () => {
	it('keeps published tool counts and authoritative DNS infra tools current', () => {
		const toolCount = TOOLS.length;

		expect(toolCount).toBe(62);
		expect(readme).toContain(`MCP%20tools-${toolCount}`);
		expect(readme).toContain(`current ${toolCount}-tool surface`);
		expect(readme).toContain(`${toolCount} MCP tools`);
		expect(readme).toContain('18 scoring categories');
		expect(readme).toContain('check_authoritative_dns_infra');
		expect(readme).toContain('check_root_server_set');
	});

	it('keeps supporting docs aligned with the authoritative DNS infra surface', () => {
		expect(githubSettings).toContain('62 MCP tools');
		expect(scoringDocs).toContain('Authoritative DNS Infrastructure');
		expect(scoringDocs).toContain('authoritative_dns_infra');
		expect(packageReadme).toContain('authoritative_dns_infra');
		expect(troubleshootingDocs).toContain('BV_INFRA_PROBE');
	});
});
