// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import githubSettings from '../../docs/github-settings.md?raw';
import scoringDocs from '../../docs/scoring.md?raw';
import troubleshootingDocs from '../../docs/troubleshooting.md?raw';
import packageReadme from '../../packages/dns-checks/README.md?raw';
import readme from '../../README.md?raw';
import resourcesSource from '../../src/handlers/resources.ts?raw';
import vscodePackageText from '../../extensions/vscode/package.json?raw';
import vscodeReadme from '../../extensions/vscode/README.md?raw';
import { TOOLS } from '../../src/schemas/tool-definitions';

describe('README tool surface', () => {
	it('keeps published tool counts and authoritative DNS infra tools current', () => {
		const toolCount = TOOLS.length;

		expect(toolCount).toBe(74);
		expect(readme).toContain(`MCP%20tools-${toolCount}`);
		expect(readme).toContain(`current ${toolCount}-tool surface`);
		expect(readme).toContain(`${toolCount} MCP tools`);
		expect(readme).toContain('18 scoring categories');
		expect(readme).toContain('check_authoritative_dns_infra');
		expect(readme).toContain('check_root_server_set');
	});

	it('keeps supporting docs aligned with the authoritative DNS infra surface', () => {
		expect(githubSettings).toContain('74 MCP tools');
		expect(scoringDocs).toContain('Authoritative DNS Infrastructure');
		expect(scoringDocs).toContain('authoritative_dns_infra');
		expect(packageReadme).toContain('authoritative_dns_infra');
		expect(troubleshootingDocs).toContain('BV_INFRA_PROBE');
	});

	it('keeps MCP resources and VS Code extension metadata aligned with the tool registry', () => {
		const toolCount = TOOLS.length;
		const checkToolCount = TOOLS.filter((tool) => tool.name.startsWith('check_')).length;
		const vscodePackage = JSON.parse(vscodePackageText) as { description: string };

		expect(resourcesSource).toContain('TOOLS.length');
		expect(resourcesSource).toContain("tool.name.startsWith('check_')");
		expect(vscodeReadme).toContain(`**${toolCount} DNS & email security tools**`);
		expect(vscodeReadme).toContain(`All ${toolCount} tools`);
		expect(vscodeReadme).toContain(`## Tools (${toolCount})`);
		expect(vscodeReadme).toContain(`${checkToolCount} \`check_*\` tools`);
		expect(vscodePackage.description).toContain(`${toolCount} DNS & email security tools`);
	});
});
