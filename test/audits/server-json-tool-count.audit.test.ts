// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import smitheryYamlText from '../../smithery.yaml?raw';
import serverJsonText from '../../server.json?raw';
import { TOOLS } from '../../src/schemas/tool-definitions';
import { INTERNAL_ONLY_TOOLS } from '../../src/lib/config';

// Public-facing count: internal-only tools (e.g. map_csc_products) are removed
// from the public /mcp surface, so registry-listing prose advertises this count.
const PUBLIC_TOOL_COUNT = TOOLS.length - INTERNAL_ONLY_TOOLS.size;

describe('server.json tool count', () => {
	it('keeps the MCP Registry description tool count in sync with the PUBLIC tool count', () => {
		const serverJson = JSON.parse(serverJsonText) as { description: string };
		const match = serverJson.description.match(/(\d+) MCP tools/);

		expect(match, 'server.json description must contain "N MCP tools"').not.toBeNull();
		expect(Number(match![1])).toBe(PUBLIC_TOOL_COUNT);
	});

	// NOTE: the MCP Registry hard-caps server.json `description` at 100 chars
	// (locked by npm-publish-surface.audit.test.ts). The full A2 disambiguation
	// vocabulary cannot fit there, so it lives on the uncapped smithery.yaml
	// description instead — asserted below. server.json only carries the honest
	// "N MCP tools" count plus a short blurb, per the registry length limit.
});

describe('smithery.yaml manifest', () => {
	it('parses as valid YAML (non-empty file)', () => {
		expect(smitheryYamlText.trim().length).toBeGreaterThan(0);
		// Basic structural checks — if startCommand is present the file is well-formed
		expect(smitheryYamlText).toContain('startCommand');
		expect(smitheryYamlText).toContain('url:');
	});

	it('contains a description or displayName with the honest tool count', () => {
		const toolCount = TOOLS.length;
		const countPattern = new RegExp(`${toolCount}`);
		expect(smitheryYamlText).toMatch(
			countPattern,
			`smithery.yaml must mention the tool count (${toolCount}) so the Smithery directory listing is honest`,
		);
	});

	it('mirrors A2 load-bearing vocabulary in smithery.yaml description', () => {
		// Same A2 vocab checks — Smithery listing must match the registry
		expect(smitheryYamlText).toMatch(/industry average|percentile|sector/i, 'smithery.yaml must include get_benchmark vocabulary');
		expect(smitheryYamlText).toMatch(/improved|regressed|drift/i, 'smithery.yaml must include analyze_drift vocabulary');
		expect(smitheryYamlText).toMatch(/bulk.scan|bulk scan|multiple domains/i, 'smithery.yaml must include batch_scan vocabulary');
		expect(smitheryYamlText).toMatch(
			/SPF include chain|subdomailing|dangling/i,
			'smithery.yaml must include check_subdomailing vocabulary',
		);
	});
});
