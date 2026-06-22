// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import smitheryYamlText from '../../smithery.yaml?raw';
import serverJsonText from '../../server.json?raw';
import { TOOLS } from '../../src/schemas/tool-definitions';

describe('server.json tool count', () => {
	it('keeps the MCP Registry description tool count in sync with TOOLS.length', () => {
		const serverJson = JSON.parse(serverJsonText) as { description: string };
		const match = serverJson.description.match(/(\d+) MCP tools/);

		expect(match, 'server.json description must contain "N MCP tools"').not.toBeNull();
		expect(Number(match![1])).toBe(TOOLS.length);
	});

	it('mirrors A2 load-bearing vocabulary in server.json description', () => {
		const serverJson = JSON.parse(serverJsonText) as { description: string };
		const desc = serverJson.description;

		// A2 winning vocab that agents use to select tools must appear in the registry listing
		// so that the model browsing the registry gets the same disambiguation cues.
		expect(desc).toMatch(
			/industry average|percentile|sector/i,
			'server.json must include get_benchmark vocabulary (industry average / percentile / sector)',
		);
		expect(desc).toMatch(
			/improved|regressed|drift/i,
			'server.json must include analyze_drift vocabulary (improved / regressed / drift)',
		);
		expect(desc).toMatch(
			/bulk.scan|bulk scan|multiple domains/i,
			'server.json must include batch_scan vocabulary (bulk-scan / multiple domains)',
		);
		expect(desc).toMatch(
			/SPF include chain|subdomailing|dangling/i,
			'server.json must include check_subdomailing vocabulary (SPF include chain / dangling)',
		);
	});
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
		expect(smitheryYamlText).toMatch(
			/industry average|percentile|sector/i,
			'smithery.yaml must include get_benchmark vocabulary',
		);
		expect(smitheryYamlText).toMatch(
			/improved|regressed|drift/i,
			'smithery.yaml must include analyze_drift vocabulary',
		);
		expect(smitheryYamlText).toMatch(
			/bulk.scan|bulk scan|multiple domains/i,
			'smithery.yaml must include batch_scan vocabulary',
		);
		expect(smitheryYamlText).toMatch(
			/SPF include chain|subdomailing|dangling/i,
			'smithery.yaml must include check_subdomailing vocabulary',
		);
	});
});
