// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it, vi } from 'vitest';
import { TOOLS } from '../src/schemas/tool-definitions';
import { TOOL_SCHEMA_MAP } from '../src/schemas/tool-args';
import { handleToolsCall, handleToolsList } from '../src/handlers/tools';
import { scanDomain } from '../src/tools/scan-domain';

describe('authoritative DNS infra registration', () => {
	it('registers direct MCP tools and schemas for authoritative infra checks', () => {
		const names = TOOLS.map((tool) => tool.name);

		expect(names).toContain('check_authoritative_dns_infra');
		expect(names).toContain('check_root_server_set');
		expect(Object.keys(TOOL_SCHEMA_MAP)).toEqual(expect.arrayContaining([
			'check_authoritative_dns_infra',
			'check_root_server_set',
		]));

		const rootSet = TOOLS.find((tool) => tool.name === 'check_root_server_set');
		expect(rootSet).toMatchObject({
			group: 'infrastructure',
			tier: 'core',
			scanIncluded: false,
		});
		expect(rootSet?.inputSchema.required ?? []).toEqual([]);

		const listedNames = handleToolsList().tools.map((tool) => tool.name);
		expect(listedNames).toEqual(expect.arrayContaining([
			'check_authoritative_dns_infra',
			'check_root_server_set',
		]));
	});

	it('dispatches the root server set tool without requiring a domain argument', async () => {
		const result = await handleToolsCall({ name: 'check_root_server_set', arguments: {} });

		expect(result.isError).toBeUndefined();
		expect(result.content[0].text).toContain('Official root hints embedded');
	});

	it('runs only authoritative infrastructure checks for the authoritative_dns_infra profile', async () => {
		globalThis.fetch = vi.fn(async () => {
			throw new Error('scan_domain should not run default DoH or HTTPS checks for this profile');
		}) as unknown as typeof globalThis.fetch;

		const result = await scanDomain('a.root-servers.net', undefined, {
			profile: 'authoritative_dns_infra',
			forceRefresh: true,
		});

		expect(result.context.profile).toBe('authoritative_dns_infra');
		expect(result.checks).toHaveLength(1);
		expect(result.checks[0]).toMatchObject({
			category: 'authoritative_dns_infra',
			partial: true,
			metadata: {
				evidenceMode: 'worker_only',
			},
		});
		expect(result.checks[0].findings.map((finding) => finding.title)).toEqual(expect.arrayContaining([
			'Authoritative DNS infra probe not configured',
			'Official root hints embedded',
		]));
	});
});
