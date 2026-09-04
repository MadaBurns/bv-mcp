// SPDX-License-Identifier: BUSL-1.1

import packageJsonText from '../../package.json?raw';
import commandSource from '../../src/cli/command.ts?raw';
import evidenceSource from '../../src/cli/evidence.ts?raw';
import clientSource from '../../src/cli/mcp-http-client.ts?raw';
import schemasSource from '../../src/cli/schemas.ts?raw';
import tsupSource from '../../tsup.config.ts?raw';
import { describe, expect, it } from 'vitest';

const sources = [commandSource, evidenceSource, clientSource, schemasSource].join('\n');

describe('CLI distribution boundary', () => {
	it('preserves the MCP bin and adds the CLI build entry', () => {
		const pkg = JSON.parse(packageJsonText) as { bin?: Record<string, string> };
		expect(pkg.bin).toEqual({ 'blackveil-dns-mcp': 'dist/stdio.js', blackveil: 'dist/cli.js' });
		expect(tsupSource).toContain("entry: { cli: 'src/cli.ts' }");
	});

	it('does not import local tools or scoring into the hosted client', () => {
		expect(sources).not.toMatch(/@blackveil\/dns-checks|from ['"][^'"]*tools|scoreToGrade|nistScoreToGrade|SEVERITY_PENALTIES/);
	});

	it('has no paid-batch fallback or SARIF surface', () => {
		const batchBody = commandSource.slice(
			commandSource.indexOf('async function runBatch'),
			commandSource.indexOf('async function runPolicy'),
		);
		expect(batchBody).toContain("callTool('batch_scan'");
		expect(batchBody).not.toContain("callTool('scan_domain'");
		expect(sources.toLowerCase()).not.toContain('sarif');
	});

	it('accepts API credentials from the environment only', () => {
		expect(commandSource).toContain('BLACKVEIL_API_KEY');
		expect(commandSource).not.toContain("'--api-key'");
	});
});
