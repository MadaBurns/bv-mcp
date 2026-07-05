// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import packageJsonText from '../../package.json?raw';

const packageJson = JSON.parse(packageJsonText) as {
	dependencies?: Record<string, string>;
	pnpm?: { overrides?: Record<string, string> };
	scripts?: Record<string, string>;
};
const workspaceFiles = import.meta.glob('../../pnpm-workspace.yaml', {
	query: '?raw',
	import: 'default',
	eager: true,
});
const npmRcFiles = import.meta.glob('../../.npmrc', {
	query: '?raw',
	import: 'default',
	eager: true,
});
const pnpmWorkspace = Object.values(workspaceFiles)[0] as string | undefined;
const npmRc = Object.values(npmRcFiles)[0] as string | undefined;

describe('Glama pnpm build contract', () => {
	it('declares pnpm workspaces so Glama links the local dns-checks package', () => {
		expect(pnpmWorkspace, 'Glama runs pnpm install, which ignores package.json workspaces without pnpm-workspace.yaml').toBeTypeOf(
			'string',
		);
		expect(pnpmWorkspace).toMatch(/packages:\s*\n(?:\s*-\s*['"]?packages\/\*['"]?\s*\n?)/);
	});

	it('forces pnpm to resolve dns-checks from the workspace instead of the registry', () => {
		const dnsChecksSpec = packageJson.dependencies?.['@blackveil/dns-checks'] ?? '';
		const dnsChecksPnpmOverride = packageJson.pnpm?.overrides?.['@blackveil/dns-checks'] ?? '';
		const usesWorkspaceProtocol = dnsChecksSpec.startsWith('workspace:');
		const usesLocalPnpmOverride = dnsChecksPnpmOverride === 'link:packages/dns-checks';
		const linksMatchingWorkspacePackages = npmRc?.split(/\r?\n/).some((line) => line.trim() === 'link-workspace-packages=true');

		expect(
			usesWorkspaceProtocol || usesLocalPnpmOverride || linksMatchingWorkspacePackages,
			'pnpm otherwise resolves @blackveil/dns-checks from npm when the semver range matches a stale published version',
		).toBe(true);
	});

	it('builds dns-checks before the stdio bundle imports its scoring exports', () => {
		const buildScript = packageJson.scripts?.build ?? '';
		const dnsChecksBuildIndex = buildScript.indexOf('npm -w packages/dns-checks run build');
		const tsupIndex = buildScript.indexOf('tsup');

		expect(dnsChecksBuildIndex, 'root build must generate packages/dns-checks/dist before building dist/stdio.js').toBeGreaterThan(
			-1,
		);
		expect(tsupIndex, 'root build must still run tsup for the MCP bundles').toBeGreaterThan(-1);
		expect(dnsChecksBuildIndex, 'dns-checks must build before tsup emits the stdio bundle').toBeLessThan(tsupIndex);
	});
});
