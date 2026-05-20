// Audit test: the root npm package must publish only the compiled CLI/API
// surface, not repository internals such as docs, tests, scripts, workflow
// files, private config examples, or build caches.

import packageJsonText from '../../package.json?raw';
import serverJsonText from '../../server.json?raw';
import { describe, expect, it } from 'vitest';

const pkg = JSON.parse(packageJsonText) as { files?: unknown };
const serverJson = JSON.parse(serverJsonText) as { description?: unknown };

describe('npm publish surface audit', () => {
	it('root package has an explicit files allowlist', () => {
		expect(pkg.files).toEqual(['dist', 'LICENSE', 'README.md']);
	});

	it('root package files allowlist excludes internal repo surfaces', () => {
		const files = Array.isArray(pkg.files) ? pkg.files.map(String) : [];
		const forbidden = ['.github', '.dev', 'docs', 'scripts', 'test', 'src', 'packages', 'crates', 'conductor'];
		const offenders = files.filter((entry) => forbidden.some((prefix) => entry === prefix || entry.startsWith(`${prefix}/`)));

		expect(offenders, `Root package.json files allowlist exposes internal paths: ${offenders.join(', ')}`).toEqual([]);
	});

	it('MCP Registry description fits the published schema limit', () => {
		expect(typeof serverJson.description).toBe('string');
		expect(
			(serverJson.description as string).length,
			'MCP Registry rejects server.json descriptions longer than 100 characters',
		).toBeLessThanOrEqual(100);
	});
});
