/** @vitest-environment node */
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

const scriptPath = join(process.cwd(), 'scripts/license-check.mjs');

describe('dependency-license gate', () => {
	it('passes on the real shipped production tree (all allowlisted licenses)', () => {
		const result = spawnSync('node', [scriptPath], {
			cwd: process.cwd(),
			encoding: 'utf8',
		});

		expect(result.status).toBe(0);
		expect(result.stdout).toContain('all licenses allowlisted');
	});

	it('fails when a production dependency carries a non-allowlisted (GPL) license', () => {
		const tempRoot = mkdtempSync(join(tmpdir(), 'bv-mcp-license-check-'));
		try {
			// Fixture package root: one production dep pointing at a GPL package.
			writeFileSync(
				join(tempRoot, 'package.json'),
				JSON.stringify(
					{
						name: 'license-fixture',
						version: '0.0.0',
						private: true,
						dependencies: {
							'evil-gpl-pkg': '^1.0.0',
						},
					},
					null,
					2,
				),
			);

			const pkgDir = join(tempRoot, 'node_modules', 'evil-gpl-pkg');
			mkdirSync(pkgDir, { recursive: true });
			writeFileSync(
				join(pkgDir, 'package.json'),
				JSON.stringify(
					{
						name: 'evil-gpl-pkg',
						version: '1.2.3',
						license: 'GPL-3.0-only',
					},
					null,
					2,
				),
			);

			const result = spawnSync('node', [scriptPath, '--root', tempRoot], {
				cwd: process.cwd(),
				encoding: 'utf8',
			});

			expect(result.status).not.toBe(0);
			const combined = `${result.stdout}${result.stderr}`;
			expect(combined).toContain('evil-gpl-pkg');
			expect(combined).toContain('GPL-3.0-only');
		} finally {
			rmSync(tempRoot, { recursive: true, force: true });
		}
	});
});
