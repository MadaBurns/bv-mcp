// SPDX-License-Identifier: BUSL-1.1

import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const root = fileURLToPath(new URL('../..', import.meta.url));

describe('root package CLI pack smoke', () => {
	it('packs both bins and executes blackveil help', () => {
		execFileSync(`${root}/node_modules/.bin/tsup`, [], { cwd: root, stdio: 'pipe' });
		const pack = JSON.parse(
			execFileSync('npm', ['pack', '--dry-run', '--ignore-scripts', '--json'], { cwd: root, encoding: 'utf8' }),
		) as Array<{
			files: Array<{ path: string }>;
		}>;
		const files = pack[0]?.files.map((entry) => entry.path) ?? [];
		expect(files).toContain('dist/cli.js');
		expect(files).toContain('dist/stdio.js');
		expect(existsSync(`${root}/dist/cli.js`)).toBe(true);
		expect(readFileSync(`${root}/dist/cli.js`, 'utf8')).toContain('#!/usr/bin/env node');
		const help = execFileSync(process.execPath, [`${root}/dist/cli.js`, '--help'], { cwd: root, encoding: 'utf8' });
		expect(help).toContain('BlackVeil hosted DNS security CLI');
	});
});
