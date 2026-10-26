// SPDX-License-Identifier: BUSL-1.1
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import { describe, expect, it } from 'vitest';

// Exercise the actual compiler runner without launching the CLI's baseline updater.
const source = readFileSync('scripts/ci/typecheck-tests.mjs', 'utf8');
const runner = source.slice(source.indexOf('function runProject('), source.indexOf('/** Normalize a tsc-reported path'));
function runCompiler(status: number, stdout: string) {
	return runInNewContext(`${runner}\nrunProject('test/tsconfig.json')`, {
		REPO_ROOT: '/repo',
		path: { join: (...parts: string[]) => parts.join('/') },
		existsSync: () => true,
		process: { execPath: '/node' },
		spawnSync: () => ({ status, stdout, stderr: '' }),
		ERROR_LINE: /^(.+?)\((\d+),(\d+)\): error (TS\d+): (.*)$/,
		GLOBAL_ERROR_LINE: /^error TS\d+: /,
		GLOBAL_KEY: '<no-file>',
		normalize: (value: string) => value,
		fail: (message: string) => {
			throw new Error(message);
		},
	});
}

describe('test typecheck compiler exit consistency', () => {
	it.each([1, 2])('rejects exit %s without parseable diagnostics', (status) => {
		expect(() => runCompiler(status, 'Unexpected compiler failure')).toThrow('without parseable diagnostics');
	});
	it('accepts a clean compiler run', () => {
		expect(runCompiler(0, '').counts).toEqual({});
	});
	it('counts a diagnosed compiler failure', () => {
		expect(runCompiler(2, 'test/example.spec.ts(1,2): error TS2322: incompatible type').counts).toEqual({ 'test/example.spec.ts': 1 });
	});
	it('counts file-less compiler diagnostics', () => {
		expect(runCompiler(1, 'error TS2688: missing type library').counts).toEqual({ '<no-file>': 1 });
	});
	it('rejects success with diagnostics and unexpected compiler exits', () => {
		expect(() => runCompiler(0, 'error TS2688: missing type library')).toThrow('reported success');
		expect(() => runCompiler(3, 'compiler crashed')).toThrow('tsc exited 3');
	});
});
