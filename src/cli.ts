#!/usr/bin/env node
// SPDX-License-Identifier: BUSL-1.1

/// <reference types="node" />

import { readFile, writeFile } from 'node:fs/promises';
import { runCli } from './cli/command';

export async function runBlackveilCli(argv = process.argv.slice(2)): Promise<number> {
	return runCli(argv, {
		env: process.env,
		io: {
			readTextFile: (path) => readFile(path, 'utf8'),
			writeTextFile: async (path, content, overwrite) => {
				await writeFile(path, content, { encoding: 'utf8', flag: overwrite ? 'w' : 'wx' });
			},
			stdout: (text) => {
				process.stdout.write(text);
			},
			stderr: (text) => {
				process.stderr.write(text);
			},
		},
	});
}

if (import.meta.url.endsWith('/cli.js')) {
	void runBlackveilCli().then((exitCode) => {
		process.exitCode = exitCode;
	});
}
