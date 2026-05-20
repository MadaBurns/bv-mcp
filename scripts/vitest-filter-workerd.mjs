#!/usr/bin/env node
import { spawn } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const vitestCli = resolve(repoRoot, 'node_modules/vitest/vitest.mjs');
const workerdPeerDisconnectPattern =
	/^exception = workerd\/api\/web-socket\.c\+\+:\d+: disconnected: WebSocket peer disconnected$/;

function createFilteredWriter(target) {
	let pending = '';

	function writeLine(line) {
		if (workerdPeerDisconnectPattern.test(line.trim())) {
			return;
		}

		target.write(`${line}\n`);
	}

	return {
		write(chunk) {
			const text = pending + chunk.toString('utf8');
			const lines = text.split(/\r?\n/);
			pending = text.endsWith('\n') || text.endsWith('\r') ? '' : lines.pop() ?? '';

			for (const line of lines) {
				writeLine(line);
			}
		},
		flush() {
			if (pending.length > 0) {
				writeLine(pending);
				pending = '';
			}
		},
	};
}

const child = spawn(process.execPath, [vitestCli, ...process.argv.slice(2)], {
	cwd: repoRoot,
	env: process.env,
	stdio: ['inherit', 'pipe', 'pipe'],
});

const stdout = createFilteredWriter(process.stdout);
const stderr = createFilteredWriter(process.stderr);

child.stdout.on('data', (chunk) => stdout.write(chunk));
child.stderr.on('data', (chunk) => stderr.write(chunk));

for (const signal of ['SIGINT', 'SIGTERM']) {
	process.on(signal, () => {
		child.kill(signal);
	});
}

child.on('exit', (code, signal) => {
	stdout.flush();
	stderr.flush();

	if (signal) {
		process.kill(process.pid, signal);
		return;
	}

	process.exitCode = code ?? 1;
});
