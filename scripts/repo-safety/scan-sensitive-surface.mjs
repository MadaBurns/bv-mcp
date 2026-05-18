#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { formatFindings, normalizePolicy, scanFileContent } from './scanner-core.mjs';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = execFileSync('git', ['rev-parse', '--show-toplevel'], { encoding: 'utf8' }).trim();
const policy = normalizePolicy(JSON.parse(readFileSync(join(scriptDir, 'policy.json'), 'utf8')));
// Scan only tracked files: git ls-files -z
const files = execFileSync('git', ['ls-files', '-z'], { cwd: repoRoot, encoding: 'utf8' })
	.split('\0')
	.filter(Boolean);

const findings = [];

for (const file of files) {
	let text = '';
	try {
		text = readFileSync(join(repoRoot, file), 'utf8');
	} catch {
		text = '';
	}
	findings.push(...scanFileContent(file, text, policy));
}

if (findings.length > 0) {
	console.error('Repo safety scanner blocked sensitive repository surface:');
	console.error(formatFindings(findings));
	process.exit(1);
}

console.log(formatFindings(findings));
