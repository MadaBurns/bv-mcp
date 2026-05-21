#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { formatFindings, normalizePolicy, scanCommitMessage } from './scanner-core.mjs';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const policy = normalizePolicy(JSON.parse(readFileSync(join(scriptDir, 'policy.json'), 'utf8')));
const messageFile = process.argv[2];

if (!messageFile) {
	console.error('Usage: node scripts/repo-safety/scan-commit-message.mjs <commit-message-file>');
	process.exit(2);
}

const findings = scanCommitMessage(readFileSync(messageFile, 'utf8'), policy);

if (findings.length > 0) {
	console.error('Repo safety commit-message scanner blocked sensitive wording:');
	console.error(formatFindings(findings));
	process.exit(1);
}

console.log('Repo safety commit-message scanner found no sensitive wording.');
