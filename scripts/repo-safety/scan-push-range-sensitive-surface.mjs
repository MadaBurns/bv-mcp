#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
	formatFindings,
	normalizePolicy,
	scanPathForForbiddenSurface,
	scanTextForSensitiveSurface,
	shouldScanFile,
} from './scanner-core.mjs';

const ZERO_SHA = '0000000000000000000000000000000000000000';
const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = execFileSync('git', ['rev-parse', '--show-toplevel'], { encoding: 'utf8' }).trim();
const policy = normalizePolicy(JSON.parse(readFileSync(join(scriptDir, 'policy.json'), 'utf8')));

function git(args, options = {}) {
	return execFileSync('git', args, { cwd: repoRoot, encoding: 'utf8', ...options }).trim();
}

function tryGit(args) {
	try {
		return git(args);
	} catch {
		return '';
	}
}

function gitSucceeds(args) {
	try {
		git(args);
		return true;
	} catch {
		return false;
	}
}

function commitExists(sha) {
	return /^[0-9a-f]{40}$/i.test(sha) && gitSucceeds(['cat-file', '-e', `${sha}^{commit}`]);
}

function rangeForRef(localSha, remoteSha) {
	if (!localSha || localSha === ZERO_SHA) return null;
	if (!commitExists(localSha)) return null;
	if (remoteSha && remoteSha !== ZERO_SHA) {
		return commitExists(remoteSha) ? `${remoteSha}..${localSha}` : localSha;
	}
	const base = tryGit(['merge-base', localSha, 'origin/main']);
	return base ? `${base}..${localSha}` : localSha;
}

function commitsForRange(range) {
	if (!range) return [];
	return git(['rev-list', '--reverse', range])
		.split('\n')
		.map((line) => line.trim())
		.filter(Boolean);
}

function changedFilesForCommit(commit) {
	return git(['diff-tree', '--root', '--no-commit-id', '--name-only', '-r', '--diff-filter=ACMR', commit])
		.split('\n')
		.map((line) => line.trim())
		.filter(Boolean);
}

function blobText(commit, file) {
	try {
		return git(['show', `${commit}:${file}`], { maxBuffer: 10 * 1024 * 1024 });
	} catch {
		return '';
	}
}

function scanCommit(commit) {
	const findings = [];
	for (const file of changedFilesForCommit(commit)) {
		findings.push(...scanPathForForbiddenSurface(file, policy));
		if (shouldScanFile(file, policy)) {
			findings.push(...scanTextForSensitiveSurface(file, blobText(commit, file), policy));
		}
	}
	return findings.map((finding) => ({ ...finding, commit: commit.slice(0, 12) }));
}

const input = readFileSync(0, 'utf8');
const refUpdates = input
	.split(/\r?\n/)
	.map((line) => line.trim())
	.filter(Boolean)
	.map((line) => line.split(/\s+/))
	.filter((parts) => parts.length >= 4);

const findings = [];
for (const [, localSha, , remoteSha] of refUpdates) {
	for (const commit of commitsForRange(rangeForRef(localSha, remoteSha))) {
		findings.push(...scanCommit(commit));
	}
}

if (findings.length > 0) {
	console.error('Repo safety push-range scanner blocked sensitive history:');
	for (const finding of findings) {
		console.error(`${finding.commit} ${formatFindings([finding])}`);
	}
	process.exit(1);
}

console.log('Repo safety push-range scanner found no sensitive history.');
