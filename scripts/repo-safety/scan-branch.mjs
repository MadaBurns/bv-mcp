#!/usr/bin/env node
// Survey-only scanner: reads files from a given git ref's tree and counts findings.
// Uses the same rules as scan-sensitive-surface.mjs but operates against `git show <ref>:<path>` instead of the working tree, so it can audit branches without checkout.
import { execFileSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';
import { normalizePolicy, scanFileContent } from './scanner-core.mjs';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const ref = process.argv[2];
if (!ref) {
	console.error('Usage: node scripts/repo-safety/scan-branch.mjs <git-ref> [--with-client-domains]');
	process.exit(2);
}
const enableClientDomains = process.argv.includes('--with-client-domains');

const basePolicy = JSON.parse(readFileSync(join(scriptDir, 'policy.json'), 'utf8'));
const policy = normalizePolicy({
	...basePolicy,
	forbiddenClientDomains: enableClientDomains
		? [
				'amazon.com', 'apple.com', 'brand-eta.com', 'brand-zeta.com',
				'brand-beta.com', 'brand-beta.com.au', 'github.com', 'google.com',
				'brand-iota.com', 'brand-kappa.com', 'brand-theta.com',
				'microsoft.com', 'brand-gamma.com', 'paypal.com', 'stripe.com',
				'brand-lambda.com', 'brand-mu.com', 'brand-mu.com.au', 'brand-alpha.com',
			]
		: basePolicy.forbiddenClientDomains ?? [],
});

const files = execFileSync('git', ['ls-tree', '-r', '--name-only', '-z', ref], { encoding: 'utf8' })
	.split('\0')
	.filter(Boolean);

const buckets = new Map();
for (const file of files) {
	let text = '';
	try {
		text = execFileSync('git', ['show', `${ref}:${file}`], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
	} catch {
		continue;
	}
	const findings = scanFileContent(file, text, policy);
	for (const f of findings) {
		const key = `${f.ruleId}`;
		buckets.set(key, (buckets.get(key) ?? 0) + 1);
	}
}

const total = [...buckets.values()].reduce((a, b) => a + b, 0);
const breakdown = [...buckets.entries()].sort((a, b) => b[1] - a[1]).map(([k, v]) => `${k}=${v}`).join(' ');
console.log(`${ref}: total=${total} ${breakdown}`);
