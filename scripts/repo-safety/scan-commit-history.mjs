#!/usr/bin/env node
// Survey commit messages across history for sensitive wording.
// Always uses the full forbiddenClientDomains list (this is an audit, not a gate).
import { execFileSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';
import { normalizePolicy, scanCommitMessage } from './scanner-core.mjs';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const range = process.argv[2] ?? '--all';

const basePolicy = JSON.parse(readFileSync(join(scriptDir, 'policy.json'), 'utf8'));
const policy = normalizePolicy({
	...basePolicy,
	forbiddenClientDomains: [
		'amazon.com', 'apple.com', 'brand-eta.com', 'brand-zeta.com',
		'brand-beta.com', 'brand-beta.com.au', 'github.com', 'google.com',
		'brand-iota.com', 'brand-kappa.com', 'brand-theta.com',
		'microsoft.com', 'brand-gamma.com', 'paypal.com', 'stripe.com',
		'brand-lambda.com', 'brand-mu.com', 'brand-mu.com.au', 'brand-alpha.com',
	],
});

const SEP = '<<<<COMMIT-SEP>>>>';
const log = execFileSync(
	'git',
	['log', range, `--format=%H%n%s%n%b%n${SEP}`],
	{ encoding: 'utf8', maxBuffer: 100 * 1024 * 1024 },
);

const commits = log.split(`${SEP}\n`).map((block) => {
	const [sha, ...rest] = block.split('\n');
	return { sha, message: rest.join('\n').trim() };
}).filter((c) => c.sha);

const offenders = [];
for (const { sha, message } of commits) {
	const findings = scanCommitMessage(message, policy);
	if (findings.length > 0) {
		const byRule = new Map();
		for (const f of findings) byRule.set(f.ruleId, (byRule.get(f.ruleId) ?? 0) + 1);
		offenders.push({
			sha: sha.slice(0, 10),
			rules: [...byRule.entries()].map(([k, v]) => `${k}=${v}`).join(' '),
			subject: message.split('\n')[0].slice(0, 80),
		});
	}
}

console.log(`Scanned ${commits.length} commits, ${offenders.length} with sensitive wording.\n`);
for (const o of offenders) {
	console.log(`${o.sha}  ${o.rules.padEnd(40)}  ${o.subject}`);
}
