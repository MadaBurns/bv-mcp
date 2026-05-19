#!/usr/bin/env node
// SPDX-License-Identifier: BUSL-1.1

import { copyFileSync, mkdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';

const domains = process.argv.slice(2).map((domain) => domain.trim().toLowerCase()).filter(Boolean);
if (domains.length === 0) {
	console.error('Usage: node scripts/promote-brand-report.mjs <domain> [domain...]');
	process.exit(1);
}

mkdirSync('.csc', { recursive: true });

for (const domain of domains) {
	const qa = spawnSync(process.execPath, ['scripts/audits/brand-report-qa.mjs', domain], {
		stdio: 'inherit',
	});
	if (qa.status !== 0) {
		console.error(`QA failed for ${domain}; not promoting.`);
		process.exit(qa.status ?? 1);
	}
	copyFileSync(join('reports', `${domain}-discovery-report.json`), join('.csc', `${domain}-discovery-report.json`));
	copyFileSync(join('reports', `${domain}-discovery-report.pdf`), join('.csc', `${domain}-discovery-report.pdf`));
	console.log(`Promoted QA-passing report pair for ${domain} into .csc/.`);
}
