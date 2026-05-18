#!/usr/bin/env node
// SPDX-License-Identifier: BUSL-1.1

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const REPORT_PATH = '.reports/brand-audit-depth-baseline.json';

const domains = process.argv.slice(2).map((domain) => domain.trim().toLowerCase()).filter(Boolean);
if (domains.length === 0) {
	console.error('Usage: node scripts/brand-audit-depth-baseline.mjs <domain> [domain...]');
	process.exit(1);
}

const rows = [];
const failures = [];
for (const domain of domains) {
	const path = join('reports', `${domain}-discovery-report.json`);
	if (!existsSync(path)) {
		failures.push({ target: domain, reason: 'missingReport', path });
		continue;
	}
	try {
		const sidecar = JSON.parse(readFileSync(path, 'utf8'));
		rows.push({
			target: sidecar.target,
			generatedAt: sidecar.generatedAt,
			counts: sidecar.counts,
			depth: sidecar.depth ?? null,
			dataQuality: sidecar.dataQuality,
		});
	} catch (error) {
		failures.push({
			target: domain,
			reason: 'invalidJson',
			path,
			error: error instanceof Error ? error.message : String(error),
		});
	}
}

mkdirSync('.reports', { recursive: true });
writeFileSync(REPORT_PATH, JSON.stringify({ generatedAt: new Date().toISOString(), rows, failures }, null, 2));
console.log(`Wrote ${REPORT_PATH} for ${rows.length} domain(s), ${failures.length} failure(s).`);
