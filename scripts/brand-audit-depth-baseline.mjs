#!/usr/bin/env node
// SPDX-License-Identifier: BUSL-1.1

import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const REPORT_PATH = '.reports/brand-audit-depth-baseline.json';

const domains = process.argv.slice(2).map((domain) => domain.trim().toLowerCase()).filter(Boolean);
if (domains.length === 0) {
	console.error('Usage: node scripts/brand-audit-depth-baseline.mjs <domain> [domain...]');
	process.exit(1);
}

const rows = [];
for (const domain of domains) {
	const path = join('reports', `${domain}-discovery-report.json`);
	const sidecar = JSON.parse(readFileSync(path, 'utf8'));
	rows.push({
		target: sidecar.target,
		generatedAt: sidecar.generatedAt,
		counts: sidecar.counts,
		depth: sidecar.depth ?? null,
		dataQuality: sidecar.dataQuality,
	});
}

mkdirSync('.reports', { recursive: true });
writeFileSync(REPORT_PATH, JSON.stringify({ generatedAt: new Date().toISOString(), rows }, null, 2));
console.log(`Wrote ${REPORT_PATH} for ${rows.length} domain(s).`);
