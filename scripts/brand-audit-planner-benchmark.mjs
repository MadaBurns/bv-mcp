#!/usr/bin/env node
// SPDX-License-Identifier: BUSL-1.1

import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { formatAcceptanceSummary, summarizeBenchmark } from './brand-audit-planner-benchmark-summary.mjs';

const modes = ['observe', 'enforce'];
const domains = process.argv.slice(2).filter(Boolean);
if (domains.length === 0) {
	console.error('Usage: node scripts/brand-audit-planner-benchmark.mjs <domain> [domain...]');
	process.exit(1);
}

const outDir = '.reports/brand-audit-planner-benchmark';
mkdirSync(outDir, { recursive: true });

const benchmarkRunId = `benchmark-${Date.now()}`;
const outPath = `${outDir}/${benchmarkRunId}.json`;
const rows = [];
const generatedAt = new Date().toISOString();

function safeFileStem(value) {
	return value.toLowerCase().replace(/[^a-z0-9.-]+/g, '-').replace(/^-+|-+$/g, '');
}

function readJson(path) {
	return JSON.parse(readFileSync(path, 'utf8'));
}

function extractSidecarMetrics(sidecar) {
	const depth = sidecar && typeof sidecar === 'object' ? sidecar.depth : null;
	const plannerEfficiency = depth && typeof depth === 'object' ? depth.plannerEfficiency ?? null : null;
	return {
		auditId: typeof sidecar?.auditId === 'string' ? sidecar.auditId : null,
		sourceMode: typeof sidecar?.sourceMode === 'string' ? sidecar.sourceMode : null,
		counts: sidecar?.counts ?? null,
		candidateUniverse: depth?.candidateUniverse ?? null,
		signalCoverage: depth?.signalCoverage ?? null,
		plannerEfficiency,
		candidateSignalProbes: plannerEfficiency?.candidateSignalProbes ?? null,
		baselineCandidateSignalProbes: plannerEfficiency?.baselineCandidateSignalProbes ?? null,
		wouldProbeBySignal: plannerEfficiency?.wouldProbeBySignal ?? null,
		wouldDropBySignal: plannerEfficiency?.wouldDropBySignal ?? null,
		warnings: Array.isArray(depth?.warnings) ? depth.warnings : [],
	};
}

function writeSnapshot() {
	const acceptance = summarizeBenchmark({ rows });
	writeFileSync(
		outPath,
		JSON.stringify(
			{
				generatedAt,
				updatedAt: new Date().toISOString(),
				rows,
				acceptance,
			},
			null,
			2,
		),
	);
}

writeSnapshot();
for (const domain of domains) {
	for (const mode of modes) {
		const rowRunId = `${benchmarkRunId}-${safeFileStem(domain)}-${mode}`;
		const startedAt = Date.now();
		console.log(`[benchmark] start domain=${domain} mode=${mode}`);
		const child = spawnSync('npm', ['run', 'generate-report', '--', domain], {
			env: { ...process.env, BV_BRAND_AUDIT_PLANNER_MODE: mode, BV_REPORT_RUN_ID: rowRunId },
			encoding: 'utf8',
			maxBuffer: 10 * 1024 * 1024,
		});

		const finalJsonPath = `reports/${domain}-discovery-report.json`;
		const finalPdfPath = `reports/${domain}-discovery-report.pdf`;
		const artifactJsonPath = `${outDir}/${rowRunId}.json`;
		const artifactPdfPath = `${outDir}/${rowRunId}.pdf`;
		let metrics = null;
		if (child.status === 0 && existsSync(finalJsonPath)) {
			copyFileSync(finalJsonPath, artifactJsonPath);
			metrics = extractSidecarMetrics(readJson(artifactJsonPath));
		}
		if (child.status === 0 && existsSync(finalPdfPath)) {
			copyFileSync(finalPdfPath, artifactPdfPath);
		}

		const row = {
			domain,
			mode,
			exitCode: child.status,
			elapsedMs: Date.now() - startedAt,
			artifactJsonPath: existsSync(artifactJsonPath) ? artifactJsonPath : null,
			artifactPdfPath: existsSync(artifactPdfPath) ? artifactPdfPath : null,
			metrics,
			stdoutTail: child.stdout.slice(-2000),
			stderrTail: child.stderr.slice(-2000),
		};
		rows.push(row);
		writeSnapshot();
		console.log(`[benchmark] done domain=${domain} mode=${mode} exit=${row.exitCode} elapsedMs=${row.elapsedMs} artifact=${artifactJsonPath}`);
	}
}

console.log('');
console.log(formatAcceptanceSummary(summarizeBenchmark({ rows })));
console.log('');
console.log(outPath);
