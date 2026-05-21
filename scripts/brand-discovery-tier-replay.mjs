#!/usr/bin/env node
// SPDX-License-Identifier: BUSL-1.1

/**
 * T11 — n=14 brand-discovery tier replay validator.
 *
 * For every domain (CLI args, or the documented 14-brand default cohort) we
 * invoke the generate-report pipeline twice — once in `tiered` discovery_mode
 * and once in `baseline` (classic) discovery_mode — and copy the resulting
 * report JSON into `.reports/brand-discovery-tier-replay/`.
 *
 * Filenames are deterministic per (brand, mode), so re-running overwrites
 * cleanly:
 *
 *     .reports/brand-discovery-tier-replay/<brand>-tiered.json
 *     .reports/brand-discovery-tier-replay/<brand>-baseline.json
 *
 * Manual validation against the predicted lifts (Google/Nike/PayPal/Apple
 * improve; Microsoft ≥ 40 surfaces; no regressions on ownedPortfolioTotal)
 * happens in T13 — this script is the operator-run replay producer.
 *
 * Mirrors scripts/brand-audit-planner-benchmark.mjs in convention.
 */

import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';

/**
 * The n=14 production-brand cohort from the design doc. Order matches the doc
 * so audit-test failures point clearly at any drift.
 */
const DEFAULT_BRANDS = Object.freeze([
	'google.com',
	'microsoft.com',
	'apple.com',
	'amazon.com',
	'github.com',
	'brand-eta.example.com',
	'brand-zeta.example.com',
	'brand-beta.example.com',
	'brand-epsilon.example.com',
	'brand-gamma.example.com',
	'brand-alpha.example.com',
	'blackveilsecurity.com',
	'brand-delta.example.com',
	'brand-theta.example.com',
]);

/** discovery_mode values, paired per brand. `baseline` → classic downstream. */
const modes = ['tiered', 'baseline'];

const argvDomains = process.argv.slice(2).map((d) => d.trim().toLowerCase()).filter(Boolean);
const domains = argvDomains.length > 0 ? argvDomains : [...DEFAULT_BRANDS];

const outDir = '.reports/brand-discovery-tier-replay';
mkdirSync(outDir, { recursive: true });

const generatedAt = new Date().toISOString();
const indexPath = `${outDir}/index.json`;
const rows = [];

function safeFileStem(value) {
	return value.toLowerCase().replace(/[^a-z0-9.-]+/g, '-').replace(/^-+|-+$/g, '');
}

function readJson(path) {
	return JSON.parse(readFileSync(path, 'utf8'));
}

function extractSidecarMetrics(sidecar) {
	if (!sidecar || typeof sidecar !== 'object') return null;
	const depth = sidecar.depth ?? null;
	const counts = sidecar.counts ?? null;
	const ownedPortfolioTotal =
		typeof sidecar.ownedPortfolio?.total === 'number'
			? sidecar.ownedPortfolio.total
			: typeof counts?.consolidated === 'number' || typeof counts?.shadowIt === 'number' || typeof counts?.indeterminate === 'number'
				? (counts?.consolidated ?? 0) + (counts?.shadowIt ?? 0) + (counts?.indeterminate ?? 0)
				: null;
	return {
		target: typeof sidecar.target === 'string' ? sidecar.target : null,
		generatedAt: typeof sidecar.generatedAt === 'string' ? sidecar.generatedAt : null,
		counts,
		ownedPortfolioTotal,
		consolidated: counts?.consolidated ?? null,
		shadowIt: counts?.shadowIt ?? null,
		registrarSprawl: Array.isArray(sidecar.registrarSprawl) ? sidecar.registrarSprawl.length : null,
		vendorDependencies: Array.isArray(sidecar.vendorDependencies) ? sidecar.vendorDependencies.length : null,
		impersonation: counts?.impersonation ?? null,
		tiers: sidecar.performance?.tiers ?? null,
		discoveryMode: sidecar.discoveryMode ?? null,
		warnings: Array.isArray(depth?.warnings) ? depth.warnings : [],
	};
}

function writeIndexSnapshot() {
	writeFileSync(
		indexPath,
		JSON.stringify(
			{
				generatedAt,
				updatedAt: new Date().toISOString(),
				domains,
				modes,
				rows,
			},
			null,
			2,
		),
	);
}

writeIndexSnapshot();

for (const domain of domains) {
	for (const mode of modes) {
		const stem = safeFileStem(domain);
		const rowRunId = `tier-replay-${stem}-${mode}`;
		const startedAt = Date.now();
		console.log(`[tier-replay] start domain=${domain} mode=${mode}`);

		// `baseline` collapses to classic downstream — the pipeline accepts
		// 'classic' | 'tiered' (src/schemas/tool-args.ts). Aliased here so the
		// CLI argv / output filenames read in benchmark terms.
		const discoveryMode = mode === 'baseline' ? 'classic' : 'tiered';

		const child = spawnSync('npm', ['run', 'generate-report', '--', domain], {
			env: {
				...process.env,
				BV_REPORT_DISCOVERY_MODE: discoveryMode,
				BV_REPORT_RUN_ID: rowRunId,
			},
			encoding: 'utf8',
			maxBuffer: 10 * 1024 * 1024,
		});

		const finalJsonPath = `reports/${domain}-discovery-report.json`;
		const finalPdfPath = `reports/${domain}-discovery-report.pdf`;
		// Deterministic per-(brand, mode) artifact names — idempotent.
		const artifactJsonPath = `${outDir}/${stem}-${mode}.json`;
		const artifactPdfPath = `${outDir}/${stem}-${mode}.pdf`;

		let metrics = null;
		if (child.status === 0 && existsSync(finalJsonPath)) {
			copyFileSync(finalJsonPath, artifactJsonPath);
			try {
				metrics = extractSidecarMetrics(readJson(artifactJsonPath));
			} catch (error) {
				metrics = { error: error instanceof Error ? error.message : String(error) };
			}
		}
		if (child.status === 0 && existsSync(finalPdfPath)) {
			copyFileSync(finalPdfPath, artifactPdfPath);
		}

		const row = {
			domain,
			mode,
			discoveryMode,
			exitCode: child.status,
			elapsedMs: Date.now() - startedAt,
			artifactJsonPath: existsSync(artifactJsonPath) ? artifactJsonPath : null,
			artifactPdfPath: existsSync(artifactPdfPath) ? artifactPdfPath : null,
			metrics,
			stdoutTail: (child.stdout ?? '').slice(-2000),
			stderrTail: (child.stderr ?? '').slice(-2000),
		};
		rows.push(row);
		writeIndexSnapshot();
		console.log(
			`[tier-replay] done domain=${domain} mode=${mode} exit=${row.exitCode} elapsedMs=${row.elapsedMs} artifact=${artifactJsonPath}`,
		);
	}
}

console.log('');
console.log(`Wrote ${rows.length} row(s) across ${domains.length} domain(s) to ${indexPath}`);
