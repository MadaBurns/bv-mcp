#!/usr/bin/env node
// SPDX-License-Identifier: BUSL-1.1

import { existsSync, readFileSync, statSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';

function usage() {
	console.error('Usage: node scripts/audits/brand-report-qa.mjs <domain> [domain...] [--json path --pdf path]');
	process.exit(1);
}

function parseArgs(argv) {
	const domains = [];
	const options = { json: null, pdf: null, reportsDir: 'reports' };
	for (let i = 0; i < argv.length; i++) {
		const arg = argv[i];
		if (arg === '--json') {
			options.json = argv[++i] ?? null;
		} else if (arg === '--pdf') {
			options.pdf = argv[++i] ?? null;
		} else if (arg === '--reports-dir') {
			options.reportsDir = argv[++i] ?? 'reports';
		} else if (arg.startsWith('--')) {
			usage();
		} else {
			domains.push(arg.trim().toLowerCase());
		}
	}
	if (domains.length === 0) usage();
	if ((options.json || options.pdf) && domains.length !== 1) {
		console.error('--json/--pdf overrides are only valid for a single domain.');
		process.exit(1);
	}
	return { domains: domains.filter(Boolean), options };
}

function isObject(value) {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function readJson(path) {
	try {
		return JSON.parse(readFileSync(path, 'utf8'));
	} catch (error) {
		return { __qaError: error instanceof Error ? error.message : String(error) };
	}
}

function pdfPageCount(path) {
	const result = spawnSync('pdfinfo', [path], { encoding: 'utf8' });
	if (result.error && result.error.code === 'ENOENT') return { available: false, pages: null, error: null };
	if (result.error) {
		return { available: true, pages: null, error: result.error.message };
	}
	if (result.status !== 0) {
		const detail = (result.stderr || result.stdout || `exit status ${result.status}`).trim();
		return { available: true, pages: null, error: detail };
	}
	const match = /^Pages:\s*(\d+)/m.exec(result.stdout);
	if (!match) return { available: true, pages: null, error: 'Pages field missing from pdfinfo output' };
	return { available: true, pages: Number(match[1]), error: null };
}

function validateDomain(domain, options) {
	const jsonPath = options.json ?? join(options.reportsDir, `${domain}-discovery-report.json`);
	const pdfPath = options.pdf ?? join(options.reportsDir, `${domain}-discovery-report.pdf`);
	const errors = [];

	if (!existsSync(jsonPath)) errors.push(`missing JSON: ${jsonPath}`);
	if (!existsSync(pdfPath)) errors.push(`missing PDF: ${pdfPath}`);
	if (errors.length > 0) return { domain, ok: false, errors };

	const sidecar = readJson(jsonPath);
	if (sidecar.__qaError) errors.push(`invalid JSON: ${sidecar.__qaError}`);
	if (!isObject(sidecar)) errors.push('JSON sidecar is not an object');
	if (isObject(sidecar)) {
		if (sidecar.target !== domain) errors.push(`target mismatch: expected ${domain}, got ${sidecar.target}`);
		if (!('auditId' in sidecar)) errors.push('missing auditId');
		if (sidecar.sourceMode !== 'local' && (typeof sidecar.auditId !== 'string' || sidecar.auditId.length === 0)) {
			errors.push('auditId must be populated for non-local reports');
		}
		if (typeof sidecar.generatedAt !== 'string' || Number.isNaN(Date.parse(sidecar.generatedAt))) errors.push('missing/invalid generatedAt');
		if (!isObject(sidecar.counts)) errors.push('missing counts');
		if (!isObject(sidecar.depth)) errors.push('missing depth');
		if (!isObject(sidecar.dataQuality)) errors.push('missing dataQuality');
		if (typeof sidecar.depthMode !== 'string') errors.push('missing depthMode');
		const qaSchemaVersion = sidecar.qaSchemaVersion;
		if (qaSchemaVersion !== 1 && qaSchemaVersion !== 2 && qaSchemaVersion !== 3) errors.push('unsupported qaSchemaVersion');
		if (qaSchemaVersion >= 2) {
			if (!isObject(sidecar.performance)) {
				errors.push('missing performance');
			} else {
				if (!isObject(sidecar.performance.stepStatusCounts)) errors.push('missing performance.stepStatusCounts');
				if (!Array.isArray(sidecar.performance.steps)) errors.push('missing performance.steps');
			}
		}
		if (qaSchemaVersion === 3) {
			// v3 (tiered-mode) sidecar: must split owned portfolio + impersonation surface.
			if (!isObject(sidecar.ownedPortfolio)) {
				errors.push('missing ownedPortfolio');
			} else {
				const op = sidecar.ownedPortfolio;
				if (!Array.isArray(op.tenantDeclared)) errors.push('missing ownedPortfolio.tenantDeclared');
				if (!Array.isArray(op.graphSurfaced)) errors.push('missing ownedPortfolio.graphSurfaced');
				if (!Array.isArray(op.declaredEvidence)) errors.push('missing ownedPortfolio.declaredEvidence');
				if (!isObject(op.inferred)) {
					errors.push('missing ownedPortfolio.inferred');
				} else {
					if (!Array.isArray(op.inferred.consolidated)) errors.push('missing ownedPortfolio.inferred.consolidated');
					if (!Array.isArray(op.inferred.shadowIt)) errors.push('missing ownedPortfolio.inferred.shadowIt');
					if (!Array.isArray(op.inferred.indeterminate)) errors.push('missing ownedPortfolio.inferred.indeterminate');
				}
			}
			if (!Array.isArray(sidecar.impersonationSurface)) errors.push('missing impersonationSurface');
			if (isObject(sidecar.performance) && !isObject(sidecar.performance.tiers)) {
				errors.push('missing performance.tiers');
			}
		}
		if (!isObject(sidecar.freshness)) {
			errors.push('missing freshness');
		} else if (sidecar.freshness.sameRun !== true) {
			errors.push('freshness.sameRun must be true');
		}
	}

	const pdfStat = statSync(pdfPath);
	if (pdfStat.size <= 0) errors.push('PDF is empty');
	const pageInfo = pdfPageCount(pdfPath);
	const pages = pageInfo.pages;
	if (pageInfo.available && pageInfo.error) errors.push(`pdfinfo failed: ${pageInfo.error}`);
	if (pages !== null && (!Number.isInteger(pages) || pages <= 0)) errors.push(`pdfinfo page count invalid: ${pages}`);

	return {
		domain,
		ok: errors.length === 0,
		errors,
		jsonPath,
		pdfPath,
		pdfBytes: pdfStat.size,
		pdfPages: pages,
	};
}

const { domains, options } = parseArgs(process.argv.slice(2));
const results = domains.map((domain) => validateDomain(domain, options));
const failed = results.filter((result) => !result.ok);
console.log(JSON.stringify({ ok: failed.length === 0, results }, null, 2));
if (failed.length > 0) process.exit(1);
