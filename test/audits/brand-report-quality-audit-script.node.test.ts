/** @vitest-environment node */
// SPDX-License-Identifier: BUSL-1.1

import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { describe, expect, it } from 'vitest';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '../..');
const auditScript = join(repoRoot, 'scripts/audits/brand-report-quality-audit.mjs');

function writeSidecar(reportsDir: string, domain: string, sidecar: Record<string, unknown>) {
	writeFileSync(
		join(reportsDir, `${domain}-discovery-report.json`),
		JSON.stringify(
			{
				target: domain,
				qaSchemaVersion: 3,
				discoveryMode: 'tiered',
				counts: { consolidated: 0, shadowIt: 0, indeterminate: 0, impersonation: 0 },
				depth: {
					candidateUniverse: { seeded: 150, probed: 150, surfaced: 0, dropped: {}, sources: {} },
					warnings: [],
					registrarCoverage: { knownRatio: 1 },
					signalCoverage: { failed: 0 },
				},
				performance: {
					tiers: {
						tier0Count: 1,
						tier1Count: 0,
						tier2Count: 1,
						tier3Count: 0,
						tier4Count: 0,
						tier0Status: 'ok',
						tier1Status: 'ok',
						tier2Status: 'ok',
						tier3FallbackTriggered: 0,
						optOutsFiltered: 0,
					},
				},
				buckets: { consolidated: [], shadowIt: [], indeterminate: [], impersonation: [] },
				...sidecar,
			},
			null,
			2,
		),
	);
}

describe('brand-report-quality-audit script', () => {
	it('flags zero-result real-brand fixtures and graph-only consolidated findings', () => {
		const root = mkdtempSync(join(tmpdir(), 'brand-report-quality-'));
		const reportsDir = join(root, 'reports');
		mkdirSync(reportsDir);

		try {
			writeSidecar(reportsDir, 'brand.example', {});
			writeSidecar(reportsDir, 'graph-only.example', {
				counts: { consolidated: 1, shadowIt: 0, indeterminate: 0, impersonation: 0 },
				depth: {
					candidateUniverse: { seeded: 150, probed: 150, surfaced: 1, dropped: {}, sources: {} },
					warnings: [],
					registrarCoverage: { knownRatio: 0.5 },
					signalCoverage: { failed: 0 },
				},
				performance: {
					tiers: {
						tier0Count: 0,
						tier1Count: 1,
						tier2Count: 0,
						tier3Count: 0,
						tier4Count: 0,
						tier0Status: 'ok',
						tier1Status: 'ok',
						tier2Status: 'ok',
						tier3FallbackTriggered: 0,
						optOutsFiltered: 0,
					},
				},
				buckets: {
					consolidated: [
						{
							domain: 'unrelated.example',
							bucket: 'consolidated',
							signals: ['markov_gen'],
							registrar: 'Unknown',
							registrarSource: 'unknown',
							combinedConfidence: 0.92,
							reasons: ['tier 1 graph-only'],
						},
					],
					shadowIt: [],
					indeterminate: [],
					impersonation: [],
				},
			});

			const result = spawnSync(process.execPath, [auditScript, '--reports-dir', reportsDir], {
				cwd: repoRoot,
				encoding: 'utf8',
			});

			expect(result.status).toBe(1);
			const parsed = JSON.parse(result.stdout);
			expect(parsed.ok).toBe(false);
			expect(parsed.results).toEqual(
				expect.arrayContaining([
					expect.objectContaining({ domain: 'brand.example', grade: 'weak' }),
					expect.objectContaining({ domain: 'graph-only.example', grade: 'bad' }),
				]),
			);
			expect(parsed.summary).toMatchObject({ total: 2, bad: 1, weak: 1 });
		} finally {
			rmSync(root, { recursive: true, force: true });
		}
	});

	it('fails when the reports directory contains no sidecars', () => {
		const root = mkdtempSync(join(tmpdir(), 'brand-report-quality-empty-'));
		const reportsDir = join(root, 'reports');
		mkdirSync(reportsDir);

		try {
			const result = spawnSync(process.execPath, [auditScript, '--reports-dir', reportsDir], {
				cwd: repoRoot,
				encoding: 'utf8',
			});

			expect(result.status).toBe(1);
			const parsed = JSON.parse(result.stdout);
			expect(parsed.ok).toBe(false);
			expect(parsed.errors).toEqual([`no report sidecars found in ${reportsDir}`]);
			expect(parsed.summary).toMatchObject({ total: 0 });
		} finally {
			rmSync(root, { recursive: true, force: true });
		}
	});

	it('flags impersonation rows that claim no shared infrastructure while listing shared infra signals', () => {
		const root = mkdtempSync(join(tmpdir(), 'brand-report-quality-contradiction-'));
		const reportsDir = join(root, 'reports');
		mkdirSync(reportsDir);

		try {
			writeSidecar(reportsDir, 'google.example', {
				counts: { consolidated: 0, shadowIt: 0, indeterminate: 0, impersonation: 1 },
				depth: {
					candidateUniverse: { seeded: 150, probed: 150, surfaced: 1, dropped: {}, sources: {} },
					warnings: [],
					registrarCoverage: { knownRatio: 0.5 },
					signalCoverage: { failed: 0 },
				},
				buckets: {
					consolidated: [],
					shadowIt: [],
					indeterminate: [],
					impersonation: [
						{
							domain: 'google.co.nz',
							bucket: 'impersonation',
							signals: ['active_lookalike', 'mx_overlap', 'ns'],
							registrar: 'Unknown',
							registrarSource: 'unknown',
							combinedConfidence: 1,
							reasons: ['lookalike score 1.00 >= 0.85', 'no shared infrastructure signal'],
						},
					],
				},
			});

			const result = spawnSync(process.execPath, [auditScript, '--reports-dir', reportsDir], {
				cwd: repoRoot,
				encoding: 'utf8',
			});

			expect(result.status).toBe(1);
			const parsed = JSON.parse(result.stdout);
			expect(parsed.summary).toMatchObject({ total: 1, bad: 1 });
			expect(parsed.results[0]).toMatchObject({
				domain: 'google.example',
				grade: 'bad',
				contradictoryCandidates: ['google.co.nz'],
			});
		} finally {
			rmSync(root, { recursive: true, force: true });
		}
	});

	it('flags shadow IT rows that use shared MX platform plus owned-infra signals', () => {
		const root = mkdtempSync(join(tmpdir(), 'brand-report-quality-shadow-contradiction-'));
		const reportsDir = join(root, 'reports');
		mkdirSync(reportsDir);

		try {
			writeSidecar(reportsDir, 'walmart.example', {
				counts: { consolidated: 0, shadowIt: 1, indeterminate: 0, impersonation: 0 },
				depth: {
					candidateUniverse: { seeded: 150, probed: 150, surfaced: 1, dropped: {}, sources: {} },
					warnings: [],
					registrarCoverage: { knownRatio: 1 },
					signalCoverage: { failed: 0 },
				},
				buckets: {
					consolidated: [],
					shadowIt: [
						{
							domain: 'walmart.org',
							bucket: 'shadowIt',
							signals: ['active_lookalike', 'mx_platform', 'ns'],
							registrar: 'MarkMonitor Inc.',
							registrarSource: 'rdap',
							combinedConfidence: 0.775,
							reasons: ['shared MX platform (proofpoint)', 'lookalike score 1.00 corroborates shared MX platform'],
						},
					],
					indeterminate: [],
					impersonation: [],
				},
			});

			const result = spawnSync(process.execPath, [auditScript, '--reports-dir', reportsDir], {
				cwd: repoRoot,
				encoding: 'utf8',
			});

			expect(result.status).toBe(1);
			const parsed = JSON.parse(result.stdout);
			expect(parsed.summary).toMatchObject({ total: 1, bad: 1 });
			expect(parsed.results[0]).toMatchObject({
				domain: 'walmart.example',
				grade: 'bad',
				contradictoryCandidates: ['walmart.org'],
			});
		} finally {
			rmSync(root, { recursive: true, force: true });
		}
	});

	it('flags Shadow IT rows whose relationship type is an authorized vendor dependency', () => {
		const root = mkdtempSync(join(tmpdir(), 'brand-report-quality-vendor-shadow-'));
		const reportsDir = join(root, 'reports');
		mkdirSync(reportsDir);

		try {
			writeSidecar(reportsDir, 'bank.example', {
				qaSchemaVersion: 4,
				relationshipSchemaVersion: 1,
				registrarSprawl: [],
				vendorDependencies: [
					{
						domain: 'pphosted.example',
						bucket: 'indeterminate',
						relationshipType: 'authorized_vendor_dependency',
						signals: ['spf_include_seed'],
						registrar: 'Example Registrar',
						registrarSource: 'rdap',
					},
				],
				counts: { consolidated: 0, shadowIt: 1, indeterminate: 0, impersonation: 0 },
				depth: {
					candidateUniverse: { seeded: 150, probed: 150, surfaced: 1, dropped: {}, sources: {} },
					warnings: [],
					registrarCoverage: { knownRatio: 1 },
					signalCoverage: { failed: 0 },
				},
				buckets: {
					consolidated: [],
					shadowIt: [
						{
							domain: 'pphosted.example',
							bucket: 'shadowIt',
							relationshipType: 'authorized_vendor_dependency',
							signals: ['spf_include_seed'],
							registrar: 'Example Registrar',
							registrarSource: 'rdap',
							combinedConfidence: 0.85,
							reasons: ['authorized vendor dependency via seed SPF delegation'],
						},
					],
					indeterminate: [],
					impersonation: [],
				},
			});

			const result = spawnSync(process.execPath, [auditScript, '--reports-dir', reportsDir], {
				cwd: repoRoot,
				encoding: 'utf8',
			});

			expect(result.status).toBe(1);
			const parsed = JSON.parse(result.stdout);
			expect(parsed.summary).toMatchObject({ total: 1, bad: 1 });
			expect(parsed.results[0]).toMatchObject({
				domain: 'bank.example',
				grade: 'bad',
				falseShadowItCandidates: ['pphosted.example'],
			});
		} finally {
			rmSync(root, { recursive: true, force: true });
		}
	});
});
