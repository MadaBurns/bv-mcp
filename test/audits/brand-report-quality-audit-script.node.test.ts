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
});
