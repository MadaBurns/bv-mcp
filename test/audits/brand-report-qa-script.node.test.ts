// SPDX-License-Identifier: BUSL-1.1

import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { describe, expect, it } from 'vitest';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '../..');
const qaScript = join(repoRoot, 'scripts/audits/brand-report-qa.mjs');

describe('brand report QA script behavior', () => {
	it('accepts qa schema v1 sidecars without performance metadata', () => {
		const workspace = makeWorkspace();
		try {
			writeReportPair(workspace.reportsDir, { qaSchemaVersion: 1 });
			const result = runQa(workspace.reportsDir, fakePdfinfo(workspace.root, { status: 0, stdout: 'Pages: 1\n' }));

			expect(result.status).toBe(0);
			expect(result.stdout).toContain('"ok": true');
		} finally {
			rmSync(workspace.root, { recursive: true, force: true });
		}
	});

	it('rejects qa schema v2 sidecars without performance metadata', () => {
		const workspace = makeWorkspace();
		try {
			writeReportPair(workspace.reportsDir, { qaSchemaVersion: 2 });
			const result = runQa(workspace.reportsDir, fakePdfinfo(workspace.root, { status: 0, stdout: 'Pages: 1\n' }));

			expect(result.status).toBe(1);
			expect(result.stdout).toContain('missing performance');
		} finally {
			rmSync(workspace.root, { recursive: true, force: true });
		}
	});

	it('accepts qa schema v2 sidecars with performance metadata', () => {
		const workspace = makeWorkspace();
		try {
			writeReportPair(workspace.reportsDir, {
				qaSchemaVersion: 2,
				performance: {
					stepStatusCounts: { completed: 1, partial: 0, failed: 0, skipped: 0 },
					steps: [
						{ name: 'discovery', status: 'completed', startedAtMs: 1000, finishedAtMs: 1100, elapsedMs: 100 },
					],
				},
			});
			const result = runQa(workspace.reportsDir, fakePdfinfo(workspace.root, { status: 0, stdout: 'Pages: 2\n' }));

			expect(result.status).toBe(0);
			expect(result.stdout).toContain('"pdfPages": 2');
		} finally {
			rmSync(workspace.root, { recursive: true, force: true });
		}
	});

	it('accepts qa schema v4 sidecars with relationship sections', () => {
		const workspace = makeWorkspace();
		try {
			writeReportPair(workspace.reportsDir, {
				qaSchemaVersion: 4,
				discoveryMode: 'tiered',
				performance: {
					stepStatusCounts: { completed: 1, partial: 0, failed: 0, skipped: 0 },
					steps: [
						{ name: 'discovery', status: 'completed', startedAtMs: 1000, finishedAtMs: 1100, elapsedMs: 100 },
					],
					tiers: {
						tier0Count: 0,
						tier1Count: 0,
						tier2Count: 0,
						tier3Count: 1,
						tier4Count: 0,
						tier0Status: 'ok',
						tier1Status: 'ok',
						tier2Status: 'ok',
						tier3FallbackTriggered: 0,
						optOutsFiltered: 0,
					},
				},
				relationshipSchemaVersion: 1,
				ownedPortfolio: {
					tenantDeclared: [],
					graphSurfaced: [],
					declaredEvidence: [],
					inferred: { consolidated: [], shadowIt: [], indeterminate: [] },
				},
				registrarSprawl: [],
				vendorDependencies: [],
				impersonationSurface: [],
			});
			const result = runQa(workspace.reportsDir, fakePdfinfo(workspace.root, { status: 0, stdout: 'Pages: 2\n' }));

			expect(result.status).toBe(0);
			expect(result.stdout).toContain('"ok": true');
		} finally {
			rmSync(workspace.root, { recursive: true, force: true });
		}
	});

	it('rejects qa schema v4 sidecars missing relationship sections', () => {
		const workspace = makeWorkspace();
		try {
			writeReportPair(workspace.reportsDir, {
				qaSchemaVersion: 4,
				discoveryMode: 'tiered',
				performance: {
					stepStatusCounts: { completed: 1, partial: 0, failed: 0, skipped: 0 },
					steps: [
						{ name: 'discovery', status: 'completed', startedAtMs: 1000, finishedAtMs: 1100, elapsedMs: 100 },
					],
					tiers: {},
				},
				ownedPortfolio: {
					tenantDeclared: [],
					graphSurfaced: [],
					declaredEvidence: [],
					inferred: { consolidated: [], shadowIt: [], indeterminate: [] },
				},
				impersonationSurface: [],
			});
			const result = runQa(workspace.reportsDir, fakePdfinfo(workspace.root, { status: 0, stdout: 'Pages: 2\n' }));

			expect(result.status).toBe(1);
			expect(result.stdout).toContain('missing relationshipSchemaVersion');
			expect(result.stdout).toContain('missing registrarSprawl');
			expect(result.stdout).toContain('missing vendorDependencies');
		} finally {
			rmSync(workspace.root, { recursive: true, force: true });
		}
	});

	it('rejects malformed JSON sidecars and empty PDFs', () => {
		const workspace = makeWorkspace();
		try {
			writeFileSync(join(workspace.reportsDir, 'example.com-discovery-report.json'), '{not json');
			writeFileSync(join(workspace.reportsDir, 'example.com-discovery-report.pdf'), '');

			const result = runQa(workspace.reportsDir, fakePdfinfo(workspace.root, { status: 0, stdout: 'Pages: 1\n' }));

			expect(result.status).toBe(1);
			expect(result.stdout).toContain('invalid JSON');
			expect(result.stdout).toContain('PDF is empty');
		} finally {
			rmSync(workspace.root, { recursive: true, force: true });
		}
	});

	it('rejects unreadable PDFs when pdfinfo is available', () => {
		const workspace = makeWorkspace();
		try {
			writeReportPair(workspace.reportsDir, { qaSchemaVersion: 1 });
			const result = runQa(workspace.reportsDir, fakePdfinfo(workspace.root, {
				status: 2,
				stderr: 'Syntax Error: not a PDF\n',
			}));

			expect(result.status).toBe(1);
			expect(result.stdout).toContain('pdfinfo failed');
			expect(result.stdout).toContain('Syntax Error');
		} finally {
			rmSync(workspace.root, { recursive: true, force: true });
		}
	});
});

function makeWorkspace(): { root: string; reportsDir: string } {
	const root = mkdtempSync(join(tmpdir(), 'brand-report-qa-'));
	const reportsDir = join(root, 'reports');
	mkdirSync(reportsDir);
	return { root, reportsDir };
}

function runQa(reportsDir: string, env: NodeJS.ProcessEnv) {
	return spawnSync(process.execPath, [qaScript, 'example.com', '--reports-dir', reportsDir], {
		cwd: repoRoot,
		encoding: 'utf8',
		env: { ...process.env, ...env },
	});
}

function fakePdfinfo(root: string, options: { status: number; stdout?: string; stderr?: string }): NodeJS.ProcessEnv {
	const binDir = join(root, 'bin');
	mkdirSync(binDir);
	const pdfinfo = join(binDir, 'pdfinfo');
	writeFileSync(
		pdfinfo,
		[
			'#!/usr/bin/env node',
			`process.stdout.write(${JSON.stringify(options.stdout ?? '')});`,
			`process.stderr.write(${JSON.stringify(options.stderr ?? '')});`,
			`process.exit(${options.status});`,
		].join('\n'),
	);
	chmodSync(pdfinfo, 0o755);
	return { PATH: `${binDir}${delimiter}${process.env.PATH ?? ''}` };
}

function writeReportPair(reportsDir: string, overrides: Record<string, unknown>): void {
	writeFileSync(join(reportsDir, 'example.com-discovery-report.pdf'), '%PDF-1.4\n% synthetic non-empty fixture\n');
	writeFileSync(
		join(reportsDir, 'example.com-discovery-report.json'),
		JSON.stringify(
			{
				target: 'example.com',
				auditId: 'audit-test-1',
				generatedAt: '2026-05-18T00:00:00.000Z',
				counts: { candidates: 1 },
				depth: { warnings: [] },
				dataQuality: { warnings: [] },
				depthMode: 'deep',
				freshness: { sameRun: true },
				...overrides,
			},
			null,
			2,
		),
	);
}
