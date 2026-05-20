// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it, vi } from 'vitest';
import type { CheckResult, Finding } from '../src/lib/scoring';
import { createMemoryBrandAuditStepStore } from '../src/lib/brand-audit-step-store';
import { runBrandAuditPipeline } from '../src/lib/brand-audit-pipeline';

function summaryFinding(seedDomain: string, surfaced: number): Finding {
	return {
		category: 'brand_discovery',
		title: `Brand-domain discovery: ${surfaced} candidate(s) at confidence ≥ 0.5`,
		severity: 'info',
		detail: `Seed=${seedDomain}`,
		metadata: { summary: true, signals: ['ns'], signalStatus: {}, minConfidence: 0.5, totalAggregated: surfaced, surfaced },
	};
}

function candidateFinding(domain: string): Finding {
	return {
		category: 'brand_discovery',
		title: `Discovered candidate: ${domain}`,
		severity: 'low',
		detail: 'Found via ns; combined confidence 0.95.',
		metadata: { candidate: domain, signals: ['ns'], combinedConfidence: 0.95, sources: {} },
	};
}

function discoveryResult(seedDomain: string, candidates: string[]): CheckResult {
	return {
		category: 'brand_discovery',
		score: 100,
		findings: [summaryFinding(seedDomain, candidates.length), ...candidates.map(candidateFinding)],
	};
}

function rdapResult(registrar: string, registrant: string, registrarIanaId: string | null = null): CheckResult {
	return {
		category: 'rdap',
		score: 100,
		findings: [
			{
				category: 'rdap',
				title: 'RDAP registrar',
				severity: 'info',
				detail: registrar,
				metadata: { registrar, registrarIanaId, registrarSource: 'rdap', registrant },
			},
		],
	};
}

describe('runBrandAuditPipeline', () => {
	it('persists partial discovery progress before discovery completes', async () => {
		const stepStore = createMemoryBrandAuditStepStore();
		const discoverBrandDomains = vi.fn(async (_seed: string, options?: { onProgress?: (event: unknown) => Promise<void> }) => {
			await options?.onProgress?.({
				name: 'signal_sweep',
				status: 'started',
				startedAtMs: 1_800_000_000_050,
				detail: { signals: ['ns'], probedCandidates: 2 },
			});
			const partial = await stepStore.get('aud-progress', 'example.com', 'discovery');
			expect(partial?.status).toBe('partial');
			expect(partial?.payload).toMatchObject({
				telemetry: {
					events: [
						{
							name: 'signal_sweep',
							status: 'started',
							startedAtMs: 1_800_000_000_050,
							detail: { signals: ['ns'], probedCandidates: 2 },
						},
					],
				},
			});
			return discoveryResult('example.com', ['example.net']);
		});
		const checkRdapLookup = vi.fn().mockResolvedValue(rdapResult('MarkMonitor Inc.', 'Example Inc.'));

		await runBrandAuditPipeline(
			'example.com',
			{ auditId: 'aud-progress', stepStore },
			{ discoverBrandDomains: discoverBrandDomains as never, checkRdapLookup },
		);

		const completed = await stepStore.get('aud-progress', 'example.com', 'discovery');
		expect(completed?.status).toBe('completed');
		expect(discoverBrandDomains).toHaveBeenCalled();
	});

	it('reuses a completed discovery step and continues with RDAP enrichment', async () => {
		const stepStore = createMemoryBrandAuditStepStore();
		await stepStore.put({
			auditId: 'aud-1',
			target: 'example.com',
			step: 'discovery',
			status: 'completed',
			payload: discoveryResult('example.com', ['example.net']),
		});
		const discoverBrandDomains = vi.fn().mockResolvedValue(discoveryResult('example.com', []));
		const checkRdapLookup = vi.fn().mockResolvedValue(rdapResult('MarkMonitor Inc.', 'Example Inc.'));

		const result = await runBrandAuditPipeline('example.com', { auditId: 'aud-1', stepStore }, { discoverBrandDomains, checkRdapLookup });

		expect(discoverBrandDomains).not.toHaveBeenCalled();
		expect(checkRdapLookup).toHaveBeenCalled();
		expect(result.findings.some((f) => f.metadata?.summary === true)).toBe(true);
	});

	it('reuses completed discovery and registrar enrichment steps before classification', async () => {
		const stepStore = createMemoryBrandAuditStepStore();
		await stepStore.put({
			auditId: 'aud-1',
			target: 'example.com',
			step: 'discovery',
			status: 'completed',
			payload: discoveryResult('example.com', ['example.net']),
		});
		await stepStore.put({
			auditId: 'aud-1',
			target: 'example.com',
			step: 'registrar_enrichment',
			status: 'completed',
			payload: {
				targetLookup: { registrar: 'MarkMonitor Inc.', registrarSource: 'rdap', registrant: 'Example Inc.' },
				candidates: [
					{
						candidate: 'example.net',
						lookup: { registrar: 'MarkMonitor Inc.', registrarSource: 'rdap', registrant: 'Example Inc.' },
					},
				],
			},
		});
		const discoverBrandDomains = vi.fn().mockResolvedValue(discoveryResult('example.com', []));
		const checkRdapLookup = vi.fn().mockResolvedValue(rdapResult('MarkMonitor Inc.', 'Example Inc.'));

		const result = await runBrandAuditPipeline('example.com', { auditId: 'aud-1', stepStore }, { discoverBrandDomains, checkRdapLookup });

		expect(discoverBrandDomains).not.toHaveBeenCalled();
		expect(checkRdapLookup).not.toHaveBeenCalled();
		expect(result.findings.some((f) => f.metadata?.summary === true)).toBe(true);
	});

	it('applies resumed registrar enrichment by candidate domain instead of array position', async () => {
		const stepStore = createMemoryBrandAuditStepStore();
		await stepStore.put({
			auditId: 'aud-1',
			target: 'example.com',
			step: 'discovery',
			status: 'completed',
			payload: discoveryResult('example.com', ['first.example.net', 'second.example.net']),
		});
		await stepStore.put({
			auditId: 'aud-1',
			target: 'example.com',
			step: 'registrar_enrichment',
			status: 'completed',
			payload: {
				targetLookup: { registrar: 'MarkMonitor Inc.', registrarSource: 'rdap', registrant: 'Example Inc.' },
				candidates: [
					{
						candidate: 'second.example.net',
						lookup: { registrar: 'Cloudflare Registrar LLC', registrarSource: 'rdap', registrant: 'Second LLC' },
					},
					{
						candidate: 'first.example.net',
						lookup: { registrar: 'MarkMonitor Inc.', registrarSource: 'rdap', registrant: 'Example Inc.' },
					},
				],
			},
		});
		const discoverBrandDomains = vi.fn().mockResolvedValue(discoveryResult('example.com', []));
		const checkRdapLookup = vi.fn().mockResolvedValue(rdapResult('MarkMonitor Inc.', 'Example Inc.'));

		const result = await runBrandAuditPipeline('example.com', { auditId: 'aud-1', stepStore }, { discoverBrandDomains, checkRdapLookup });
		const first = result.findings.find((f) => f.metadata?.candidate === 'first.example.net');
		const second = result.findings.find((f) => f.metadata?.candidate === 'second.example.net');

		expect(checkRdapLookup).not.toHaveBeenCalled();
		expect(first?.metadata?.registrar).toBe('MarkMonitor Inc.');
		expect(first?.metadata?.registrant).toBe('Example Inc.');
		expect(second?.metadata?.registrar).toBe('Cloudflare Registrar LLC');
		expect(second?.metadata?.registrant).toBe('Second LLC');
	});

	it('propagates registrar IANA IDs into classification and result metadata', async () => {
		const discovery = discoveryResult('example.com', ['example.net']);
		const candidate = discovery.findings.find((f) => f.metadata?.candidate === 'example.net');
		candidate!.metadata = {
			...candidate!.metadata,
			signals: ['ns', 'mx_overlap'],
			combinedConfidence: 0.6,
		};
		const checkRdapLookup = vi.fn(async (domain: string) => {
			if (domain === 'example.com') return rdapResult('CSC Corporate Domains, Inc.', 'Target LLC', '299');
			return rdapResult('Corporation Service Company', 'Candidate LLC', '299');
		});

		const result = await runBrandAuditPipeline(
			'example.com',
			{ auditId: 'aud-iana' },
			{ discoverBrandDomains: vi.fn().mockResolvedValue(discovery), checkRdapLookup },
		);
		const summary = result.findings.find((f) => f.metadata?.summary === true);
		const finding = result.findings.find((f) => f.metadata?.candidate === 'example.net');

		expect(summary?.metadata?.targetRegistrarIanaId).toBe('299');
		expect(finding?.metadata).toMatchObject({
			bucket: 'consolidated',
			registrarIanaId: '299',
			registrar: 'Corporation Service Company',
		});
	});

	it('passes evidence observations into classification for replayed weak-only discovery results', async () => {
		const discovery = discoveryResult('example.com', ['upps.com']);
		const candidate = discovery.findings.find((f) => f.metadata?.candidate === 'upps.com');
		candidate!.metadata = {
			...candidate!.metadata,
			signals: ['markov_gen', 'mx_platform'],
			combinedConfidence: 0.5545,
			sharedMxPlatform: 'm365',
			evidenceObservations: [
				{ signal: 'markov_gen' },
				{ signal: 'mx_platform', metadata: { sharedMxPlatform: 'm365' } },
			],
		};
		const checkRdapLookup = vi.fn(async (domain: string) => {
			if (domain === 'example.com') return rdapResult('CSC Corporate Domains, Inc.', 'Target LLC', '299');
			return rdapResult('GoDaddy.com, LLC', 'Candidate LLC', '146');
		});

		const result = await runBrandAuditPipeline(
			'example.com',
			{ auditId: 'aud-evidence' },
			{ discoverBrandDomains: vi.fn().mockResolvedValue(discovery), checkRdapLookup },
		);
		const finding = result.findings.find((f) => f.metadata?.candidate === 'upps.com');

		expect(finding?.metadata).toMatchObject({
			bucket: 'indeterminate',
			reasons: expect.arrayContaining(['weak evidence did not clear ownership gate']),
		});
	});

	it('returns a partial audit result when registrar enrichment hits the deadline after some candidates', async () => {
		const stepStore = createMemoryBrandAuditStepStore();
		const discovery: CheckResult = {
			category: 'brand_discovery',
			score: 100,
			findings: [
				{
					category: 'brand_discovery',
					title: 'summary',
					severity: 'info',
					detail: 'summary',
					metadata: {
						summary: true,
						candidateUniverse: { seeded: 2, probed: 2, surfaced: 2, sources: {}, dropped: {} },
						signalStatus: {},
					},
				},
				{
					category: 'brand_discovery',
					title: 'candidate 1',
					severity: 'info',
					detail: 'candidate',
					metadata: { candidate: 'example.net', signals: ['txt_verification'], combinedConfidence: 0.9 },
				},
				{
					category: 'brand_discovery',
					title: 'candidate 2',
					severity: 'info',
					detail: 'candidate',
					metadata: { candidate: 'example.org', signals: ['markov_gen'], combinedConfidence: 0.2 },
				},
			],
		};
		let now = 1_800_000_000_000;
		const checkRdapLookup = vi.fn(async (domain: string) => {
			if (domain === 'example.net') now += 200;
			return rdapResult('MarkMonitor Inc.', 'Example Inc.');
		});

		const result = await runBrandAuditPipeline(
			'example.com',
			{ auditId: 'aud-1', deadlineMs: now + 100, now: () => now, stepStore },
			{ discoverBrandDomains: vi.fn().mockResolvedValue(discovery), checkRdapLookup },
		);
		const summary = result.findings.find((finding) => finding.metadata?.summary === true);
		const skipped = result.findings.find((finding) => finding.metadata?.candidate === 'example.org');
		const enrichment = await stepStore.get('aud-1', 'example.com', 'registrar_enrichment');

		expect(checkRdapLookup).toHaveBeenCalledTimes(2);
		expect(enrichment?.status).toBe('partial');
		expect(summary?.metadata?.performance).toMatchObject({ stepStatusCounts: { partial: 1 } });
		expect(summary?.metadata?.depth).toMatchObject({
			warnings: expect.arrayContaining([
				'Registrar enrichment completed partially; ownership classification may require manual review.',
			]),
		});
		expect(skipped?.metadata).toMatchObject({
			bucket: 'indeterminate',
			registrar: 'Unknown',
			registrarSource: 'unknown',
			registrarEnrichmentStatus: 'skipped_deadline',
		});
	});

	it('threads discovery planner efficiency into the depth summary', async () => {
		const discovery = discoveryResult('example.com', ['example.net']);
		const summary = discovery.findings.find((finding) => finding.metadata?.summary === true);
		summary!.metadata = {
			...summary!.metadata,
			candidateUniverse: { seeded: 12, probed: 12, surfaced: 1, dropped: {}, sources: {} },
			signalStatus: { ns: { status: 'ok' } },
			discoveryPerformance: {
				efficiency: {
					candidateSignalProbes: 30,
					baselineCandidateSignalProbes: 120,
					surfacedCandidates: 1,
					probesPerSurfacedCandidate: 30,
					plannerMode: 'enforce',
				},
				planner: {
					mode: 'enforce',
					wouldProbeBySignal: { ns: 12, dkim_key_reuse: 8 },
					wouldDropBySignal: { dkim_key_reuse: 4 },
				},
			},
		};
		const checkRdapLookup = vi.fn().mockResolvedValue(rdapResult('MarkMonitor Inc.', 'Example Inc.'));

		const result = await runBrandAuditPipeline(
			'example.com',
			{ auditId: 'aud-planner-efficiency' },
			{ discoverBrandDomains: vi.fn().mockResolvedValue(discovery), checkRdapLookup },
		);
		const pipelineSummary = result.findings.find((finding) => finding.metadata?.summary === true);

		expect(pipelineSummary?.metadata?.depth).toMatchObject({
			plannerEfficiency: {
				mode: 'enforce',
				candidateSignalProbes: 30,
				baselineCandidateSignalProbes: 120,
				surfacedCandidates: 1,
				wouldProbeBySignal: { ns: 12, dkim_key_reuse: 8 },
				wouldDropBySignal: { dkim_key_reuse: 4 },
			},
			warnings: expect.arrayContaining([
				'Discovery planner reduced candidate-backed probes by 75.0%; review recall guard metrics before treating coverage as exhaustive.',
			]),
		});
	});

	it('returns a completed classification step directly', async () => {
		const stepStore = createMemoryBrandAuditStepStore();
		const sentinel: CheckResult = {
			category: 'brand_discovery',
			score: 100,
			findings: [
				{
					category: 'brand_discovery',
					title: 'sentinel classification',
					severity: 'info',
					detail: 'already classified',
					metadata: { summary: true, sentinel: true },
				},
			],
		};
		await stepStore.put({
			auditId: 'aud-1',
			target: 'example.com',
			step: 'classification',
			status: 'completed',
			payload: sentinel,
		});
		const discoverBrandDomains = vi.fn().mockResolvedValue(discoveryResult('example.com', []));
		const checkRdapLookup = vi.fn().mockResolvedValue(rdapResult('MarkMonitor Inc.', 'Example Inc.'));

		const result = await runBrandAuditPipeline('example.com', { auditId: 'aud-1', stepStore }, { discoverBrandDomains, checkRdapLookup });

		expect(discoverBrandDomains).not.toHaveBeenCalled();
		expect(checkRdapLookup).not.toHaveBeenCalled();
		expect(result).toBe(sentinel);
	});
});

// ----------------------------------------------------------------------------
// T13 — BlackVeil-production env-var override for discovery_mode default.
//
// The public schema default in `src/schemas/tool-args.ts` stays `'classic'`
// permanently — BSL self-hosters get classic mode out of the box. BlackVeil's
// production runtime flips its own default to `'tiered'` via the private
// wrangler overlay (`.dev/wrangler.deploy.jsonc`) by setting
// `BRAND_AUDIT_DISCOVERY_MODE_DEFAULT: "tiered"`. The pipeline reads that env
// var via `options.env` and uses `'tiered'` as the *runtime default* — but
// ONLY when the caller hasn't passed an explicit `discovery_mode`. An
// explicit caller value always wins.
//
// This test pins the BSL boundary: the env-var override is opt-in,
// caller-overridable, and a no-op unless the env var is exactly `'tiered'`.
// ----------------------------------------------------------------------------
describe('runBrandAuditPipeline — T13 BRAND_AUDIT_DISCOVERY_MODE_DEFAULT env override', () => {
	it('uses tiered mode by default when env says tiered and caller omits discovery_mode', async () => {
		const discoverBrandDomains = vi.fn().mockResolvedValue(discoveryResult('example.com', ['example.net']));
		const checkRdapLookup = vi.fn().mockResolvedValue(rdapResult('MarkMonitor Inc.', 'Example Inc.'));

		await runBrandAuditPipeline(
			'example.com',
			{ env: { BRAND_AUDIT_DISCOVERY_MODE_DEFAULT: 'tiered' } },
			{ discoverBrandDomains: discoverBrandDomains as never, checkRdapLookup },
		);

		expect(discoverBrandDomains).toHaveBeenCalledOnce();
		const [, discoveryOpts] = discoverBrandDomains.mock.calls[0]!;
		expect((discoveryOpts as { discovery_mode?: string }).discovery_mode).toBe('tiered');
	});

	it('explicit caller discovery_mode wins over env override', async () => {
		const discoverBrandDomains = vi.fn().mockResolvedValue(discoveryResult('example.com', ['example.net']));
		const checkRdapLookup = vi.fn().mockResolvedValue(rdapResult('MarkMonitor Inc.', 'Example Inc.'));

		await runBrandAuditPipeline(
			'example.com',
			{ discovery_mode: 'classic', env: { BRAND_AUDIT_DISCOVERY_MODE_DEFAULT: 'tiered' } },
			{ discoverBrandDomains: discoverBrandDomains as never, checkRdapLookup },
		);

		const [, discoveryOpts] = discoverBrandDomains.mock.calls[0]!;
		expect((discoveryOpts as { discovery_mode?: string }).discovery_mode).toBe('classic');
	});

	it('leaves discovery_mode undefined when env unset (BSL default path)', async () => {
		const discoverBrandDomains = vi.fn().mockResolvedValue(discoveryResult('example.com', ['example.net']));
		const checkRdapLookup = vi.fn().mockResolvedValue(rdapResult('MarkMonitor Inc.', 'Example Inc.'));

		await runBrandAuditPipeline(
			'example.com',
			{},
			{ discoverBrandDomains: discoverBrandDomains as never, checkRdapLookup },
		);

		const [, discoveryOpts] = discoverBrandDomains.mock.calls[0]!;
		expect((discoveryOpts as { discovery_mode?: string }).discovery_mode).toBeUndefined();
	});

	it('ignores env values other than the literal string "tiered"', async () => {
		const discoverBrandDomains = vi.fn().mockResolvedValue(discoveryResult('example.com', ['example.net']));
		const checkRdapLookup = vi.fn().mockResolvedValue(rdapResult('MarkMonitor Inc.', 'Example Inc.'));

		await runBrandAuditPipeline(
			'example.com',
			{ env: { BRAND_AUDIT_DISCOVERY_MODE_DEFAULT: 'classic' } },
			{ discoverBrandDomains: discoverBrandDomains as never, checkRdapLookup },
		);

		const [, discoveryOpts] = discoverBrandDomains.mock.calls[0]!;
		expect((discoveryOpts as { discovery_mode?: string }).discovery_mode).toBeUndefined();
	});

	it('stamps discoveryMode metadata when env-defaulted tiered run surfaces candidates', async () => {
		// When env-default flips tiered, the summary finding must still carry
		// `discoveryMode: 'tiered'` — `brand-audit-markdown.ts` reads this field
		// to drive the v3 sections, and an env-defaulted run must not look any
		// different from an explicitly-tiered run at the report layer.
		const discoverBrandDomains = vi.fn().mockResolvedValue(discoveryResult('example.com', ['example.net']));
		const checkRdapLookup = vi.fn().mockResolvedValue(rdapResult('MarkMonitor Inc.', 'Example Inc.'));

		const result = await runBrandAuditPipeline(
			'example.com',
			{ env: { BRAND_AUDIT_DISCOVERY_MODE_DEFAULT: 'tiered' } },
			{ discoverBrandDomains: discoverBrandDomains as never, checkRdapLookup },
		);

		const summary = result.findings.find((f) => f.metadata?.summary === true);
		expect(summary?.metadata?.discoveryMode).toBe('tiered');
	});
});
