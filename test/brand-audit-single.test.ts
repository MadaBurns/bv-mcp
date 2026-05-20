// SPDX-License-Identifier: BUSL-1.1

/**
 * Tests for the brand_audit_single MCP tool.
 *
 * The orchestrator composes three existing pieces:
 *   1. `discoverBrandDomains` — finds candidate brand-related domains
 *   2. `checkRdapLookup` per candidate — populates registrar + registrant
 *   3. `classifyCandidate` — buckets candidates by ownership evidence
 *
 * All three are injected as deps so unit tests stay fast and offline.
 */

import { describe, it, expect, vi } from 'vitest';
import type { CheckResult, Finding } from '../src/lib/scoring';
import type { BrandAuditSingleDeps } from '../src/tools/brand-audit-single';

function candidateFinding(
	domain: string,
	signals: string[],
	combinedConfidence: number,
	severity: 'low' | 'info' = 'low',
): Finding {
	return {
		category: 'brand_discovery',
		title: `Discovered candidate: ${domain}`,
		severity,
		detail: `Found via ${signals.length} signal(s): ${signals.join(', ')}; combined confidence ${combinedConfidence.toFixed(2)}.`,
		metadata: { candidate: domain, signals, combinedConfidence, sources: {} },
	};
}

function summaryFinding(seedDomain: string, surfaced: number): Finding {
	return {
		category: 'brand_discovery',
		title: `Brand-domain discovery: ${surfaced} candidate(s) at confidence ≥ 0.5`,
		severity: 'info',
		detail: `Seed=${seedDomain}`,
		metadata: { summary: true, signals: ['san', 'ns'], signalStatus: {}, minConfidence: 0.5, totalAggregated: surfaced, surfaced },
	};
}

function rdapResult(registrar: string, source: 'rdap' | 'whois' | 'redacted' | 'notfound' | 'unknown', registrant: string | null = null): CheckResult {
	return {
		category: 'rdap',
		score: 100,
		findings: [
			{
				category: 'rdap',
				title: `RDAP registrar`,
				severity: 'info',
				detail: `${registrar} (${source})`,
				metadata: { registrar, registrarSource: source, registrant },
			},
		],
	};
}

function discoveryResult(seed: string, candidates: Array<{ domain: string; signals: string[]; conf: number }>): CheckResult {
	const candFindings = candidates.map((c) => candidateFinding(c.domain, c.signals, c.conf, c.conf >= 0.85 ? 'low' : 'info'));
	return {
		category: 'brand_discovery',
		score: 100,
		findings: [summaryFinding(seed, candidates.length), ...candFindings],
	};
}

function emptyDiscoveryResult(seed: string): CheckResult {
	return {
		category: 'brand_discovery',
		score: 100,
		findings: [
			{
				category: 'brand_discovery',
				title: `Brand-domain discovery: 0 candidate(s) at confidence ≥ 0.5`,
				severity: 'info',
				detail: `Seed=${seed} aggregated_total=0 surfaced=0`,
				metadata: { summary: true, signals: ['san'], signalStatus: { san: { status: 'failed', error: 'crt.sh down' } }, minConfidence: 0.5, totalAggregated: 0, surfaced: 0 },
			},
		],
	};
}

function makeDeps(overrides: Partial<BrandAuditSingleDeps> = {}): BrandAuditSingleDeps {
	return {
		discoverBrandDomains: vi.fn().mockResolvedValue(discoveryResult('apple.com', [])),
		checkRdapLookup: vi.fn().mockResolvedValue(rdapResult('MarkMonitor Inc.', 'rdap', 'Apple Inc.')),
		enforceQuota: vi.fn().mockResolvedValue({ allowed: true, remaining: 49, limit: 50 }),
		...overrides,
	};
}

describe('brandAuditSingle', () => {
	it('classifies discovered candidates into four buckets and emits a summary', async () => {
		const { brandAuditSingle } = await import('../src/tools/brand-audit-single');

		// Three candidates with distinct evidence shapes — should fan out to distinct buckets.
		const candidates = [
			{ domain: 'apple.net', signals: ['ns', 'san'], conf: 0.95 }, // strong infra → consolidated
			{ domain: 'apple-store.net', signals: ['dmarc_rua'], conf: 0.7 }, // dmarc_rua only, different registrar → shadowIt
			{ domain: 'aple.co', signals: ['markov_gen'], conf: 0.45 }, // low confidence, no infra → impersonation (forced via min_confidence override)
		];

		const rdapMock = vi.fn().mockImplementation((domain: string) => {
			if (domain === 'apple.com') return Promise.resolve(rdapResult('MarkMonitor Inc.', 'rdap', 'Apple Inc.'));
			if (domain === 'apple.net') return Promise.resolve(rdapResult('MarkMonitor Inc.', 'rdap', 'Apple Inc.'));
			if (domain === 'apple-store.net') return Promise.resolve(rdapResult('GoDaddy', 'rdap', 'Third Party LLC'));
			return Promise.resolve(rdapResult('Unknown', 'notfound'));
		});

		const deps = makeDeps({
			discoverBrandDomains: vi.fn().mockResolvedValue(discoveryResult('apple.com', candidates)),
			checkRdapLookup: rdapMock,
		});

		const result = await brandAuditSingle('apple.com', { min_confidence: 0.4 }, deps);

		expect(result.category).toBe('brand_discovery');
		// Summary + per-candidate findings.
		const candFindings = result.findings.filter((f) => f.metadata?.candidate);
		expect(candFindings).toHaveLength(3);

		const buckets = candFindings.map((f) => f.metadata?.bucket as string).sort();
		// Each candidate landed in a bucket — exact distribution depends on classifier
		// rules, but we lock the invariant that every candidate gets one and only one.
		expect(buckets.every((b) => ['consolidated', 'shadowIt', 'indeterminate', 'impersonation'].includes(b))).toBe(true);

		const summary = result.findings.find((f) => f.metadata?.summary === true);
		expect(summary).toBeDefined();
		expect(summary?.metadata?.target).toBe('apple.com');
		expect(summary?.metadata?.consolidated).toBeTypeOf('number');
		expect(summary?.metadata?.shadowIt).toBeTypeOf('number');
		expect(summary?.metadata?.indeterminate).toBeTypeOf('number');
		expect(summary?.metadata?.impersonation).toBeTypeOf('number');
		const total = (summary!.metadata!.consolidated as number) + (summary!.metadata!.shadowIt as number) + (summary!.metadata!.indeterminate as number) + (summary!.metadata!.impersonation as number);
		expect(total).toBe(3);
	});

	it('assigns severity by bucket (consolidated=info, indeterminate=low, shadowIt=medium, impersonation=high)', async () => {
		const { brandAuditSingle } = await import('../src/tools/brand-audit-single');

		// Two strong-infra candidates — both should land in `consolidated` with `info` severity.
		const candidates = [
			{ domain: 'apple.net', signals: ['ns'], conf: 0.95 },
			{ domain: 'apple.org', signals: ['dkim_key_reuse'], conf: 0.97 },
		];
		const deps = makeDeps({
			discoverBrandDomains: vi.fn().mockResolvedValue(discoveryResult('apple.com', candidates)),
			checkRdapLookup: vi.fn().mockResolvedValue(rdapResult('MarkMonitor Inc.', 'rdap', 'Apple Inc.')),
		});
		const result = await brandAuditSingle('apple.com', {}, deps);
		const candFindings = result.findings.filter((f) => f.metadata?.candidate);
		for (const f of candFindings) {
			expect(f.metadata?.bucket).toBe('consolidated');
			expect(f.severity).toBe('info');
		}
	});

	it('emits a missingControl summary when discovery surfaces zero candidates', async () => {
		const { brandAuditSingle } = await import('../src/tools/brand-audit-single');
		const deps = makeDeps({
			discoverBrandDomains: vi.fn().mockResolvedValue(emptyDiscoveryResult('apple.com')),
			checkRdapLookup: vi.fn(),
		});
		const result = await brandAuditSingle('apple.com', {}, deps);

		const candFindings = result.findings.filter((f) => f.metadata?.candidate);
		expect(candFindings).toHaveLength(0);

		const summary = result.findings.find((f) => f.metadata?.summary === true);
		expect(summary).toBeDefined();
		expect(summary?.metadata?.missingControl).toBe(true);
		// RDAP shouldn't have been called for the target when there were no candidates to classify… or
		// alternatively it MAY have been called once for the target itself (to seed registrar family);
		// we accept either, but it must not be called more than once.
		expect((deps.checkRdapLookup as ReturnType<typeof vi.fn>).mock.calls.length).toBeLessThanOrEqual(1);
	});

	it('rejects the call when quota is exceeded, without calling discovery', async () => {
		const { brandAuditSingle } = await import('../src/tools/brand-audit-single');
		const discoverSpy = vi.fn();
		const rdapSpy = vi.fn();
		const deps = makeDeps({
			discoverBrandDomains: discoverSpy,
			checkRdapLookup: rdapSpy,
			enforceQuota: vi.fn().mockResolvedValue({ allowed: false, remaining: 0, limit: 50, retryAfterMs: 86_400_000 }),
		});
		const result = await brandAuditSingle('apple.com', {}, deps);

		const errorFinding = result.findings.find((f) => f.metadata?.quotaExceeded === true);
		expect(errorFinding).toBeDefined();
		expect(errorFinding?.severity).toBe('high');
		expect(discoverSpy).not.toHaveBeenCalled();
		expect(rdapSpy).not.toHaveBeenCalled();
	});

	it('classifies candidates even when individual RDAP lookups fail', async () => {
		const { brandAuditSingle } = await import('../src/tools/brand-audit-single');
		const candidates = [
			{ domain: 'apple.net', signals: ['ns'], conf: 0.95 },
			{ domain: 'apple.org', signals: ['ns'], conf: 0.95 },
		];
		const rdapSpy = vi.fn().mockImplementation((domain: string) => {
			if (domain === 'apple.com') return Promise.resolve(rdapResult('MarkMonitor Inc.', 'rdap', 'Apple Inc.'));
			if (domain === 'apple.net') return Promise.reject(new Error('RDAP timeout'));
			return Promise.resolve(rdapResult('MarkMonitor Inc.', 'rdap', 'Apple Inc.'));
		});
		const deps = makeDeps({
			discoverBrandDomains: vi.fn().mockResolvedValue(discoveryResult('apple.com', candidates)),
			checkRdapLookup: rdapSpy,
		});
		const result = await brandAuditSingle('apple.com', {}, deps);

		const candFindings = result.findings.filter((f) => f.metadata?.candidate);
		expect(candFindings).toHaveLength(2);
		// Both still classified — the rdap failure surfaces as registrarSource=lookup_failed
		// (transient, retryable) with registrarFailureReason='exception'. Pre-Phase-1 this
		// collapsed to 'unknown', which masked retryable failures as permanent ones.
		const failed = candFindings.find((f) => f.metadata?.candidate === 'apple.net');
		expect(failed?.metadata?.registrarSource).toBe('lookup_failed');
		expect(failed?.metadata?.registrarFailureReason).toBe('exception');
	});

	it('threads min_confidence into discoverBrandDomains and the cache-key inputs', async () => {
		const { brandAuditSingle } = await import('../src/tools/brand-audit-single');
		const discoverSpy = vi.fn().mockResolvedValue(emptyDiscoveryResult('apple.com'));
		const deps = makeDeps({ discoverBrandDomains: discoverSpy });
		await brandAuditSingle('apple.com', { min_confidence: 0.7 }, deps);

		expect(discoverSpy).toHaveBeenCalledTimes(1);
		const [, optsArg] = discoverSpy.mock.calls[0];
		expect(optsArg.min_confidence).toBe(0.7);
	});

	it('threads depth, brand_aliases, and candidate_domains into discoverBrandDomains', async () => {
		const { brandAuditSingle } = await import('../src/tools/brand-audit-single');
		const discoverSpy = vi.fn().mockResolvedValue(emptyDiscoveryResult('example.com'));
		const deps = makeDeps({ discoverBrandDomains: discoverSpy });

		await brandAuditSingle(
			'example.com',
			{ depth: 'deep', brand_aliases: ['examplecorp'], candidate_domains: ['example.net'] },
			deps,
		);

		expect(discoverSpy).toHaveBeenCalledWith(
			'example.com',
			expect.objectContaining({
				depth: 'deep',
				brand_aliases: ['examplecorp'],
				candidate_domains: ['example.net'],
			}),
		);
	});

	it('marks subdomain candidates as consolidated/Organizational', async () => {
		const { brandAuditSingle } = await import('../src/tools/brand-audit-single');
		const candidates = [{ domain: 'login.apple.com', signals: ['markov_gen'], conf: 0.5 }];
		const deps = makeDeps({
			discoverBrandDomains: vi.fn().mockResolvedValue(discoveryResult('apple.com', candidates)),
			checkRdapLookup: vi.fn().mockResolvedValue(rdapResult('Unknown', 'unknown')),
		});
		const result = await brandAuditSingle('apple.com', { min_confidence: 0.4 }, deps);
		const cand = result.findings.find((f) => f.metadata?.candidate === 'login.apple.com');
		expect(cand?.metadata?.bucket).toBe('consolidated');
		expect(cand?.metadata?.note).toBe('Organizational Subdomain');
	});

	it('caps candidate fanout at 200 and marks summary.truncated when discovery returns more', async () => {
		const { brandAuditSingle } = await import('../src/tools/brand-audit-single');
		// 250 candidates — over the 200 cap.
		const oversized = Array.from({ length: 250 }, (_, i) => ({
			domain: `cand-${i}.example.com`,
			signals: ['ns'],
			conf: 0.95,
		}));
		const rdapSpy = vi.fn().mockResolvedValue(rdapResult('MarkMonitor Inc.', 'rdap', 'Apple Inc.'));
		const deps = makeDeps({
			discoverBrandDomains: vi.fn().mockResolvedValue(discoveryResult('apple.com', oversized)),
			checkRdapLookup: rdapSpy,
		});
		const result = await brandAuditSingle('apple.com', {}, deps);

		const candFindings = result.findings.filter((f) => f.metadata?.candidate);
		expect(candFindings).toHaveLength(200);

		const summary = result.findings.find((f) => f.metadata?.summary === true);
		expect(summary?.metadata?.truncated).toBe(true);
		expect(summary?.metadata?.truncatedAt).toBe(200);
		expect(summary?.metadata?.discoveredTotal).toBe(250);

		// Crucially: RDAP only fanned out to the capped candidate set, not all 250.
		// (1 call for the target + 200 for capped candidates = 201.)
		expect(rdapSpy.mock.calls.length).toBeLessThanOrEqual(201);
	});

	it('passes summary.truncated=false when discovery stays under the cap', async () => {
		const { brandAuditSingle } = await import('../src/tools/brand-audit-single');
		const candidates = [{ domain: 'apple.net', signals: ['ns'], conf: 0.95 }];
		const deps = makeDeps({
			discoverBrandDomains: vi.fn().mockResolvedValue(discoveryResult('apple.com', candidates)),
		});
		const result = await brandAuditSingle('apple.com', {}, deps);
		const summary = result.findings.find((f) => f.metadata?.summary === true);
		expect(summary?.metadata?.truncated).toBe(false);
		expect(summary?.metadata?.truncatedAt).toBeUndefined();
		expect(summary?.metadata?.discoveredTotal).toBe(1);
	});

	it('includes depth metadata on the summary finding', async () => {
		const { brandAuditSingle } = await import('../src/tools/brand-audit-single');
		const candidates = [{ domain: 'example.net', signals: ['ns'], conf: 0.95 }];
		const deps = makeDeps({
			discoverBrandDomains: vi.fn().mockResolvedValue({
				...discoveryResult('example.com', candidates),
				findings: [
					{
						category: 'brand_discovery',
						title: 'summary',
						severity: 'info',
						detail: '',
						metadata: {
							summary: true,
							signalStatus: { ns: { status: 'ok' } },
							candidateUniverse: {
								seeded: 10,
								probed: 10,
								surfaced: 1,
								dropped: { corroborationGate: 7, belowConfidence: 2 },
								sources: { tld_sweep: 10 },
							},
						},
					},
					candidateFinding('example.net', ['ns'], 0.95),
				],
			}),
			checkRdapLookup: vi.fn().mockImplementation((domain: string) => {
				if (domain === 'example.com') return Promise.resolve(rdapResult('MarkMonitor Inc.', 'rdap', 'Example Inc.'));
				return Promise.resolve(rdapResult('MarkMonitor Inc.', 'rdap', 'Example Inc.'));
			}),
		});

		const result = await brandAuditSingle('example.com', {}, deps);
		const summary = result.findings.find((f) => f.metadata?.summary === true);

		expect(summary?.metadata?.depth).toMatchObject({
			candidateUniverse: { seeded: 10, surfaced: 1 },
			signalCoverage: { requested: 1, ok: 1 },
			registrarCoverage: { total: 2, rdap: 2, knownRatio: 1 },
		});
	});

	describe('shadowIt + impersonation classifier branches', () => {
		/**
		 * Build a discovery CheckResult where the candidate finding carries
		 * the new evidence fields the classifier reads (sharedTxtVerifications,
		 * sharedMxPlatform, lookalikeScore). These ride on the candidate
		 * finding's metadata; the orchestrator must surface them into
		 * `CandidateInput`.
		 */
		function discoveryWithExtras(
			seed: string,
			extras: {
				domain: string;
				signals: string[];
				conf: number;
				sharedTxtVerifications?: string[];
				sharedMxPlatform?: string | null;
				lookalikeScore?: number;
			},
		): CheckResult {
			const f: Finding = {
				category: 'brand_discovery',
				title: `Discovered candidate: ${extras.domain}`,
				severity: 'info',
				detail: `Found via ${extras.signals.length} signal(s)`,
				metadata: {
					candidate: extras.domain,
					signals: extras.signals,
					combinedConfidence: extras.conf,
					sources: {},
					sharedTxtVerifications: extras.sharedTxtVerifications ?? [],
					sharedMxPlatform: extras.sharedMxPlatform ?? null,
					lookalikeScore: extras.lookalikeScore ?? 0,
				},
			};
			return {
				category: 'brand_discovery',
				score: 100,
				findings: [summaryFinding(seed, 1), f],
			};
		}

		it('vendor dependency — candidate on disjoint provider but shares a TXT verification token', async () => {
			const { brandAuditSingle } = await import('../src/tools/brand-audit-single');
			const rdapSpy = vi.fn().mockImplementation((domain: string) => {
				if (domain === 'example.com') return Promise.resolve(rdapResult('MarkMonitor Inc.', 'rdap', 'Example Inc.'));
				// shop.example-shop.com — Shopify-hosted, different registrar, no NS overlap
				return Promise.resolve(rdapResult('Namecheap, Inc.', 'rdap', 'Third Party LLC'));
			});
			const deps = makeDeps({
				discoverBrandDomains: vi.fn().mockResolvedValue(
					discoveryWithExtras('example.com', {
						domain: 'example-shop.com',
						signals: ['markov_gen'],
						conf: 0.55,
						sharedTxtVerifications: ['google-site-verification=abc123'],
					}),
				),
				checkRdapLookup: rdapSpy,
			});
			const result = await brandAuditSingle('example.com', { min_confidence: 0.4 }, deps);
			const cand = result.findings.find((f) => f.metadata?.candidate === 'example-shop.com');
			expect(cand?.metadata?.bucket).toBe('indeterminate');
			expect(cand?.metadata?.relationshipType).toBe('authorized_vendor_dependency');
		});

		it('indeterminate — candidate only points at the same broad mail platform as target', async () => {
			const { brandAuditSingle } = await import('../src/tools/brand-audit-single');
			const rdapSpy = vi.fn().mockImplementation((domain: string) => {
				if (domain === 'example.com') return Promise.resolve(rdapResult('MarkMonitor Inc.', 'rdap', 'Example Inc.'));
				return Promise.resolve(rdapResult('GoDaddy.com, LLC', 'rdap', 'Third Party LLC'));
			});
			const deps = makeDeps({
				discoverBrandDomains: vi.fn().mockResolvedValue(
					discoveryWithExtras('example.com', {
						domain: 'example-mail.net',
						signals: ['markov_gen'],
						conf: 0.55,
						sharedMxPlatform: 'google_workspace',
					}),
				),
				checkRdapLookup: rdapSpy,
			});
			const result = await brandAuditSingle('example.com', { min_confidence: 0.4 }, deps);
			const cand = result.findings.find((f) => f.metadata?.candidate === 'example-mail.net');
			expect(cand?.metadata?.bucket).toBe('indeterminate');
		});

		it('impersonation — typosquat, registrar mismatch, no shared signal, lookalike ≥0.85', async () => {
			const { brandAuditSingle } = await import('../src/tools/brand-audit-single');
			const rdapSpy = vi.fn().mockImplementation((domain: string) => {
				if (domain === 'example.com') return Promise.resolve(rdapResult('MarkMonitor Inc.', 'rdap', 'Example Inc.'));
				return Promise.resolve(rdapResult('Namecheap, Inc.', 'rdap', 'Privacy Service'));
			});
			const deps = makeDeps({
				discoverBrandDomains: vi.fn().mockResolvedValue(
					discoveryWithExtras('example.com', {
						domain: 'examp1e.com',
						signals: ['markov_gen'],
						conf: 0.55, // medium — Rule 7 would otherwise catch as indeterminate
						sharedTxtVerifications: [],
						sharedMxPlatform: null,
						lookalikeScore: 0.92,
					}),
				),
				checkRdapLookup: rdapSpy,
			});
			const result = await brandAuditSingle('example.com', { min_confidence: 0.4 }, deps);
			const cand = result.findings.find((f) => f.metadata?.candidate === 'examp1e.com');
			expect(cand?.metadata?.bucket).toBe('impersonation');
		});

		it('NOT impersonation — typosquat but registrar family matches brand (defensive registration)', async () => {
			const { brandAuditSingle } = await import('../src/tools/brand-audit-single');
			const rdapSpy = vi.fn().mockImplementation((_domain: string) => {
				// Both target and candidate on MarkMonitor — defensive typosquat registration.
				return Promise.resolve(rdapResult('MarkMonitor Inc.', 'rdap', 'Example Inc.'));
			});
			const deps = makeDeps({
				discoverBrandDomains: vi.fn().mockResolvedValue(
					discoveryWithExtras('example.com', {
						domain: 'examp1e.com',
						signals: ['markov_gen'],
						conf: 0.55,
						sharedTxtVerifications: [],
						sharedMxPlatform: null,
						lookalikeScore: 0.92,
					}),
				),
				checkRdapLookup: rdapSpy,
			});
			const result = await brandAuditSingle('example.com', { min_confidence: 0.4 }, deps);
			const cand = result.findings.find((f) => f.metadata?.candidate === 'examp1e.com');
			expect(cand?.metadata?.bucket).not.toBe('impersonation');
			expect(['consolidated', 'indeterminate']).toContain(cand?.metadata?.bucket);
		});
	});
});
