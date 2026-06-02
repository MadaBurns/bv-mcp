import { describe, expect, it } from 'vitest';
import { buildStructuredScanResult, formatScanReport } from '../src/tools/scan/format-report';
import type { ScanDomainResult } from '../src/tools/scan-domain';
import { SCORING_MODEL_VERSION } from '../src/lib/scoring-version';

describe('format-scan-report', () => {
	it('tolerates a non-resolving result (empty checks/categoryScores/findings)', () => {
		// Mirrors buildNonResolvingResult: grade N/A, resolves:false, nothing scored.
		// Both formatters must iterate empty collections without indexing a fixed
		// category and without throwing.
		const result: ScanDomainResult = {
			domain: 'does-not-exist-zzz.example',
			score: {
				overall: 0,
				grade: 'N/A',
				categoryScores: {} as ScanDomainResult['score']['categoryScores'],
				findings: [],
				summary:
					'does-not-exist-zzz.example does not resolve (NXDOMAIN) — the domain does not exist in DNS, so there is no security posture to assess.',
			},
			checks: [],
			maturity: { stage: 0, label: 'Does not resolve', description: 'no posture', nextStep: 'Confirm the domain is registered.' },
			context: { profile: 'mail_enabled', signals: ['domain does not resolve (NXDOMAIN)'], weights: {} as never, detectedProvider: null },
			cached: false,
			timestamp: '2026-06-02T00:00:00.000Z',
			scoringNote: 'does not resolve',
			adaptiveWeightDeltas: null,
			interactionEffects: [],
			resolves: false,
		};

		const report = formatScanReport(result);
		expect(report).toContain('Overall Score: 0/100 (N/A)');
		expect(report).toContain('does not resolve');

		const structured = buildStructuredScanResult(result);
		expect(structured.grade).toBe('N/A');
		expect(structured.passed).toBe(false);
		expect(Object.keys(structured.categoryScores)).toHaveLength(0);
		expect(structured.findingCounts).toEqual({ critical: 0, high: 0, medium: 0, low: 0 });
		expect(structured.notApplicableCategories).toHaveLength(0);
	});

	it('renders scan summaries without changing report structure', () => {
		const result: ScanDomainResult = {
			domain: 'example.com',
			score: {
				overall: 72,
				grade: 'C+',
				categoryScores: {
					spf: 70,
					dmarc: 80,
					dkim: 65,
					dnssec: 100,
					ssl: 90,
					mta_sts: 50,
					ns: 100,
					caa: 100,
					subdomain_takeover: 100,
					mx: 100,
				},
				findings: [
					{
						category: 'subdomain_takeover',
						title: 'Dangling CNAME',
						severity: 'critical',
						detail: 'Potential takeover vector.',
						metadata: {
							verificationStatus: 'potential',
							confidence: 'heuristic',
							proofRequired: 'authorized_proof_of_control',
						},
					},
				],
				summary: '1 issue(s) found. Grade: C+',
			},
			checks: [],
			cached: true,
			timestamp: '2026-03-07T00:00:00.000Z',
		};

		const report = formatScanReport(result);
		expect(report).toContain('DNS Security Scan: example.com');
		expect(report).toContain('Overall Score: 72/100 (C+)');
		expect(report).toContain('Takeover Verification: potential');
		expect(report).toContain('Proof Required: authorized proof of control');
		expect(report).toContain('Confidence: heuristic');
		expect(report).toContain('Results served from cache');
	});

	it('sanitizes untrusted finding text in scan output', () => {
		const result: ScanDomainResult = {
			domain: 'example.com',
			score: {
				overall: 10,
				grade: 'F',
				categoryScores: {
					spf: 10,
					dmarc: 10,
					dkim: 10,
					dnssec: 10,
					ssl: 10,
					mta_sts: 10,
					ns: 10,
					caa: 10,
					subdomain_takeover: 10,
					mx: 10,
				},
				findings: [
					{
						category: 'subdomain_takeover',
						title: '# injected title',
						severity: 'high',
						detail: '[malicious](https://evil.example) ```payload```',
					},
				],
				summary: '1 finding',
			},
			checks: [],
			maturity: {
				stage: 0,
				label: 'Unprotected',
				description: 'No meaningful protections found.',
			},
			cached: false,
			timestamp: '2026-03-10T00:00:00.000Z',
		};

		const report = formatScanReport(result);
		expect(report).not.toContain('[malicious]');
		expect(report).not.toContain('```');
		expect(report).not.toContain('# injected title');
		expect(report).toContain('injected title');
	});

	it('buildStructuredScanResult returns machine-readable fields', () => {
		const result = {
			domain: 'test.com',
			score: {
				overall: 85,
				grade: 'A',
				categoryScores: {
					spf: 100,
					dmarc: 90,
					dkim: 80,
					dnssec: 100,
					ssl: 100,
					mta_sts: 70,
					ns: 80,
					caa: 90,
					subdomain_takeover: 100,
					mx: 85,
					bimi: 100,
					tlsrpt: 100,
					lookalikes: 100,
				},
				findings: [
					{ category: 'dmarc', title: 'No rua', severity: 'medium', detail: 'No aggregate reporting' },
					{ category: 'ssl', title: 'Weak cipher', severity: 'high', detail: 'Weak cipher suite detected' },
					{ category: 'spf', title: 'SPF ok', severity: 'info', detail: 'SPF configured' },
					{ category: 'dnssec', title: 'DNSSEC critical', severity: 'critical', detail: 'DNSSEC broken' },
					{ category: 'ns', title: 'Low diversity', severity: 'low', detail: 'Single provider' },
				],
				summary: 'Grade: A',
			},
			checks: [],
			maturity: { stage: 3, label: 'Enforcing', description: 'DMARC enforced.', nextStep: '' },
			cached: false,
			timestamp: '2026-03-12T00:00:00.000Z',
		} as ScanDomainResult;

		const structured = buildStructuredScanResult(result);
		expect(structured.domain).toBe('test.com');
		expect(structured.score).toBe(85);
		expect(structured.grade).toBe('A');
		expect(structured.passed).toBe(true);
		expect(structured.maturityStage).toBe(3);
		expect(structured.maturityLabel).toBe('Enforcing');
		expect(structured.categoryScores.spf).toBe(100);
		expect(structured.findingCounts).toEqual({ critical: 1, high: 1, medium: 1, low: 1 });
		expect(structured.timestamp).toBe('2026-03-12T00:00:00.000Z');
		expect(structured.cached).toBe(false);
		// New profile fields default gracefully when context is absent
		expect(structured.scoringProfile).toBe('mail_enabled');
		expect(structured.scoringSignals).toEqual([]);
	});

	it('buildStructuredScanResult handles missing maturity', () => {
		const result = {
			domain: 'no-maturity.com',
			score: {
				overall: 40,
				grade: 'F',
				categoryScores: {
					spf: 10,
					dmarc: 10,
					dkim: 10,
					dnssec: 10,
					ssl: 10,
					mta_sts: 10,
					ns: 10,
					caa: 10,
					subdomain_takeover: 10,
					mx: 10,
					bimi: 10,
					tlsrpt: 10,
					lookalikes: 10,
				},
				findings: [],
				summary: 'Grade: F',
			},
			checks: [],
			cached: true,
			timestamp: '2026-03-12T00:00:00.000Z',
		} as unknown as ScanDomainResult;

		const structured = buildStructuredScanResult(result);
		expect(structured.passed).toBe(false);
		expect(structured.maturityStage).toBeNull();
		expect(structured.maturityLabel).toBeNull();
		expect(structured.findingCounts).toEqual({ critical: 0, high: 0, medium: 0, low: 0 });
	});

	it('stamps the scoring-model version + config hash into the structured result', () => {
		const result = {
			domain: 'stamp.com',
			score: { overall: 50, grade: 'D', categoryScores: {}, findings: [], summary: '' },
			checks: [],
			cached: false,
			timestamp: '2026-06-02T00:00:00.000Z',
		} as unknown as ScanDomainResult;

		const structured = buildStructuredScanResult(result);
		expect(structured.scoringModelVersion).toBe(SCORING_MODEL_VERSION);
		// Un-threaded callers fall back to the default-config marker.
		expect(structured.scoringConfigHash).toBe('default');

		// When an enrichment hash is threaded, it is stamped verbatim.
		const enriched = buildStructuredScanResult(result, { scoringConfigHash: 'abc123' });
		expect(enriched.scoringConfigHash).toBe('abc123');
	});

	it('passes through resolves additively (true/false pass through, undefined omitted)', () => {
		const base = {
			domain: 'r.com',
			score: { overall: 50, grade: 'D', categoryScores: {}, findings: [], summary: '' },
			checks: [],
			cached: false,
			timestamp: '2026-06-02T00:00:00.000Z',
		} as unknown as ScanDomainResult;

		expect(buildStructuredScanResult({ ...base, resolves: true }).resolves).toBe(true);
		expect(buildStructuredScanResult({ ...base, resolves: false }).resolves).toBe(false);
		// undefined → absent (additive-optional; key not present).
		const noResolves = buildStructuredScanResult(base);
		expect(noResolves.resolves).toBeUndefined();
		expect(Object.prototype.hasOwnProperty.call(noResolves, 'resolves')).toBe(false);
	});

	it("passes through resolves:'broken' and renders the broken result without throwing", () => {
		// Mirrors buildDnsBrokenResult: grade N/A, empty checks/categoryScores/findings,
		// resolves:'broken'. The tri-state value must pass through buildStructuredScanResult
		// and both formatters must render it without indexing a fixed category.
		const result: ScanDomainResult = {
			domain: 'broken-dnssec.example',
			score: {
				overall: 0,
				grade: 'N/A',
				categoryScores: {} as ScanDomainResult['score']['categoryScores'],
				findings: [],
				summary: 'broken-dnssec.example DNS resolution is broken (DNSSEC validation failure).',
			},
			checks: [],
			maturity: {
				stage: 0,
				label: 'DNS resolution broken',
				description: 'DNSSEC validation failure',
				nextStep: 'Fix or remove the broken DNSSEC chain.',
			},
			context: { profile: 'mail_enabled', signals: ['DNS resolution broken'], weights: {} as never, detectedProvider: null },
			cached: false,
			timestamp: '2026-06-02T00:00:00.000Z',
			scoringNote: 'DNS resolution broken',
			adaptiveWeightDeltas: null,
			interactionEffects: [],
			resolves: 'broken',
		};

		const structured = buildStructuredScanResult(result);
		expect(structured.resolves).toBe('broken');
		expect(structured.grade).toBe('N/A');
		expect(structured.passed).toBe(false);
		expect(Object.keys(structured.categoryScores)).toHaveLength(0);

		const report = formatScanReport(result);
		expect(report).toContain('Overall Score: 0/100 (N/A)');
		expect(report).toContain('DNS resolution');
	});

	it('full report footer shows the scoring-model version; compact omits it', () => {
		const result = {
			domain: 'footer.com',
			score: { overall: 50, grade: 'D', categoryScores: { spf: 50 }, findings: [], summary: 'x' },
			checks: [],
			cached: false,
			timestamp: '2026-06-02T00:00:00.000Z',
		} as unknown as ScanDomainResult;

		expect(formatScanReport(result, 'full')).toContain(`Scoring model: v${SCORING_MODEL_VERSION}`);
		expect(formatScanReport(result, 'compact')).not.toContain('Scoring model:');
	});
});
