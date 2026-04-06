import { describe, expect, it, vi, beforeEach } from 'vitest';
import { type CheckResult, buildCheckResult, createFinding } from '../src/lib/scoring';
import { resetProviderSignatureState } from '../src/lib/provider-signatures';

describe('scan-post-processing helpers', () => {
	it('downgrades missing email findings for non-mail domains when no MX records exist', async () => {
		vi.doMock('../src/lib/dns', () => ({
			queryTxtRecords: vi.fn().mockResolvedValue(['v=DMARC1; p=reject']),
		}));
		const { applyScanPostProcessing } = await import('../src/tools/scan/post-processing');

		const results: CheckResult[] = [
			buildCheckResult('spf', [createFinding('spf', 'No SPF record found', 'critical', 'No SPF record found for example.com.')]),
			buildCheckResult('mx', [createFinding('mx', 'No MX records found', 'info', 'No inbound mail is configured.')]),
		];

		const updated = await applyScanPostProcessing('app.example.com', results);
		expect(updated[0].findings[0].severity).toBe('info');
		expect(updated[0].findings[0].detail).toContain('expected');
		vi.doUnmock('../src/lib/dns');
	});

	it('clarifies MTA-STS text for mail domains with MX records', async () => {
		const { applyScanPostProcessing } = await import('../src/tools/scan/post-processing');

		const results: CheckResult[] = [
			buildCheckResult('mx', [createFinding('mx', 'MX records found', 'info', '2 MX records configured.')]),
			buildCheckResult('mta_sts', [
				createFinding('mta_sts', 'No MTA-STS or TLS-RPT records found', 'medium', 'Neither MTA-STS nor TLS-RPT DNS records were found.'),
			]),
		];

		const updated = await applyScanPostProcessing('example.com', results);
		const mtaSts = updated.find((r) => r.category === 'mta_sts');
		expect(mtaSts?.findings[0].detail).toContain('has MX records and accepts email');
		expect(mtaSts?.findings[0].detail).toContain('recommended');
	});

	it('does not clarify MTA-STS text when no MX records exist', async () => {
		vi.doMock('../src/lib/dns', () => ({
			queryTxtRecords: vi.fn().mockResolvedValue([]),
		}));
		const { applyScanPostProcessing } = await import('../src/tools/scan/post-processing');

		const results: CheckResult[] = [
			buildCheckResult('mx', [createFinding('mx', 'No MX records found', 'info', 'No inbound mail.')]),
			buildCheckResult('mta_sts', [
				createFinding('mta_sts', 'No MTA-STS or TLS-RPT records found', 'medium', 'Neither MTA-STS nor TLS-RPT DNS records were found.'),
			]),
		];

		const updated = await applyScanPostProcessing('no-mail.example.com', results);
		const mtaSts = updated.find((r) => r.category === 'mta_sts');
		// For non-mail domains, severity gets downgraded to info (not clarified)
		expect(mtaSts?.findings[0].detail).not.toContain('has MX records and accepts email');
		vi.doUnmock('../src/lib/dns');
	});

	it('replaces BIMI "eligible" text with non-mail explanation when domain has no MX records', async () => {
		vi.doMock('../src/lib/dns', () => ({
			queryTxtRecords: vi.fn().mockResolvedValue([]),
		}));
		const { applyScanPostProcessing } = await import('../src/tools/scan/post-processing');

		const results: CheckResult[] = [
			buildCheckResult('mx', [createFinding('mx', 'No MX records found', 'info', 'No inbound mail is configured.')]),
			buildCheckResult('bimi', [
				createFinding(
					'bimi',
					'No BIMI record found',
					'low',
					'No BIMI record found at default._bimi.example.com. This domain has DMARC enforcement and is eligible for BIMI. Publishing a BIMI record allows email clients like Gmail and Apple Mail to display your brand logo next to your emails.',
					{ missingControl: true },
				),
			]),
		];

		const updated = await applyScanPostProcessing('example.com', results);
		const bimi = updated.find((r) => r.category === 'bimi');
		expect(bimi?.findings[0].detail).toContain('does not appear to send email');
		expect(bimi?.findings[0].detail).not.toContain('eligible for BIMI');
		expect(bimi?.findings[0].severity).toBe('low');
		expect(bimi?.findings[0].metadata?.missingControl).toBe(true);
		vi.doUnmock('../src/lib/dns');
	});

	it('preserves BIMI "eligible" text for mail-sending domains with MX records', async () => {
		const { applyScanPostProcessing } = await import('../src/tools/scan/post-processing');

		const results: CheckResult[] = [
			buildCheckResult('mx', [createFinding('mx', 'MX records found', 'info', '2 MX records configured.')]),
			buildCheckResult('bimi', [
				createFinding(
					'bimi',
					'No BIMI record found',
					'low',
					'No BIMI record found at default._bimi.example.com. This domain has DMARC enforcement and is eligible for BIMI. Publishing a BIMI record allows email clients like Gmail and Apple Mail to display your brand logo next to your emails.',
					{ missingControl: true },
				),
			]),
		];

		const updated = await applyScanPostProcessing('example.com', results);
		const bimi = updated.find((r) => r.category === 'bimi');
		expect(bimi?.findings[0].detail).toContain('eligible for BIMI');
		expect(bimi?.findings[0].detail).not.toContain('does not appear to send email');
	});

	it('adds outbound provider inference when SPF include domains match provider signatures', async () => {
		const { applyScanPostProcessing } = await import('../src/tools/scan/post-processing');

		const results: CheckResult[] = [
			buildCheckResult('spf', [createFinding('spf', 'SPF record configured', 'info', 'Healthy SPF', { includeDomains: ['google.com'] })]),
			buildCheckResult('dkim', []),
			buildCheckResult('mx', []),
		];

		const updated = await applyScanPostProcessing('example.com', results);
		const spf = updated.find((result) => result.category === 'spf');
		expect(spf?.findings.some((finding) => finding.title === 'Outbound email provider inferred')).toBe(true);
	});
});

describe('addOutboundProviderInference — provider detection coverage', () => {
	beforeEach(() => {
		resetProviderSignatureState();
		vi.doUnmock('../src/lib/provider-signatures');
		vi.doUnmock('../src/tools/scan/post-processing');
	});

	// -------------------------------------------------------------------------
	// Provider detection via SPF includeDomains
	// -------------------------------------------------------------------------

	it('detects Microsoft 365 via SPF include:spf.protection.outlook.com', async () => {
		const { applyScanPostProcessing } = await import('../src/tools/scan/post-processing');

		const results: CheckResult[] = [
			buildCheckResult('spf', [
				createFinding('spf', 'SPF record configured', 'info', 'SPF ok', {
					includeDomains: ['spf.protection.outlook.com'],
				}),
			]),
			buildCheckResult('mx', [createFinding('mx', 'MX records found', 'info', '2 MX configured.')]),
		];

		const updated = await applyScanPostProcessing('example.com', results);
		const spf = updated.find((r) => r.category === 'spf');
		const inferred = spf?.findings.find((f) => f.title === 'Outbound email provider inferred');
		expect(inferred).toBeDefined();
		expect(inferred?.detail).toContain('Microsoft 365');
		expect(inferred?.metadata?.providers).toEqual(
			expect.arrayContaining([expect.objectContaining({ name: 'Microsoft 365' })]),
		);
	});

	it('detects Amazon SES via SPF include:amazonses.com', async () => {
		const { applyScanPostProcessing } = await import('../src/tools/scan/post-processing');

		const results: CheckResult[] = [
			buildCheckResult('spf', [
				createFinding('spf', 'SPF record configured', 'info', 'SPF ok', {
					includeDomains: ['amazonses.com'],
				}),
			]),
			buildCheckResult('mx', [createFinding('mx', 'MX records found', 'info', '2 MX configured.')]),
		];

		const updated = await applyScanPostProcessing('example.com', results);
		const spf = updated.find((r) => r.category === 'spf');
		const inferred = spf?.findings.find((f) => f.title === 'Outbound email provider inferred');
		expect(inferred).toBeDefined();
		expect(inferred?.detail).toContain('Amazon SES');
	});

	it('detects Google Workspace via SPF include:_spf.google.com (subdomain boundary match)', async () => {
		const { applyScanPostProcessing } = await import('../src/tools/scan/post-processing');

		const results: CheckResult[] = [
			buildCheckResult('spf', [
				createFinding('spf', 'SPF record configured', 'info', 'SPF ok', {
					includeDomains: ['_spf.google.com'],
				}),
			]),
			buildCheckResult('mx', [createFinding('mx', 'MX records found', 'info', '2 MX configured.')]),
		];

		const updated = await applyScanPostProcessing('example.com', results);
		const spf = updated.find((r) => r.category === 'spf');
		const inferred = spf?.findings.find((f) => f.title === 'Outbound email provider inferred');
		expect(inferred).toBeDefined();
		expect(inferred?.detail).toContain('Google Workspace');
	});

	it('detects provider via SPF redirect domain', async () => {
		const { applyScanPostProcessing } = await import('../src/tools/scan/post-processing');

		const results: CheckResult[] = [
			buildCheckResult('spf', [
				createFinding('spf', 'SPF redirect configured', 'info', 'SPF ok', {
					redirectDomain: 'spf.protection.outlook.com',
				}),
			]),
			buildCheckResult('mx', [createFinding('mx', 'MX records found', 'info', '2 MX configured.')]),
		];

		const updated = await applyScanPostProcessing('example.com', results);
		const spf = updated.find((r) => r.category === 'spf');
		const inferred = spf?.findings.find((f) => f.title === 'Outbound email provider inferred');
		expect(inferred).toBeDefined();
		expect(inferred?.detail).toContain('Microsoft 365');
	});

	// -------------------------------------------------------------------------
	// Provider detection via DKIM selectors
	// -------------------------------------------------------------------------

	it('detects Google Workspace via DKIM selector hint "google"', async () => {
		const { applyScanPostProcessing } = await import('../src/tools/scan/post-processing');

		const results: CheckResult[] = [
			buildCheckResult('spf', [createFinding('spf', 'SPF configured', 'info', 'SPF ok')]),
			buildCheckResult('dkim', [
				createFinding('dkim', 'DKIM selectors found', 'info', 'DKIM ok', {
					selectorsFound: ['google'],
				}),
			]),
			buildCheckResult('mx', [createFinding('mx', 'MX records found', 'info', '2 MX configured.')]),
		];

		const updated = await applyScanPostProcessing('example.com', results);
		const spf = updated.find((r) => r.category === 'spf');
		const inferred = spf?.findings.find((f) => f.title === 'Outbound email provider inferred');
		expect(inferred).toBeDefined();
		expect(inferred?.detail).toContain('Google Workspace');
		expect(inferred?.metadata?.signalsUsed?.dkimSelectors).toContain('google');
	});

	it('detects Microsoft 365 via DKIM selector hint "selector1"', async () => {
		const { applyScanPostProcessing } = await import('../src/tools/scan/post-processing');

		const results: CheckResult[] = [
			buildCheckResult('spf', [createFinding('spf', 'SPF configured', 'info', 'SPF ok')]),
			buildCheckResult('dkim', [
				createFinding('dkim', 'DKIM selectors found', 'info', 'DKIM ok', {
					selectorsFound: ['selector1'],
				}),
			]),
			buildCheckResult('mx', [createFinding('mx', 'MX records found', 'info', '2 MX configured.')]),
		];

		const updated = await applyScanPostProcessing('example.com', results);
		const spf = updated.find((r) => r.category === 'spf');
		const inferred = spf?.findings.find((f) => f.title === 'Outbound email provider inferred');
		expect(inferred).toBeDefined();
		expect(inferred?.detail).toContain('Microsoft 365');
		expect(inferred?.metadata?.signalsUsed?.dkimSelectors).toContain('selector1');
	});

	it('detects Microsoft 365 via DKIM selector hint "selector2"', async () => {
		const { applyScanPostProcessing } = await import('../src/tools/scan/post-processing');

		const results: CheckResult[] = [
			buildCheckResult('spf', [createFinding('spf', 'SPF configured', 'info', 'SPF ok')]),
			buildCheckResult('dkim', [
				createFinding('dkim', 'DKIM selectors found', 'info', 'DKIM ok', {
					selectorsFound: ['selector2'],
				}),
			]),
			buildCheckResult('mx', [createFinding('mx', 'MX records found', 'info', '2 MX configured.')]),
		];

		const updated = await applyScanPostProcessing('example.com', results);
		const spf = updated.find((r) => r.category === 'spf');
		const inferred = spf?.findings.find((f) => f.title === 'Outbound email provider inferred');
		expect(inferred).toBeDefined();
		expect(inferred?.detail).toContain('Microsoft 365');
	});

	// -------------------------------------------------------------------------
	// Confidence scoring
	// -------------------------------------------------------------------------

	it('sets confidence 0.65 (built-in source) when no runtime signatures URL is configured', async () => {
		const { applyScanPostProcessing } = await import('../src/tools/scan/post-processing');

		const results: CheckResult[] = [
			buildCheckResult('spf', [
				createFinding('spf', 'SPF configured', 'info', 'SPF ok', {
					includeDomains: ['amazonses.com'],
				}),
			]),
			buildCheckResult('mx', [createFinding('mx', 'MX records found', 'info', '2 MX configured.')]),
		];

		// No runtimeOptions → built-in source (confidence base = 0.65, no boost)
		const updated = await applyScanPostProcessing('example.com', results);
		const inferred = updated.find((r) => r.category === 'spf')?.findings.find((f) => f.title === 'Outbound email provider inferred');
		expect(inferred).toBeDefined();
		expect(inferred?.metadata?.signatureSource).toBe('built-in');
		expect(inferred?.metadata?.providerConfidence).toBeCloseTo(0.65, 5);
	});

	it('boosts confidence to 0.70 (spf + dkim signal) when source is built-in', async () => {
		const { applyScanPostProcessing } = await import('../src/tools/scan/post-processing');

		const results: CheckResult[] = [
			buildCheckResult('spf', [
				createFinding('spf', 'SPF configured', 'info', 'SPF ok', {
					includeDomains: ['google.com'],
				}),
			]),
			buildCheckResult('dkim', [
				createFinding('dkim', 'DKIM selectors found', 'info', 'DKIM ok', {
					selectorsFound: ['google'],
				}),
			]),
			buildCheckResult('mx', [createFinding('mx', 'MX records found', 'info', '2 MX configured.')]),
		];

		// Both SPF + DKIM signals present → +0.05 boost → 0.65 + 0.05 = 0.70
		const updated = await applyScanPostProcessing('example.com', results);
		const inferred = updated.find((r) => r.category === 'spf')?.findings.find((f) => f.title === 'Outbound email provider inferred');
		expect(inferred).toBeDefined();
		expect(inferred?.metadata?.providerConfidence).toBeCloseTo(0.70, 5);
		expect(inferred?.metadata?.signatureSource).toBe('built-in');
	});

	it('sets confidence 0.85 when signatures source is "runtime"', async () => {
		vi.resetModules();
		vi.doMock('../src/lib/provider-signatures', async (importOriginal) => {
			const original = await importOriginal<typeof import('../src/lib/provider-signatures')>();
			return {
				...original,
				loadProviderSignatures: vi.fn().mockResolvedValue({
					source: 'runtime',
					version: 'runtime-test',
					fetchedAt: new Date().toISOString(),
					degraded: false,
					inbound: [{ name: 'Amazon SES', domains: ['amazonses.com'] }],
					outbound: [],
				}),
			};
		});
		const { applyScanPostProcessing } = await import('../src/tools/scan/post-processing');

		const results: CheckResult[] = [
			buildCheckResult('spf', [
				createFinding('spf', 'SPF configured', 'info', 'SPF ok', {
					includeDomains: ['amazonses.com'],
				}),
			]),
			buildCheckResult('mx', [createFinding('mx', 'MX records found', 'info', '2 MX configured.')]),
		];

		const updated = await applyScanPostProcessing('example.com', results);
		const inferred = updated.find((r) => r.category === 'spf')?.findings.find((f) => f.title === 'Outbound email provider inferred');
		expect(inferred).toBeDefined();
		expect(inferred?.metadata?.signatureSource).toBe('runtime');
		expect(inferred?.metadata?.providerConfidence).toBeCloseTo(0.85, 5);
		vi.doUnmock('../src/lib/provider-signatures');
		vi.resetModules();
	});

	it('sets confidence 0.70 when signatures source is "stale"', async () => {
		vi.resetModules();
		vi.doMock('../src/lib/provider-signatures', async (importOriginal) => {
			const original = await importOriginal<typeof import('../src/lib/provider-signatures')>();
			return {
				...original,
				loadProviderSignatures: vi.fn().mockResolvedValue({
					source: 'stale',
					version: 'stale-test',
					fetchedAt: new Date().toISOString(),
					degraded: true,
					inbound: [{ name: 'Amazon SES', domains: ['amazonses.com'] }],
					outbound: [],
				}),
			};
		});
		const { applyScanPostProcessing } = await import('../src/tools/scan/post-processing');

		const results: CheckResult[] = [
			buildCheckResult('spf', [
				createFinding('spf', 'SPF configured', 'info', 'SPF ok', {
					includeDomains: ['amazonses.com'],
				}),
			]),
			buildCheckResult('mx', [createFinding('mx', 'MX records found', 'info', '2 MX configured.')]),
		];

		const updated = await applyScanPostProcessing('example.com', results);
		const inferred = updated.find((r) => r.category === 'spf')?.findings.find((f) => f.title === 'Outbound email provider inferred');
		expect(inferred).toBeDefined();
		expect(inferred?.metadata?.signatureSource).toBe('stale');
		expect(inferred?.metadata?.providerConfidence).toBeCloseTo(0.70, 5);
		vi.doUnmock('../src/lib/provider-signatures');
		vi.resetModules();
	});

	it('boosts confidence by 0.05 when runtime source has both SPF and DKIM signals (capped at 0.90)', async () => {
		vi.resetModules();
		vi.doMock('../src/lib/provider-signatures', async (importOriginal) => {
			const original = await importOriginal<typeof import('../src/lib/provider-signatures')>();
			return {
				...original,
				loadProviderSignatures: vi.fn().mockResolvedValue({
					source: 'runtime',
					version: 'runtime-test',
					fetchedAt: new Date().toISOString(),
					degraded: false,
					inbound: [{ name: 'Google Workspace', domains: ['google.com'], selectorHints: ['google'] }],
					outbound: [],
				}),
			};
		});
		const { applyScanPostProcessing } = await import('../src/tools/scan/post-processing');

		const results: CheckResult[] = [
			buildCheckResult('spf', [
				createFinding('spf', 'SPF configured', 'info', 'SPF ok', {
					includeDomains: ['google.com'],
				}),
			]),
			buildCheckResult('dkim', [
				createFinding('dkim', 'DKIM selectors found', 'info', 'DKIM ok', {
					selectorsFound: ['google'],
				}),
			]),
			buildCheckResult('mx', [createFinding('mx', 'MX records found', 'info', '2 MX configured.')]),
		];

		// runtime base 0.85 + 0.05 boost = 0.90
		const updated = await applyScanPostProcessing('example.com', results);
		const inferred = updated.find((r) => r.category === 'spf')?.findings.find((f) => f.title === 'Outbound email provider inferred');
		expect(inferred).toBeDefined();
		expect(inferred?.metadata?.providerConfidence).toBeCloseTo(0.90, 5);
		vi.doUnmock('../src/lib/provider-signatures');
		vi.resetModules();
	});

	// -------------------------------------------------------------------------
	// Metadata structure
	// -------------------------------------------------------------------------

	it('populates signalsUsed.spfDomains and signalsUsed.dkimSelectors in the inferred finding', async () => {
		const { applyScanPostProcessing } = await import('../src/tools/scan/post-processing');

		const results: CheckResult[] = [
			buildCheckResult('spf', [
				createFinding('spf', 'SPF configured', 'info', 'SPF ok', {
					includeDomains: ['spf.protection.outlook.com'],
				}),
			]),
			buildCheckResult('dkim', [
				createFinding('dkim', 'DKIM selectors found', 'info', 'DKIM ok', {
					selectorsFound: ['selector1'],
				}),
			]),
			buildCheckResult('mx', [createFinding('mx', 'MX records found', 'info', '2 MX configured.')]),
		];

		const updated = await applyScanPostProcessing('example.com', results);
		const inferred = updated.find((r) => r.category === 'spf')?.findings.find((f) => f.title === 'Outbound email provider inferred');
		expect(inferred?.metadata?.signalsUsed?.spfDomains).toContain('spf.protection.outlook.com');
		expect(inferred?.metadata?.signalsUsed?.dkimSelectors).toContain('selector1');
	});

	it('populates providers array with name and matches fields', async () => {
		const { applyScanPostProcessing } = await import('../src/tools/scan/post-processing');

		const results: CheckResult[] = [
			buildCheckResult('spf', [
				createFinding('spf', 'SPF configured', 'info', 'SPF ok', {
					includeDomains: ['amazonses.com'],
				}),
			]),
			buildCheckResult('mx', [createFinding('mx', 'MX records found', 'info', '2 MX configured.')]),
		];

		const updated = await applyScanPostProcessing('example.com', results);
		const inferred = updated.find((r) => r.category === 'spf')?.findings.find((f) => f.title === 'Outbound email provider inferred');
		expect(inferred?.metadata?.providers).toHaveLength(1);
		const provider = (inferred?.metadata?.providers as Array<{ name: string; matches: string[] }>)?.[0];
		expect(provider?.name).toBe('Amazon SES');
		expect(provider?.matches).toContain('amazonses.com');
	});

	it('populates signatureVersion and signatureFetchedAt in the inferred finding', async () => {
		const { applyScanPostProcessing } = await import('../src/tools/scan/post-processing');

		const results: CheckResult[] = [
			buildCheckResult('spf', [
				createFinding('spf', 'SPF configured', 'info', 'SPF ok', {
					includeDomains: ['google.com'],
				}),
			]),
			buildCheckResult('mx', [createFinding('mx', 'MX records found', 'info', '2 MX configured.')]),
		];

		const updated = await applyScanPostProcessing('example.com', results);
		const inferred = updated.find((r) => r.category === 'spf')?.findings.find((f) => f.title === 'Outbound email provider inferred');
		expect(typeof inferred?.metadata?.signatureVersion).toBe('string');
		expect(typeof inferred?.metadata?.signatureFetchedAt).toBe('string');
	});

	it('sets detectionType to "outbound" on the inferred finding', async () => {
		const { applyScanPostProcessing } = await import('../src/tools/scan/post-processing');

		const results: CheckResult[] = [
			buildCheckResult('spf', [
				createFinding('spf', 'SPF configured', 'info', 'SPF ok', {
					includeDomains: ['google.com'],
				}),
			]),
			buildCheckResult('mx', [createFinding('mx', 'MX records found', 'info', '2 MX configured.')]),
		];

		const updated = await applyScanPostProcessing('example.com', results);
		const inferred = updated.find((r) => r.category === 'spf')?.findings.find((f) => f.title === 'Outbound email provider inferred');
		expect(inferred?.metadata?.detectionType).toBe('outbound');
	});

	// -------------------------------------------------------------------------
	// Edge cases
	// -------------------------------------------------------------------------

	it('returns results unmodified when no signals match any provider', async () => {
		const { applyScanPostProcessing } = await import('../src/tools/scan/post-processing');

		const results: CheckResult[] = [
			buildCheckResult('spf', [
				createFinding('spf', 'SPF configured', 'info', 'SPF ok', {
					includeDomains: ['mail.unknownprovider99.example'],
				}),
			]),
			buildCheckResult('mx', [createFinding('mx', 'MX records found', 'info', '2 MX configured.')]),
		];

		const originalFindings = results[0].findings.length;
		const updated = await applyScanPostProcessing('example.com', results);
		const spf = updated.find((r) => r.category === 'spf');
		// No inference finding added
		expect(spf?.findings.find((f) => f.title === 'Outbound email provider inferred')).toBeUndefined();
		expect(spf?.findings).toHaveLength(originalFindings);
	});

	it('returns results unmodified when SPF has no includeDomains and DKIM has no selectorsFound', async () => {
		const { applyScanPostProcessing } = await import('../src/tools/scan/post-processing');

		const results: CheckResult[] = [
			buildCheckResult('spf', [createFinding('spf', 'SPF configured', 'info', 'SPF ok')]),
			buildCheckResult('dkim', [createFinding('dkim', 'No DKIM record found', 'high', 'DKIM missing.')]),
			buildCheckResult('mx', [createFinding('mx', 'MX records found', 'info', '2 MX configured.')]),
		];

		const updated = await applyScanPostProcessing('example.com', results);
		const spf = updated.find((r) => r.category === 'spf');
		expect(spf?.findings.find((f) => f.title === 'Outbound email provider inferred')).toBeUndefined();
	});

	it('does not crash and returns results unchanged when there is no SPF check result at all', async () => {
		vi.doMock('../src/lib/dns', () => ({
			queryTxtRecords: vi.fn().mockResolvedValue([]),
		}));
		const { applyScanPostProcessing } = await import('../src/tools/scan/post-processing');

		const results: CheckResult[] = [
			buildCheckResult('mx', [createFinding('mx', 'No MX records found', 'info', 'No inbound mail.')]),
			buildCheckResult('dkim', [createFinding('dkim', 'No DKIM record found', 'high', 'DKIM missing.')]),
		];

		// Should not throw; no SPF result means no inference possible
		await expect(applyScanPostProcessing('example.com', results)).resolves.not.toThrow();
		const updated = await applyScanPostProcessing('example.com', results);
		expect(updated.find((r) => r.category === 'spf')).toBeUndefined();
		vi.doUnmock('../src/lib/dns');
	});

	it('does not crash when SPF finding has empty includeDomains array', async () => {
		const { applyScanPostProcessing } = await import('../src/tools/scan/post-processing');

		const results: CheckResult[] = [
			buildCheckResult('spf', [
				createFinding('spf', 'SPF configured', 'info', 'SPF ok', { includeDomains: [] }),
			]),
			buildCheckResult('mx', [createFinding('mx', 'MX records found', 'info', '2 MX configured.')]),
		];

		await expect(applyScanPostProcessing('example.com', results)).resolves.not.toThrow();
		const updated = await applyScanPostProcessing('example.com', results);
		const spf = updated.find((r) => r.category === 'spf');
		expect(spf?.findings.find((f) => f.title === 'Outbound email provider inferred')).toBeUndefined();
	});

	it('is additive — preserves existing SPF findings and appends the inferred finding', async () => {
		const { applyScanPostProcessing } = await import('../src/tools/scan/post-processing');

		const results: CheckResult[] = [
			buildCheckResult('spf', [
				createFinding('spf', 'SPF configured', 'info', 'SPF ok', { includeDomains: ['google.com'] }),
				createFinding('spf', 'SPF too many lookups', 'medium', 'SPF lookup count approaching limit.'),
			]),
			buildCheckResult('mx', [createFinding('mx', 'MX records found', 'info', '2 MX configured.')]),
		];

		const updated = await applyScanPostProcessing('example.com', results);
		const spf = updated.find((r) => r.category === 'spf');
		// Original 2 findings preserved
		expect(spf?.findings.some((f) => f.title === 'SPF configured')).toBe(true);
		expect(spf?.findings.some((f) => f.title === 'SPF too many lookups')).toBe(true);
		// Inference finding appended
		expect(spf?.findings.some((f) => f.title === 'Outbound email provider inferred')).toBe(true);
		expect(spf?.findings).toHaveLength(3);
	});

	it('merges SPF and DKIM evidence for the same provider into a single inferred finding', async () => {
		const { applyScanPostProcessing } = await import('../src/tools/scan/post-processing');

		const results: CheckResult[] = [
			buildCheckResult('spf', [
				createFinding('spf', 'SPF configured', 'info', 'SPF ok', {
					includeDomains: ['google.com'],
				}),
			]),
			buildCheckResult('dkim', [
				createFinding('dkim', 'DKIM selectors found', 'info', 'DKIM ok', {
					selectorsFound: ['google'],
				}),
			]),
			buildCheckResult('mx', [createFinding('mx', 'MX records found', 'info', '2 MX configured.')]),
		];

		const updated = await applyScanPostProcessing('example.com', results);
		const spf = updated.find((r) => r.category === 'spf');
		const inferredFindings = spf?.findings.filter((f) => f.title === 'Outbound email provider inferred') ?? [];
		// Both signals resolve to Google Workspace — must produce exactly one merged finding
		expect(inferredFindings).toHaveLength(1);
		expect(inferredFindings[0].detail).toContain('Google Workspace');
	});

	it('does not insert a synthetic SPF result when no SPF check is in the results array', async () => {
		// addOutboundProviderInference builds a synthetic updatedSpf but then calls
		// upsertCheckResult which only maps (replaces) existing entries — it cannot
		// insert a new category. If no 'spf' is in results, the inference is a no-op.
		const { applyScanPostProcessing } = await import('../src/tools/scan/post-processing');

		const results: CheckResult[] = [
			buildCheckResult('dkim', [
				createFinding('dkim', 'DKIM selectors found', 'info', 'DKIM ok', {
					selectorsFound: ['google'],
				}),
			]),
			buildCheckResult('mx', [createFinding('mx', 'MX records found', 'info', '2 MX configured.')]),
		];

		const updated = await applyScanPostProcessing('example.com', results);
		// No 'spf' category exists in results, so upsertCheckResult has nothing to replace
		expect(updated.find((r) => r.category === 'spf')).toBeUndefined();
		// Other checks are preserved unchanged
		expect(updated).toHaveLength(2);
	});
});