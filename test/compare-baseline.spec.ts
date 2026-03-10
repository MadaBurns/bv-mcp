import { describe, it, expect, afterEach, vi } from 'vitest';
import type { ScanDomainResult } from '../src/tools/scan-domain';
import { setupFetchMock, createDohResponse, txtResponse, nsResponse, caaResponse, dnssecResponse, httpResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();
afterEach(() => restore());

function mockAllChecks() {
	globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

		if (url.includes('cloudflare-dns.com')) {
			if (url.includes('type=TXT') || url.includes('type=16')) {
				if (url.includes('_dmarc.')) {
					return Promise.resolve(txtResponse('_dmarc.example.com', ['v=DMARC1; p=reject']));
				}
				if (url.includes('_domainkey.')) {
					return Promise.resolve(txtResponse('default._domainkey.example.com', ['v=DKIM1; k=rsa; p=MIGf']));
				}
				if (url.includes('_mta-sts.')) {
					return Promise.resolve(txtResponse('_mta-sts.example.com', ['v=STSv1; id=20240101']));
				}
				if (url.includes('_smtp._tls.')) {
					return Promise.resolve(txtResponse('_smtp._tls.example.com', ['v=TLSRPTv1; rua=mailto:tls@example.com']));
				}
				if (url.includes('default._bimi.')) {
					return Promise.resolve(txtResponse('default._bimi.example.com', ['v=BIMI1; l=https://example.com/logo.svg']));
				}
				return Promise.resolve(txtResponse('example.com', ['v=spf1 include:_spf.google.com -all']));
			}

			if (url.includes('type=NS') || url.includes('type=2')) {
				return Promise.resolve(nsResponse('example.com', ['ns1.example.com.', 'ns2.example.com.']));
			}

			if (url.includes('type=CAA') || url.includes('type=257')) {
				return Promise.resolve(caaResponse('example.com', ['0 issue "letsencrypt.org"']));
			}

			if (url.includes('type=A') || url.includes('type=1')) {
				return Promise.resolve(dnssecResponse('example.com', true));
			}

			return Promise.resolve(createDohResponse([], []));
		}

		if (url.includes('mta-sts.') && url.includes('.well-known')) {
			return Promise.resolve(httpResponse('version: STSv1\nmode: enforce\nmx: *.example.com\nmax_age: 86400'));
		}

		if (url.startsWith('https://')) {
			return Promise.resolve(httpResponse('OK'));
		}

		return Promise.resolve(httpResponse('OK'));
	});
}

function createMockScan(overrides?: Partial<ScanDomainResult>): ScanDomainResult {
	return {
		domain: 'example.com',
		score: {
			overall: 90,
			grade: 'A',
			categoryScores: {
				spf: 100,
				dmarc: 100,
				dkim: 100,
				dnssec: 100,
				ssl: 100,
				mta_sts: 100,
				ns: 100,
				caa: 100,
				subdomain_takeover: 100,
				mx: 100,
				bimi: 100,
				tlsrpt: 100,
				lookalikes: 100,
			},
			findings: [],
			summary: '',
		},
		checks: [
			{ category: 'spf', passed: true, score: 90, findings: [] },
			{ category: 'dmarc', passed: true, score: 95, findings: [{ category: 'dmarc', title: 'DMARC p=reject', severity: 'info', detail: '' }] },
			{ category: 'dkim', passed: true, score: 85, findings: [] },
			{ category: 'dnssec', passed: true, score: 70, findings: [] },
		],
		maturity: {
			stage: 3,
			label: 'Established',
			description: 'Strong controls with room for advanced hardening.',
			nextStep: 'Improve optional controls and monitoring depth.',
		},
		cached: false,
		timestamp: new Date().toISOString(),
		...overrides,
	};
}

describe('compare_baseline schema', () => {
	it('is registered in TOOLS', async () => {
		const { TOOLS } = await import('../src/handlers/tool-schemas');
		const tool = TOOLS.find((value) => value.name === 'compare_baseline');
		expect(tool).toBeDefined();
		expect(tool?.inputSchema.required).toContain('domain');
		expect(tool?.inputSchema.required).toContain('baseline');
	});
});

describe('compareBaseline', () => {
	it('returns no violations when domain meets baseline requirements', async () => {
		const { compareBaseline } = await import('../src/tools/compare-baseline');
		const result = compareBaseline(createMockScan(), { grade: 'B', require_spf: true });
		expect(result.passed).toBe(true);
		expect(result.violations).toHaveLength(0);
	});

	it('flags grade violation', async () => {
		const { compareBaseline } = await import('../src/tools/compare-baseline');
		const result = compareBaseline(
			createMockScan({
				domain: 'weak.com',
				score: { ...createMockScan().score, overall: 60, grade: 'D+', categoryScores: createMockScan().score.categoryScores },
			}),
			{ grade: 'B' },
		);
		expect(result.passed).toBe(false);
		expect(result.violations).toContainEqual(expect.objectContaining({ rule: 'grade', expected: 'B', actual: 'D+' }));
	});

	it('flags missing DMARC enforcement', async () => {
		const { compareBaseline } = await import('../src/tools/compare-baseline');
		const result = compareBaseline(
			createMockScan({
				domain: 'lax.com',
				score: { ...createMockScan().score, overall: 70, grade: 'C+' },
				checks: [
					{
						category: 'dmarc',
						passed: false,
						score: 40,
						findings: [{ category: 'dmarc', title: 'DMARC policy is none', severity: 'high', detail: 'p=none' }],
					},
				],
			}),
			{ require_dmarc_enforce: true },
		);
		expect(result.passed).toBe(false);
		expect(result.violations).toContainEqual(expect.objectContaining({ rule: 'require_dmarc_enforce' }));
	});

	it('flags critical finding count exceeding max', async () => {
		const { compareBaseline } = await import('../src/tools/compare-baseline');
		const result = compareBaseline(
			createMockScan({
				domain: 'bad.com',
				score: {
					...createMockScan().score,
					overall: 50,
					grade: 'E',
					findings: [
						{ category: 'ssl', title: 'Cert expired', severity: 'critical', detail: '' },
						{ category: 'dnssec', title: 'No DNSSEC', severity: 'critical', detail: '' },
					],
				},
			}),
			{ max_critical_findings: 0 },
		);
		expect(result.passed).toBe(false);
		expect(result.violations).toContainEqual(expect.objectContaining({ rule: 'max_critical_findings', expected: 0, actual: 2 }));
	});
});

describe('compare_baseline dispatch', () => {
	it('is listed by handleToolsList', async () => {
		const { handleToolsList } = await import('../src/handlers/tools');
		const list = handleToolsList();
		const tool = list.tools.find((value) => value.name === 'compare_baseline');
		expect(tool).toBeDefined();
	});

	it('is handled by handleToolsCall', async () => {
		mockAllChecks();
		const { handleToolsCall } = await import('../src/handlers/tools');
		const result = await handleToolsCall({
			name: 'compare_baseline',
			arguments: { domain: 'example.com', baseline: { grade: 'B', require_dmarc_enforce: true, max_critical_findings: 0 } },
		});

		expect(result.isError).toBeUndefined();
		expect(result.content).toHaveLength(1);
		expect(result.content[0].text).toContain('Baseline Comparison: example.com');
		expect(result.content[0].text).toContain('Result:');
	});
});
