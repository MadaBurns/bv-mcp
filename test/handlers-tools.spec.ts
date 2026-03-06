import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock, createDohResponse, mockTxtRecords, txtResponse, nsResponse, caaResponse, dnssecResponse, httpResponse } from './helpers/dns-mock';
import { inMemoryCache } from '../src/lib/cache';

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
			return Promise.resolve({ ...httpResponse('OK'), url });
		}

		return Promise.resolve(httpResponse('OK'));
	});
}

// -- handleToolsCall dispatch routing --

describe('handleToolsCall - dispatch routing', () => {
	async function call(name: string, args: Record<string, unknown> = {}) {
		const { handleToolsCall } = await import('../src/handlers/tools');
		return handleToolsCall({ name, arguments: args });
	}

	it('check_spf with valid domain returns content with SPF', async () => {
		mockTxtRecords(['v=spf1 -all']);
		const result = await call('check_spf', { domain: 'example.com' });
		expect(result.isError).toBeUndefined();
		expect(result.content).toHaveLength(1);
		expect(result.content[0].text).toContain('SPF');
	});

	it('check_dmarc with valid domain returns content', async () => {
		mockTxtRecords(['v=DMARC1; p=reject'], '_dmarc.example.com');
		const result = await call('check_dmarc', { domain: 'example.com' });
		expect(result.isError).toBeUndefined();
		expect(result.content).toHaveLength(1);
		expect(result.content[0].type).toBe('text');
		expect(result.content[0].text.length).toBeGreaterThan(0);
	});

	it('check_caa with valid domain returns content', async () => {
		const caaAnswers = [{ name: 'example.com', type: 257, TTL: 300, data: '0 issue "letsencrypt.org"' }];
		globalThis.fetch = vi.fn().mockResolvedValue(createDohResponse([{ name: 'example.com', type: 257 }], caaAnswers));
		const result = await call('check_caa', { domain: 'example.com' });
		expect(result.isError).toBeUndefined();
		expect(result.content).toHaveLength(1);
		expect(result.content[0].text).toContain('CAA');
	});

	it('scan_domain with valid domain returns scan report', async () => {
		mockAllChecks();
		const result = await call('scan_domain', { domain: 'example.com' });
		expect(result.isError).toBeUndefined();
		expect(result.content).toHaveLength(1);
		expect(result.content[0].text).toContain('DNS Security Scan');
	});

	it('scan alias routes to scan_domain', async () => {
		mockAllChecks();
		const result = await call('scan', { domain: 'example.com' });
		expect(result.isError).toBeUndefined();
		expect(result.content).toHaveLength(1);
		expect(result.content[0].text).toContain('DNS Security Scan');
	});

	it('check_mx with valid domain returns content with MX', async () => {
		const mxAnswers = [{ name: 'example.com', type: 15, TTL: 300, data: '10 mail.example.com.' }];
		globalThis.fetch = vi.fn().mockResolvedValue(createDohResponse([{ name: 'example.com', type: 15 }], mxAnswers));
		const result = await call('check_mx', { domain: 'example.com' });
		expect(result.isError).toBeUndefined();
		expect(result.content).toHaveLength(1);
		expect(result.content[0].text).toContain('MX');
	});

	it('check_dnssec with valid domain returns content', async () => {
		globalThis.fetch = vi.fn().mockResolvedValue(
			createDohResponse(
				[{ name: 'example.com', type: 1 }],
				[{ name: 'example.com', type: 1, TTL: 300, data: '1.2.3.4' }],
				{ ad: true },
			),
		);
		const result = await call('check_dnssec', { domain: 'example.com' });
		expect(result.isError).toBeUndefined();
		expect(result.content).toHaveLength(1);
		expect(result.content[0].text).toContain('DNSSEC');
	});

	it('check_ssl with valid domain returns content', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.startsWith('https://')) {
				return Promise.resolve({
					url,
					ok: true,
					status: 200,
					headers: new Headers({ 'strict-transport-security': 'max-age=31536000; includeSubDomains' }),
					text: () => Promise.resolve('OK'),
					json: () => Promise.resolve({}),
				} as unknown as Response);
			}
			// HTTP redirect check
			return Promise.resolve({
				ok: false,
				status: 301,
				headers: new Headers({ location: `https://${new URL(url).hostname}/` }),
				text: () => Promise.resolve(''),
				json: () => Promise.resolve({}),
			} as unknown as Response);
		});
		const result = await call('check_ssl', { domain: 'example.com' });
		expect(result.isError).toBeUndefined();
		expect(result.content).toHaveLength(1);
		expect(result.content[0].text).toContain('SSL');
	});

	it('check_mta_sts with valid domain returns content', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.includes('cloudflare-dns.com')) {
				if (url.includes('_mta-sts.')) {
					return Promise.resolve(txtResponse('_mta-sts.example.com', ['v=STSv1; id=20240101']));
				}
				if (url.includes('_smtp._tls.')) {
					return Promise.resolve(txtResponse('_smtp._tls.example.com', ['v=TLSRPTv1; rua=mailto:tls@example.com']));
				}
				return Promise.resolve(createDohResponse([], []));
			}
			if (url.includes('mta-sts.') && url.includes('.well-known')) {
				return Promise.resolve({
					ok: true,
					status: 200,
					text: () => Promise.resolve('version: STSv1\nmode: enforce\nmx: *.example.com\nmax_age: 86400'),
					json: () => Promise.resolve({}),
				} as unknown as Response);
			}
			return Promise.resolve({ ok: true, status: 200, text: () => Promise.resolve('OK'), json: () => Promise.resolve({}) } as unknown as Response);
		});
		const result = await call('check_mta_sts', { domain: 'example.com' });
		expect(result.isError).toBeUndefined();
		expect(result.content).toHaveLength(1);
		expect(result.content[0].text).toContain('MTA_STS');
	});

	it('check_ns with valid domain returns content', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.includes('type=NS') || url.includes('type=2')) {
				return Promise.resolve(nsResponse('example.com', ['ns1.example.com.', 'ns2.example.com.']));
			}
			if (url.includes('type=SOA') || url.includes('type=6')) {
				return Promise.resolve(createDohResponse([{ name: 'example.com', type: 6 }], [{ name: 'example.com', type: 6, TTL: 300, data: 'ns1.example.com. admin.example.com. 2024010101 3600 600 604800 300' }]));
			}
			return Promise.resolve(createDohResponse([], []));
		});
		const result = await call('check_ns', { domain: 'example.com' });
		expect(result.isError).toBeUndefined();
		expect(result.content).toHaveLength(1);
		expect(result.content[0].text).toContain('NS');
	});
});

// -- handleToolsCall check_dkim selector validation --

describe('handleToolsCall - check_dkim selector validation', () => {
	async function call(name: string, args: Record<string, unknown> = {}) {
		const { handleToolsCall } = await import('../src/handlers/tools');
		return handleToolsCall({ name, arguments: args });
	}

	it('check_dkim with valid selector does not error', async () => {
		mockAllChecks();
		const result = await call('check_dkim', { domain: 'example.com', selector: 'google' });
		expect(result.isError).toBeUndefined();
	});

	it('check_dkim with invalid selector (special chars) returns isError', async () => {
		mockAllChecks();
		const result = await call('check_dkim', { domain: 'example.com', selector: 'sel@ctor!' });
		expect(result.isError).toBe(true);
		expect(result.content[0].text).toContain('Invalid DKIM selector');
	});

	it('check_dkim with selector > 63 chars returns isError', async () => {
		mockAllChecks();
		const longSelector = 'a'.repeat(64);
		const result = await call('check_dkim', { domain: 'example.com', selector: longSelector });
		expect(result.isError).toBe(true);
		expect(result.content[0].text).toContain('Invalid DKIM selector');
	});
});

// -- handleToolsCall explain_finding --

describe('handleToolsCall - explain_finding', () => {
	async function call(name: string, args: Record<string, unknown> = {}) {
		const { handleToolsCall } = await import('../src/handlers/tools');
		return handleToolsCall({ name, arguments: args });
	}

	it('valid checkType + status returns content (not isError)', async () => {
		const result = await call('explain_finding', { checkType: 'SPF', status: 'pass' });
		expect(result.isError).toBeUndefined();
		expect(result.content).toHaveLength(1);
		expect(result.content[0].text.length).toBeGreaterThan(0);
	});

	it('missing checkType returns isError with "Missing required parameters"', async () => {
		const result = await call('explain_finding', { status: 'pass' });
		expect(result.isError).toBe(true);
		expect(result.content[0].text).toContain('Missing required parameters');
	});

	it('missing status returns isError with "Missing required parameters"', async () => {
		const result = await call('explain_finding', { checkType: 'SPF' });
		expect(result.isError).toBe(true);
		expect(result.content[0].text).toContain('Missing required parameters');
	});

	it('explain_finding with details includes details in output', async () => {
		const result = await call('explain_finding', { checkType: 'SPF', status: 'fail', details: 'SPF record uses +all' });
		expect(result.isError).toBeUndefined();
		expect(result.content[0].text).toContain('Details:');
		expect(result.content[0].text).toContain('SPF record uses +all');
	});

	it('explain_finding includes impact and adverse consequence sections for failure states', async () => {
		const result = await call('explain_finding', { checkType: 'DMARC', status: 'fail' });
		expect(result.isError).toBeUndefined();
		expect(result.content[0].text).toContain('### Potential Impact');
		expect(result.content[0].text).toContain('### Adverse Consequences');
	});
});

// -- handleToolsCall input validation & errors --

describe('handleToolsCall - input validation & errors', () => {
	async function call(name: string, args: Record<string, unknown> = {}) {
		const { handleToolsCall } = await import('../src/handlers/tools');
		return handleToolsCall({ name, arguments: args });
	}

	it('missing domain argument returns isError with "Missing required parameter: domain"', async () => {
		const result = await call('check_spf', {});
		expect(result.isError).toBe(true);
		expect(result.content[0].text).toContain('Missing required parameter: domain');
	});

	it('invalid domain (localhost) returns isError with validation message', async () => {
		const result = await call('check_spf', { domain: 'localhost' });
		expect(result.isError).toBe(true);
		expect(result.content[0].text.length).toBeGreaterThan(0);
	});

	it('empty domain string returns isError', async () => {
		const result = await call('check_spf', { domain: '' });
		expect(result.isError).toBe(true);
	});

	it('unknown tool name returns isError with "Unknown tool"', async () => {
		const result = await call('nonexistent_tool', { domain: 'example.com' });
		expect(result.isError).toBe(true);
		expect(result.content[0].text).toContain('Unknown tool');
	});
});

// -- handleToolsCall error categorization --

describe('handleToolsCall - error categorization', () => {
	async function call(name: string, args: Record<string, unknown> = {}) {
		const { handleToolsCall } = await import('../src/handlers/tools');
		return handleToolsCall({ name, arguments: args });
	}

	it('validation errors pass through the error message', async () => {
		const result = await call('check_spf', {});
		expect(result.isError).toBe(true);
		expect(result.content[0].text).toContain('Missing required parameter: domain');
	});

	it('unexpected errors return generic "An unexpected error occurred"', async () => {
		globalThis.fetch = vi.fn().mockImplementation(() => {
			throw new Error('ECONNREFUSED');
		});
		const result = await call('check_spf', { domain: 'error-test.example.com' });
		expect(result.isError).toBe(true);
		expect(result.content[0].text).toContain('An unexpected error occurred');
	});
});

// -- formatCheckResult (tested indirectly through handleToolsCall) --

describe('formatCheckResult - via handleToolsCall', () => {
	async function call(name: string, args: Record<string, unknown> = {}) {
		const { handleToolsCall } = await import('../src/handlers/tools');
		return handleToolsCall({ name, arguments: args });
	}

	it('passing check result contains "Passed" and score', async () => {
		mockTxtRecords(['v=spf1 include:_spf.google.com -all']);
		const result = await call('check_spf', { domain: 'example.com' });
		expect(result.content[0].text).toContain('\u2705 Passed');
		expect(result.content[0].text).toContain('/100');
	});

	it('failing check result contains findings with severity indicators', async () => {
		mockTxtRecords(['v=spf1 +all', 'v=spf1 ~all']);
		const result = await call('check_spf', { domain: 'failing-spf.example.com' });
		expect(result.content[0].text).toContain('\u274C Failed');
		expect(result.content[0].text).toContain('Findings');
		expect(result.content[0].text).toContain('Confidence: deterministic');
		expect(result.content[0].text).toContain('Potential Impact:');
		expect(result.content[0].text).toContain('Adverse Consequences:');
		const text = result.content[0].text;
		const hasSeverityIcon =
			text.includes('\u2139\uFE0F') ||
			text.includes('\u26A0\uFE0F') ||
			text.includes('\uD83D\uDD36') ||
			text.includes('\uD83D\uDD34') ||
			text.includes('\uD83D\uDEA8');
		expect(hasSeverityIcon).toBe(true);
	});

	it('subdomain takeover output includes takeover verification status when present', async () => {
		inMemoryCache.clear();

		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('type=CNAME') || url.includes('type=5')) {
				if (url.includes('staging.example.com')) {
					return Promise.resolve(createDohResponse([{ name: 'staging.example.com', type: 5 }], [{ name: 'staging.example.com', type: 5, TTL: 300, data: 'old-app.herokuapp.com.' }]));
				}
				return Promise.resolve(createDohResponse([{ name: 'example.com', type: 5 }], []));
			}

			if (url.includes('type=A') || url.includes('type=1')) {
				if (url.includes('old-app.herokuapp.com')) {
					return Promise.resolve(createDohResponse([{ name: 'old-app.herokuapp.com', type: 1 }], []));
				}
			}

			return Promise.resolve(createDohResponse([], []));
		});

		const result = await call('scan_domain', { domain: 'example.com' });
		expect(result.content[0].text).toContain('Takeover Verification: potential');
		expect(result.content[0].text).toContain('Confidence: heuristic');
	});
});
