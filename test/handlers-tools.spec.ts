import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock, createDohResponse, mockTxtRecords, txtResponse, nsResponse, caaResponse, dnssecResponse, httpResponse } from './helpers/dns-mock';
import { IN_MEMORY_CACHE } from '../src/lib/cache';

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
		expect(result.content).toHaveLength(2);
		expect(result.content[0].text).toContain('SPF');
		expect(result.content[1].text).toContain('STRUCTURED_RESULT');
	});

	it('check_spf surfaces shared-platform trust as informational when DMARC is strict', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (!url.includes('cloudflare-dns.com')) {
				return Promise.resolve(createDohResponse([], []));
			}

			if (url.includes('_dmarc.strict-spf.example.com')) {
				return Promise.resolve(txtResponse('_dmarc.strict-spf.example.com', ['v=DMARC1; p=reject; adkim=s; aspf=s']));
			}

			if (url.includes('_spf.google.com')) {
				return Promise.resolve(txtResponse('_spf.google.com', ['v=spf1 -all']));
			}

			return Promise.resolve(txtResponse('strict-spf.example.com', ['v=spf1 include:_spf.google.com -all']));
		});

		const result = await call('check_spf', { domain: 'strict-spf.example.com' });
		expect(result.isError).toBeUndefined();
		expect(result.content).toHaveLength(2);
		expect(result.content[0].text).toContain('**Status:** ✅ Passed');
		expect(result.content[0].text).toContain('**[INFO]** SPF delegates to shared platform: Google Workspace');
		expect(result.content[0].text).toContain('**[INFO]** SPF record configured');
	});

	it('check_dmarc with valid domain returns content', async () => {
		mockTxtRecords(['v=DMARC1; p=reject'], '_dmarc.example.com');
		const result = await call('check_dmarc', { domain: 'example.com' });
		expect(result.isError).toBeUndefined();
		expect(result.content).toHaveLength(2);
		expect(result.content[0].type).toBe('text');
		expect(result.content[0].text.length).toBeGreaterThan(0);
	});

	it('check_caa with valid domain returns content', async () => {
		const caaAnswers = [{ name: 'example.com', type: 257, TTL: 300, data: '0 issue "letsencrypt.org"' }];
		globalThis.fetch = vi.fn().mockResolvedValue(createDohResponse([{ name: 'example.com', type: 257 }], caaAnswers));
		const result = await call('check_caa', { domain: 'example.com' });
		expect(result.isError).toBeUndefined();
		expect(result.content).toHaveLength(2);
		expect(result.content[0].text).toContain('CAA');
	});

	it('scan_domain with valid domain returns scan report', async () => {
		mockAllChecks();
		const result = await call('scan_domain', { domain: 'example.com' });
		expect(result.isError).toBeUndefined();
		expect(result.content).toHaveLength(2);
		expect(result.content[0].text).toContain('DNS Security Scan');
		// Second content block is structured JSON for machine-readable consumption
		expect(result.content[1].text).toContain('STRUCTURED_RESULT');
		const match = result.content[1].text.match(/<!-- STRUCTURED_RESULT\n(.*)\nSTRUCTURED_RESULT -->/s);
		expect(match).not.toBeNull();
		const structured = JSON.parse(match![1]);
		expect(structured.domain).toBe('example.com');
		expect(typeof structured.score).toBe('number');
		expect(typeof structured.grade).toBe('string');
		expect(typeof structured.passed).toBe('boolean');
		expect(structured.findingCounts).toBeDefined();
	});

	it('scan alias routes to scan_domain', async () => {
		mockAllChecks();
		const result = await call('scan', { domain: 'example.com' });
		expect(result.isError).toBeUndefined();
		expect(result.content).toHaveLength(2);
		expect(result.content[0].text).toContain('DNS Security Scan');
		expect(result.content[1].text).toContain('STRUCTURED_RESULT');
	});

	it('check_mx with valid domain returns content with MX', async () => {
		const mxAnswers = [{ name: 'example.com', type: 15, TTL: 300, data: '10 mail.example.com.' }];
		globalThis.fetch = vi.fn().mockResolvedValue(createDohResponse([{ name: 'example.com', type: 15 }], mxAnswers));
		const result = await call('check_mx', { domain: 'example.com' });
		expect(result.isError).toBeUndefined();
		expect(result.content).toHaveLength(2);
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
		expect(result.content).toHaveLength(2);
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
		expect(result.content).toHaveLength(2);
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
		expect(result.content).toHaveLength(2);
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
		expect(result.content).toHaveLength(2);
		expect(result.content[0].text).toContain('NS');
	});
});

// -- handleToolsCall per-tool cache TTL --

describe('handleToolsCall - per-tool cache TTL', () => {
	it('check_lookalikes caches with 60-minute TTL (3600s)', async () => {
		globalThis.fetch = vi.fn().mockImplementation(() => {
			return Promise.resolve(createDohResponse([], []));
		});
		const mockKV = {
			get: vi.fn().mockResolvedValue(null),
			put: vi.fn().mockResolvedValue(undefined),
		};
		const { handleToolsCall } = await import('../src/handlers/tools');
		await handleToolsCall({ name: 'check_lookalikes', arguments: { domain: 'example.com' } }, mockKV as unknown as KVNamespace);
		const lookalikesPut = mockKV.put.mock.calls.find((c: unknown[]) => (c[0] as string).includes('lookalikes') && !(c[0] as string).endsWith(':computing'));
		expect(lookalikesPut).toBeDefined();
		expect(lookalikesPut![2]).toEqual({ expirationTtl: 3600 });
	});

	it('check_spf caches with default 5-minute TTL (300s)', async () => {
		mockTxtRecords(['v=spf1 -all']);
		const mockKV = {
			get: vi.fn().mockResolvedValue(null),
			put: vi.fn().mockResolvedValue(undefined),
		};
		const { handleToolsCall } = await import('../src/handlers/tools');
		await handleToolsCall({ name: 'check_spf', arguments: { domain: 'example.com' } }, mockKV as unknown as KVNamespace);
		const spfPut = mockKV.put.mock.calls.find((c: unknown[]) => (c[0] as string).includes('spf') && !(c[0] as string).endsWith(':computing'));
		expect(spfPut).toBeDefined();
		expect(spfPut![2]).toEqual({ expirationTtl: 300 });
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
		expect(result.content).toHaveLength(2);
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
		expect(result.content[0].text).not.toContain('Details:');
		expect(result.content[0].text).not.toContain('SPF record uses +all');
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

	it('unexpected errors return generic error with tool name', async () => {
		globalThis.fetch = vi.fn().mockImplementation(() => {
			throw new Error('ECONNREFUSED');
		});
		const result = await call('check_spf', { domain: 'error-test.example.com' });
		expect(result.isError).toBe(true);
		expect(result.content[0].text).toContain('An unexpected error occurred while running check_spf');
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
		IN_MEMORY_CACHE.clear();

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

// -- handleToolsList --

describe('handleToolsList', () => {
	it('returns an object with a tools array of 44 entries', async () => {
		const { handleToolsList } = await import('../src/handlers/tools');
		const result = handleToolsList();
		expect(Array.isArray(result.tools)).toBe(true);
		expect(result.tools).toHaveLength(47);
	});

	it('every tool entry has name, description, and inputSchema', async () => {
		const { handleToolsList } = await import('../src/handlers/tools');
		const { tools } = handleToolsList();
		for (const tool of tools) {
			expect(typeof tool.name, `${tool.name}: name must be string`).toBe('string');
			expect(tool.name.length, `tool name must not be empty`).toBeGreaterThan(0);
			expect(typeof tool.description, `${tool.name}: description must be string`).toBe('string');
			expect(tool.description.length, `${tool.name}: description must not be empty`).toBeGreaterThan(0);
			expect(typeof tool.inputSchema, `${tool.name}: inputSchema must be object`).toBe('object');
			expect(tool.inputSchema).not.toBeNull();
		}
	});

	it('contains the core email-auth tool names', async () => {
		const { handleToolsList } = await import('../src/handlers/tools');
		const names = handleToolsList().tools.map((t) => t.name);
		for (const expected of ['check_spf', 'check_dmarc', 'check_dkim', 'check_mx', 'check_mta_sts']) {
			expect(names).toContain(expected);
		}
	});

	it('contains the orchestration and intelligence tool names', async () => {
		const { handleToolsList } = await import('../src/handlers/tools');
		const names = handleToolsList().tools.map((t) => t.name);
		for (const expected of ['scan_domain', 'batch_scan', 'explain_finding', 'get_benchmark', 'assess_spoofability']) {
			expect(names).toContain(expected);
		}
	});

	it('all tool names are unique', async () => {
		const { handleToolsList } = await import('../src/handlers/tools');
		const names = handleToolsList().tools.map((t) => t.name);
		expect(new Set(names).size).toBe(names.length);
	});
});

// -- format routing --

describe('handleToolsCall - format routing', () => {
	async function call(name: string, args: Record<string, unknown> = {}, runtimeOptions?: Record<string, unknown>) {
		const { handleToolsCall } = await import('../src/handlers/tools');
		return handleToolsCall({ name, arguments: args }, undefined, runtimeOptions as never);
	}

	it('format: "compact" strips emoji icons and uses bracket notation', async () => {
		mockTxtRecords(['v=spf1 +all']);
		const result = await call('check_spf', { domain: 'example.com', format: 'compact' });
		expect(result.isError).toBeUndefined();
		const text = result.content[0].text;
		// Compact mode uses bracket notation, not emoji icons
		expect(text).toContain('[');
		// Compact mode should not contain the full-mode emoji severity icons
		const hasFullModeIcon = text.includes('🔶') || text.includes('🔴') || text.includes('🚨') || text.includes('⚠️') || text.includes('ℹ️');
		expect(hasFullModeIcon).toBe(false);
	});

	it('format: "full" includes emoji severity icons', async () => {
		mockTxtRecords(['v=spf1 +all']);
		const result = await call('check_spf', { domain: 'example.com', format: 'full' });
		expect(result.isError).toBeUndefined();
		const text = result.content[0].text;
		// Full mode includes emoji icons for severity
		const hasSeverityIcon =
			text.includes('ℹ️') || text.includes('⚠️') || text.includes('🔶') || text.includes('🔴') || text.includes('🚨');
		expect(hasSeverityIcon).toBe(true);
	});

	it('interactive client type auto-selects compact format (no STRUCTURED_RESULT)', async () => {
		mockAllChecks();
		const result = await call('scan_domain', { domain: 'example.com' }, { clientType: 'claude_code' });
		expect(result.isError).toBeUndefined();
		// Interactive clients should NOT get the structured JSON block
		expect(result.content).toHaveLength(1);
		expect(result.content[0].text).not.toContain('STRUCTURED_RESULT');
	});

	it('unknown client type auto-selects full format (includes STRUCTURED_RESULT for scan)', async () => {
		mockAllChecks();
		const result = await call('scan_domain', { domain: 'example.com' }, { clientType: 'unknown' });
		expect(result.isError).toBeUndefined();
		// Non-interactive clients should get the structured JSON block
		expect(result.content).toHaveLength(2);
		expect(result.content[1].text).toContain('STRUCTURED_RESULT');
	});

	it('explicit format: "compact" overrides interactive client auto-detect', async () => {
		mockTxtRecords(['v=spf1 +all']);
		// Even if clientType is unknown (non-interactive), explicit compact wins
		const result = await call('check_spf', { domain: 'example.com', format: 'compact' }, { clientType: 'unknown' });
		expect(result.isError).toBeUndefined();
		const text = result.content[0].text;
		const hasFullModeIcon = text.includes('🔶') || text.includes('🔴') || text.includes('🚨') || text.includes('⚠️') || text.includes('ℹ️');
		expect(hasFullModeIcon).toBe(false);
	});
});

// -- in-memory cache hit / miss / force_refresh --

describe('handleToolsCall - caching behaviour', () => {
	async function call(name: string, args: Record<string, unknown> = {}) {
		const { handleToolsCall } = await import('../src/handlers/tools');
		return handleToolsCall({ name, arguments: args });
	}

	it('second call for same domain+tool hits in-memory cache (fetch not called again)', async () => {
		IN_MEMORY_CACHE.clear();
		let fetchCount = 0;
		globalThis.fetch = vi.fn().mockImplementation(() => {
			fetchCount++;
			return Promise.resolve(
				createDohResponse(
					[{ name: 'cache-test.example.com', type: 16 }],
					[{ name: 'cache-test.example.com', type: 16, TTL: 300, data: '"v=spf1 -all"' }],
				),
			);
		});

		await call('check_spf', { domain: 'cache-test.example.com' });
		const firstFetchCount = fetchCount;
		expect(firstFetchCount).toBeGreaterThan(0);

		// Second call — should hit in-memory cache and not fetch again
		await call('check_spf', { domain: 'cache-test.example.com' });
		expect(fetchCount).toBe(firstFetchCount);
	});

	it('force_refresh: true on scan_domain bypasses cache and re-fetches', async () => {
		IN_MEMORY_CACHE.clear();
		let fetchCount = 0;
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			fetchCount++;
			if (url.includes('_dmarc.')) {
				return Promise.resolve(
					createDohResponse(
						[{ name: '_dmarc.force-refresh.example.com', type: 16 }],
						[{ name: '_dmarc.force-refresh.example.com', type: 16, TTL: 300, data: '"v=DMARC1; p=reject"' }],
					),
				);
			}
			if (url.includes('type=NS') || url.includes('type=2')) {
				return Promise.resolve(
					createDohResponse(
						[{ name: 'force-refresh.example.com', type: 2 }],
						[{ name: 'force-refresh.example.com', type: 2, TTL: 300, data: 'ns1.example.com.' }],
					),
				);
			}
			return Promise.resolve(
				createDohResponse(
					[{ name: 'force-refresh.example.com', type: 16 }],
					[{ name: 'force-refresh.example.com', type: 16, TTL: 300, data: '"v=spf1 -all"' }],
				),
			);
		});

		// Warm the scan cache
		const { handleToolsCall } = await import('../src/handlers/tools');
		await handleToolsCall({ name: 'scan_domain', arguments: { domain: 'force-refresh.example.com' } });
		const afterWarm = fetchCount;
		expect(afterWarm).toBeGreaterThan(0);

		// force_refresh is a tool argument for scan_domain — bypasses cache
		await handleToolsCall({ name: 'scan_domain', arguments: { domain: 'force-refresh.example.com', force_refresh: true } });
		expect(fetchCount).toBeGreaterThan(afterWarm);
	});

	it('cacheTtlSeconds override is passed to KV storage as expirationTtl', async () => {
		mockTxtRecords(['v=spf1 -all']);
		const mockKV = {
			get: vi.fn().mockResolvedValue(null),
			put: vi.fn().mockResolvedValue(undefined),
		};
		const { handleToolsCall } = await import('../src/handlers/tools');
		await handleToolsCall(
			{ name: 'check_spf', arguments: { domain: 'example.com' } },
			mockKV as unknown as KVNamespace,
		);
		const spfPut = mockKV.put.mock.calls.find((c: unknown[]) => (c[0] as string).includes('spf') && !(c[0] as string).endsWith(':computing'));
		expect(spfPut).toBeDefined();
		// Default TTL is 300s
		expect(spfPut![2]).toEqual({ expirationTtl: 300 });
	});

	it('KV cache hit short-circuits tool execution (no fetch)', async () => {
		IN_MEMORY_CACHE.clear();
		// KV.get(key, 'json') returns the already-parsed value — mock must return the object
		const cachedResult = {
			category: 'spf',
			passed: true,
			score: 90,
			findings: [] as unknown[],
		};
		const mockKV = {
			get: vi.fn().mockResolvedValue(cachedResult),
			put: vi.fn().mockResolvedValue(undefined),
		};
		let fetchCalled = false;
		globalThis.fetch = vi.fn().mockImplementation(() => {
			fetchCalled = true;
			return Promise.resolve(createDohResponse([], []));
		});
		const { handleToolsCall } = await import('../src/handlers/tools');
		const result = await handleToolsCall(
			{ name: 'check_spf', arguments: { domain: 'kv-cached.example.com' } },
			mockKV as unknown as KVNamespace,
		);
		expect(result.isError).toBeUndefined();
		expect(fetchCalled).toBe(false);
		expect(mockKV.get).toHaveBeenCalled();
	});
});

// -- resultCapture callback --

describe('handleToolsCall - resultCapture', () => {
	it('invokes resultCapture with the raw CheckResult for registry tools', async () => {
		mockTxtRecords(['v=spf1 -all']);
		let captured: unknown = null;
		const { handleToolsCall } = await import('../src/handlers/tools');
		const result = await handleToolsCall(
			{ name: 'check_spf', arguments: { domain: 'example.com' } },
			undefined,
			{ resultCapture: (r) => { captured = r; } },
		);
		expect(result.isError).toBeUndefined();
		expect(captured).not.toBeNull();
		expect((captured as Record<string, unknown>).category).toBe('spf');
		expect(typeof (captured as Record<string, unknown>).score).toBe('number');
	});
});

// -- tool routing for additional registry tools --

describe('handleToolsCall - additional registry tool routing', () => {
	async function call(name: string, args: Record<string, unknown> = {}) {
		const { handleToolsCall } = await import('../src/handlers/tools');
		return handleToolsCall({ name, arguments: args });
	}

	it('check_bimi with valid domain returns content with BIMI', async () => {
		globalThis.fetch = vi.fn().mockResolvedValue(createDohResponse([], []));
		const result = await call('check_bimi', { domain: 'example.com' });
		expect(result.isError).toBeUndefined();
		expect(result.content).toHaveLength(2);
		expect(result.content[0].text).toContain('BIMI');
	});

	it('check_tlsrpt with valid domain returns content', async () => {
		globalThis.fetch = vi.fn().mockResolvedValue(createDohResponse([], []));
		const result = await call('check_tlsrpt', { domain: 'example.com' });
		expect(result.isError).toBeUndefined();
		expect(result.content).toHaveLength(2);
		expect(result.content[0].text).toContain('TLS');
	});

	it('check_dane with valid domain returns content', async () => {
		globalThis.fetch = vi.fn().mockResolvedValue(createDohResponse([], []));
		const result = await call('check_dane', { domain: 'example.com' });
		expect(result.isError).toBeUndefined();
		expect(result.content).toHaveLength(2);
		expect(result.content[0].text).toContain('DANE');
	});

	it('check_dane_https with valid domain returns content', async () => {
		globalThis.fetch = vi.fn().mockResolvedValue(createDohResponse([], []));
		const result = await call('check_dane_https', { domain: 'example.com' });
		expect(result.isError).toBeUndefined();
		expect(result.content).toHaveLength(2);
		expect(result.content[0].text).toContain('DANE');
	});

	it('check_svcb_https with valid domain returns content', async () => {
		globalThis.fetch = vi.fn().mockResolvedValue(createDohResponse([], []));
		const result = await call('check_svcb_https', { domain: 'example.com' });
		expect(result.isError).toBeUndefined();
		expect(result.content).toHaveLength(2);
		expect(result.content[0].text).toContain('HTTPS');
	});

	it('check_txt_hygiene with valid domain returns content', async () => {
		globalThis.fetch = vi.fn().mockResolvedValue(
			createDohResponse(
				[{ name: 'example.com', type: 16 }],
				[{ name: 'example.com', type: 16, TTL: 300, data: '"v=spf1 -all"' }],
			),
		);
		const result = await call('check_txt_hygiene', { domain: 'example.com' });
		expect(result.isError).toBeUndefined();
		expect(result.content).toHaveLength(2);
		expect(result.content[0].text).toContain('TXT');
	});

	it('check_http_security with valid domain returns content', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.startsWith('https://')) {
				return Promise.resolve({
					url,
					ok: true,
					status: 200,
					headers: new Headers({
						'strict-transport-security': 'max-age=31536000; includeSubDomains',
						'content-security-policy': "default-src 'self'",
					}),
					text: () => Promise.resolve('OK'),
					json: () => Promise.resolve({}),
				} as unknown as Response);
			}
			return Promise.resolve({
				ok: false,
				status: 301,
				headers: new Headers({ location: `https://${new URL(url).hostname}/` }),
				text: () => Promise.resolve(''),
				json: () => Promise.resolve({}),
			} as unknown as Response);
		});
		const result = await call('check_http_security', { domain: 'example.com' });
		expect(result.isError).toBeUndefined();
		expect(result.content).toHaveLength(2);
		expect(result.content[0].text).toContain('HTTP');
	});

	it('check_srv with valid domain returns content', async () => {
		globalThis.fetch = vi.fn().mockResolvedValue(createDohResponse([], []));
		const result = await call('check_srv', { domain: 'example.com' });
		expect(result.isError).toBeUndefined();
		expect(result.content).toHaveLength(2);
		expect(result.content[0].text).toContain('SRV');
	});

	it('check_zone_hygiene with valid domain returns content', async () => {
		globalThis.fetch = vi.fn().mockResolvedValue(createDohResponse([], []));
		const result = await call('check_zone_hygiene', { domain: 'example.com' });
		expect(result.isError).toBeUndefined();
		expect(result.content).toHaveLength(2);
		expect(result.content[0].text.length).toBeGreaterThan(0);
	});

	it('check_subdomailing with valid domain returns content', async () => {
		mockTxtRecords(['v=spf1 -all']);
		const result = await call('check_subdomailing', { domain: 'example.com' });
		expect(result.isError).toBeUndefined();
		expect(result.content).toHaveLength(2);
		expect(result.content[0].text.length).toBeGreaterThan(0);
	});
});

// -- non-registry dispatch tool routing --

describe('handleToolsCall - non-registry tool routing', () => {
	async function call(name: string, args: Record<string, unknown> = {}) {
		const { handleToolsCall } = await import('../src/handlers/tools');
		return handleToolsCall({ name, arguments: args });
	}

	it('get_benchmark returns benchmark content without requiring a domain', async () => {
		const result = await call('get_benchmark', {});
		expect(result.isError).toBeUndefined();
		expect(result.content).toHaveLength(2);
		expect(result.content[0].text.length).toBeGreaterThan(0);
	});

	it('get_provider_insights with missing provider returns isError', async () => {
		const result = await call('get_provider_insights', {});
		expect(result.isError).toBe(true);
		expect(result.content[0].text).toContain('Missing required parameter: provider');
	});

	it('get_provider_insights with provider returns content', async () => {
		const result = await call('get_provider_insights', { provider: 'google' });
		expect(result.isError).toBeUndefined();
		expect(result.content).toHaveLength(2);
		expect(result.content[0].text.length).toBeGreaterThan(0);
	});

	it('assess_spoofability with valid domain returns content with risk level', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.includes('_dmarc.')) {
				return Promise.resolve(
					createDohResponse(
						[{ name: '_dmarc.example.com', type: 16 }],
						[{ name: '_dmarc.example.com', type: 16, TTL: 300, data: '"v=DMARC1; p=reject"' }],
					),
				);
			}
			return Promise.resolve(
				createDohResponse(
					[{ name: 'example.com', type: 16 }],
					[{ name: 'example.com', type: 16, TTL: 300, data: '"v=spf1 -all"' }],
				),
			);
		});
		const result = await call('assess_spoofability', { domain: 'example.com' });
		expect(result.isError).toBeUndefined();
		expect(result.content).toHaveLength(2);
		expect(result.content[0].text.length).toBeGreaterThan(0);
	});

	it('generate_spf_record with valid domain returns an SPF record', async () => {
		globalThis.fetch = vi.fn().mockResolvedValue(
			createDohResponse(
				[{ name: 'example.com', type: 16 }],
				[{ name: 'example.com', type: 16, TTL: 300, data: '"v=spf1 include:_spf.google.com -all"' }],
			),
		);
		const result = await call('generate_spf_record', { domain: 'example.com' });
		expect(result.isError).toBeUndefined();
		expect(result.content).toHaveLength(2);
		expect(result.content[0].text).toContain('spf1');
	});

	it('generate_dmarc_record with valid domain returns a DMARC record', async () => {
		globalThis.fetch = vi.fn().mockResolvedValue(createDohResponse([], []));
		const result = await call('generate_dmarc_record', { domain: 'example.com' });
		expect(result.isError).toBeUndefined();
		expect(result.content).toHaveLength(2);
		expect(result.content[0].text).toContain('DMARC');
	});

	it('generate_dkim_config with valid domain returns DKIM setup content', async () => {
		globalThis.fetch = vi.fn().mockResolvedValue(createDohResponse([], []));
		const result = await call('generate_dkim_config', { domain: 'example.com' });
		expect(result.isError).toBeUndefined();
		expect(result.content).toHaveLength(2);
		expect(result.content[0].text).toContain('DKIM');
	});

	it('generate_mta_sts_policy with valid domain returns policy content', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.includes('type=MX') || url.includes('type=15')) {
				return Promise.resolve(
					createDohResponse(
						[{ name: 'example.com', type: 15 }],
						[{ name: 'example.com', type: 15, TTL: 300, data: '10 mail.example.com.' }],
					),
				);
			}
			return Promise.resolve(createDohResponse([], []));
		});
		const result = await call('generate_mta_sts_policy', { domain: 'example.com' });
		expect(result.isError).toBeUndefined();
		expect(result.content).toHaveLength(2);
		expect(result.content[0].text).toContain('MTA');
	});

	it('generate_fix_plan with valid domain returns prioritized remediation content', async () => {
		mockAllChecks();
		const result = await call('generate_fix_plan', { domain: 'example.com' });
		expect(result.isError).toBeUndefined();
		expect(result.content).toHaveLength(2);
		expect(result.content[0].text.length).toBeGreaterThan(0);
	});

	it('resolve_spf_chain with valid domain returns chain content', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.includes('_spf.google.com')) {
				return Promise.resolve(
					createDohResponse(
						[{ name: '_spf.google.com', type: 16 }],
						[{ name: '_spf.google.com', type: 16, TTL: 300, data: '"v=spf1 -all"' }],
					),
				);
			}
			return Promise.resolve(
				createDohResponse(
					[{ name: 'example.com', type: 16 }],
					[{ name: 'example.com', type: 16, TTL: 300, data: '"v=spf1 include:_spf.google.com -all"' }],
				),
			);
		});
		const result = await call('resolve_spf_chain', { domain: 'example.com' });
		expect(result.isError).toBeUndefined();
		expect(result.content).toHaveLength(2);
		expect(result.content[0].text).toContain('SPF');
	});

	it('simulate_attack_paths with valid domain returns attack path content', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.includes('_dmarc.')) {
				return Promise.resolve(
					createDohResponse(
						[{ name: '_dmarc.example.com', type: 16 }],
						[{ name: '_dmarc.example.com', type: 16, TTL: 300, data: '"v=DMARC1; p=reject"' }],
					),
				);
			}
			return Promise.resolve(
				createDohResponse(
					[{ name: 'example.com', type: 16 }],
					[{ name: 'example.com', type: 16, TTL: 300, data: '"v=spf1 -all"' }],
				),
			);
		});
		const result = await call('simulate_attack_paths', { domain: 'example.com' });
		expect(result.isError).toBeUndefined();
		expect(result.content).toHaveLength(2);
		expect(result.content[0].text.length).toBeGreaterThan(0);
	});

	it('map_supply_chain with valid domain returns supply chain content', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.includes('type=NS') || url.includes('type=2')) {
				return Promise.resolve(
					createDohResponse(
						[{ name: 'example.com', type: 2 }],
						[
							{ name: 'example.com', type: 2, TTL: 300, data: 'ns1.example.com.' },
							{ name: 'example.com', type: 2, TTL: 300, data: 'ns2.example.com.' },
						],
					),
				);
			}
			return Promise.resolve(
				createDohResponse(
					[{ name: 'example.com', type: 16 }],
					[{ name: 'example.com', type: 16, TTL: 300, data: '"v=spf1 -all"' }],
				),
			);
		});
		const result = await call('map_supply_chain', { domain: 'example.com' });
		expect(result.isError).toBeUndefined();
		expect(result.content).toHaveLength(2);
		expect(result.content[0].text.length).toBeGreaterThan(0);
	});
});

// -- DKIM cache key includes selector --

describe('handleToolsCall - check_dkim cache key per selector', () => {
	it('different selectors produce different cache keys (no collision)', async () => {
		IN_MEMORY_CACHE.clear();
		const mockKV = {
			get: vi.fn().mockResolvedValue(null),
			put: vi.fn().mockResolvedValue(undefined),
		};
		globalThis.fetch = vi.fn().mockImplementation(() => {
			return Promise.resolve(
				createDohResponse(
					[{ name: 'example.com', type: 16 }],
					[{ name: 'default._domainkey.example.com', type: 16, TTL: 300, data: '"v=DKIM1; k=rsa; p=MIGf"' }],
				),
			);
		});
		const { handleToolsCall } = await import('../src/handlers/tools');
		await handleToolsCall(
			{ name: 'check_dkim', arguments: { domain: 'example.com', selector: 'google' } },
			mockKV as unknown as KVNamespace,
		);
		await handleToolsCall(
			{ name: 'check_dkim', arguments: { domain: 'example.com', selector: 'selector2' } },
			mockKV as unknown as KVNamespace,
		);

		const putKeys = mockKV.put.mock.calls
			.map((c: unknown[]) => c[0] as string)
			.filter((k: string) => k.includes('dkim') && !k.endsWith(':computing'));

		const uniqueKeys = new Set(putKeys);
		// google and selector2 must produce distinct cache keys
		expect(uniqueKeys.size).toBe(2);
		const keyArray = [...uniqueKeys];
		expect(keyArray.some((k: string) => k.includes('google'))).toBe(true);
		expect(keyArray.some((k: string) => k.includes('selector2'))).toBe(true);
	});
});
