// SPDX-License-Identifier: BUSL-1.1

/**
 * scan_domain `format: "compact"` trims the STRUCTURED payload too (hosts that hand the model
 * `structuredContent` instead of the text otherwise got the full-size result). Full output, and
 * every non-detail field, must be unchanged.
 */

import { describe, it, expect, afterEach, beforeEach, vi } from 'vitest';
import { setupFetchMock, createDohResponse, txtResponse, nsResponse, caaResponse, dnssecResponse, httpResponse } from './helpers/dns-mock';
import { IN_MEMORY_CACHE } from '../src/lib/cache';

const { restore } = setupFetchMock();

beforeEach(() => IN_MEMORY_CACHE.clear());
afterEach(() => restore());

function mockAllChecks() {
	globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
		if (url.includes('cloudflare-dns.com')) {
			if (url.includes('type=TXT') || url.includes('type=16')) {
				if (url.includes('_dmarc.')) return Promise.resolve(txtResponse('_dmarc.example.com', ['v=DMARC1; p=reject']));
				if (url.includes('_domainkey.')) return Promise.resolve(txtResponse('default._domainkey.example.com', ['v=DKIM1; k=rsa; p=MIGf']));
				if (url.includes('_mta-sts.')) return Promise.resolve(txtResponse('_mta-sts.example.com', ['v=STSv1; id=20240101']));
				if (url.includes('_smtp._tls.'))
					return Promise.resolve(txtResponse('_smtp._tls.example.com', ['v=TLSRPTv1; rua=mailto:tls@example.com']));
				return Promise.resolve(txtResponse('example.com', ['v=spf1 include:_spf.google.com -all']));
			}
			if (url.includes('type=NS') || url.includes('type=2'))
				return Promise.resolve(nsResponse('example.com', ['ns1.example.com.', 'ns2.example.com.']));
			if (url.includes('type=CAA') || url.includes('type=257'))
				return Promise.resolve(caaResponse('example.com', ['0 issue "letsencrypt.org"']));
			if (url.includes('type=A') || url.includes('type=1')) return Promise.resolve(dnssecResponse('example.com', true));
			return Promise.resolve(createDohResponse([], []));
		}
		if (url.includes('mta-sts.') && url.includes('.well-known')) {
			return Promise.resolve(httpResponse('version: STSv1\nmode: enforce\nmx: *.example.com\nmax_age: 86400'));
		}
		return Promise.resolve({ ...httpResponse('OK'), url });
	});
}

type Finding = { category: string; title: string; severity: string; detail?: string; metadata?: unknown };
type Structured = Record<string, unknown> & {
	findings: Finding[];
	webPosture?: { nonScoring: boolean; results: Array<Record<string, unknown> & { findings: Array<Record<string, unknown>> }> };
};

async function scan(args: Record<string, unknown>, runtimeOptions?: Record<string, unknown>) {
	const { handleToolsCall } = await import('../src/handlers/tools');
	IN_MEMORY_CACHE.clear();
	mockAllChecks();
	const result = await handleToolsCall(
		{ name: 'scan_domain', arguments: { domain: 'example.com', ...args } },
		undefined,
		runtimeOptions as never,
	);
	expect(result.isError).toBeUndefined();
	return { result, structured: result.structuredContent as unknown as Structured };
}

describe('scan_domain structured payload by format', () => {
	it('compact keeps every info finding (without detail) and every non-info finding intact', async () => {
		const full = (await scan({ format: 'full' })).structured;
		const compact = (await scan({ format: 'compact' })).structured;

		expect(full.findings.some((f) => f.severity === 'info')).toBe(true);
		expect(compact.findings).toHaveLength(full.findings.length);
		compact.findings.forEach((f, i) => {
			const original = full.findings[i];
			expect(f.category).toBe(original.category);
			expect(f.title).toBe(original.title);
			expect(f.severity).toBe(original.severity);
			if (f.severity === 'info') {
				expect(Object.keys(f).sort()).toEqual(['category', 'severity', 'title']);
			} else {
				expect(f).toEqual(original);
			}
		});
	});

	it('compact leaves scores, counts and statuses as they were, and says detail was omitted', async () => {
		const full = (await scan({ format: 'full' })).structured;
		const compact = (await scan({ format: 'compact' })).structured;

		const { findings: _f, webPosture: _w, compactDetailOmitted, timestamp: _t, ...compactRest } = compact;
		const { findings: _f2, webPosture: _w2, timestamp: _t2, ...fullRest } = full;
		expect(compactRest).toEqual(fullRest);
		expect(compactDetailOmitted).toMatch(/format "full"/);
	});

	it('compact turns webPosture into a per-category summary', async () => {
		const full = (await scan({ format: 'full' })).structured;
		const compact = (await scan({ format: 'compact' })).structured;

		expect(full.webPosture).toBeDefined();
		expect(compact.webPosture?.nonScoring).toBe(true);
		expect(compact.webPosture?.results).toHaveLength(full.webPosture!.results.length);
		compact.webPosture!.results.forEach((r, i) => {
			expect(Object.keys(r).sort()).toEqual(['category', 'findings', 'passed', 'score']);
			expect(r.category).toBe(full.webPosture!.results[i].category);
			const nonInfo = (full.webPosture!.results[i].findings as Finding[]).filter((f) => f.severity !== 'info');
			expect(r.findings).toEqual(nonInfo.map((f) => ({ title: f.title, severity: f.severity })));
		});
	});

	it('compact is measurably smaller than full', async () => {
		const full = JSON.stringify((await scan({ format: 'full' })).structured);
		const compact = JSON.stringify((await scan({ format: 'compact' })).structured);
		expect(compact.length).toBeLessThan(full.length);
	});

	it('full has no compact marker and keeps detail on every finding', async () => {
		const { result, structured } = await scan({ format: 'full' }, { clientType: 'claude_code' });
		expect(structured).not.toHaveProperty('compactDetailOmitted');
		expect(structured.findings.every((f) => typeof f.detail === 'string')).toBe(true);
		expect(structured.webPosture!.results.some((r) => r.findings.length > 0 && 'detail' in r.findings[0])).toBe(true);
		// the backward-compat comment carries the same untrimmed findings
		const embedded = result.content[1].text.match(/<!-- STRUCTURED_RESULT\n(.*)\nSTRUCTURED_RESULT -->/s);
		const embeddedPayload = JSON.parse(embedded![1]) as Structured;
		expect(embeddedPayload).not.toHaveProperty('compactDetailOmitted');
		expect(embeddedPayload.findings).toEqual(structured.findings);
	});

	it('a caller with no client type (the internal door) resolves to the untrimmed payload', async () => {
		const { structured } = await scan({});
		expect(structured).not.toHaveProperty('compactDetailOmitted');
		expect(structured.findings.every((f) => typeof f.detail === 'string')).toBe(true);
	});
});
