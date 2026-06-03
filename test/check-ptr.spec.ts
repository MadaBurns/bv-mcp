// SPDX-License-Identifier: BUSL-1.1
import { afterEach, describe, expect, it, vi } from 'vitest';
import { setupFetchMock } from './helpers/dns-mock';
import { resetProviderSignatureState } from '../src/lib/provider-signatures';

const fetchMock = setupFetchMock();

afterEach(() => {
	fetchMock.restore();
	resetProviderSignatureState();
	vi.restoreAllMocks();
});

/**
 * Route DoH GETs by `name`+`type`. `records` keys are `"<TYPE> <name>"` (name without
 * trailing dot); values are the `data` strings for that answer set. Unmatched → empty.
 */
function routeDns(records: Record<string, string[]>) {
	const TYPE_CODE: Record<string, number> = { A: 1, MX: 15, PTR: 12, TXT: 16, NS: 2 };
	globalThis.fetch = vi.fn().mockImplementation((input: string | Request) => {
		const raw = typeof input === 'string' ? input : (input as Request).url;
		const url = new URL(raw);
		const name = (url.searchParams.get('name') ?? '').replace(/\.$/, '');
		const type = url.searchParams.get('type') ?? '';
		const data = records[`${type} ${name}`] ?? [];
		const answers = data.map((d) => ({ name, type: TYPE_CODE[type] ?? 0, TTL: 300, data: d }));
		return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({
			Status: 0, TC: false, RD: true, RA: true, AD: false, CD: false,
			Question: [{ name, type: TYPE_CODE[type] ?? 0 }], Answer: answers,
		}) } as unknown as Response);
	});
}

// Deterministic DNS: avoid secondary-resolver confirmation in unit tests.
const DNS = { skipSecondaryConfirmation: true } as const;

describe('checkPtr', () => {
	it('returns info (not applicable) when the domain has no MX records', async () => {
		routeDns({}); // no MX
		const { checkPtr } = await import('../src/tools/check-ptr');
		const result = await checkPtr('example.com', undefined, DNS);
		expect(result.category).toBe('ptr');
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].severity).toBe('info');
		expect(result.findings[0].title).toMatch(/not applicable/i);
		expect(result.passed).toBe(true);
	});

	it('credits managed providers (Google) as controlPresent without forward-confirming', async () => {
		routeDns({ 'MX example.com': ['10 aspmx.l.google.com.'] });
		const { checkPtr } = await import('../src/tools/check-ptr');
		const result = await checkPtr('example.com', undefined, DNS);
		expect(result.findings[0].severity).toBe('info');
		expect(result.findings[0].title).toMatch(/managed by mail provider/i);
		expect(result.controlPresent).toBe(true);
	});

	it('passes when all MX IPs forward-confirm (FCrDNS OK)', async () => {
		routeDns({
			'MX example.com': ['10 mail.example.com.'],
			'A mail.example.com': ['192.0.2.10'],
			'PTR 10.2.0.192.in-addr.arpa': ['mail.example.com.'],
			// forward-confirm reuses the 'A mail.example.com' key above (router strips the trailing dot).
		});
		const { checkPtr } = await import('../src/tools/check-ptr');
		const result = await checkPtr('example.com', undefined, DNS);
		expect(result.findings[0].severity).toBe('info');
		expect(result.findings[0].title).toMatch(/forward-confirmed/i);
		expect(result.controlPresent).toBe(true);
		expect(result.passed).toBe(true);
	});

	it('flags low when a PTR exists but fails forward-confirmation (mismatch)', async () => {
		routeDns({
			'MX example.com': ['10 mail.example.com.'],
			'A mail.example.com': ['192.0.2.10'],
			'PTR 10.2.0.192.in-addr.arpa': ['wrong-host.example.net.'],
			'A wrong-host.example.net': ['198.51.100.5'], // does NOT contain 192.0.2.10
		});
		const { checkPtr } = await import('../src/tools/check-ptr');
		const result = await checkPtr('example.com', undefined, DNS);
		const low = result.findings.find((f) => f.severity === 'low');
		expect(low).toBeDefined();
		expect(low!.title).toMatch(/misconfigured/i);
	});

	it('reports info (no penalty) when PTR is missing entirely', async () => {
		routeDns({
			'MX example.com': ['10 mail.example.com.'],
			'A mail.example.com': ['192.0.2.10'],
			// no PTR answer
		});
		const { checkPtr } = await import('../src/tools/check-ptr');
		const result = await checkPtr('example.com', undefined, DNS);
		expect(result.findings.every((f) => f.severity === 'info')).toBe(true);
		expect(result.passed).toBe(true);
		expect(result.controlPresent).not.toBe(true);
	});

	it('flags low for partial coverage (one IP confirms, one missing)', async () => {
		routeDns({
			'MX example.com': ['10 mail.example.com.'],
			'A mail.example.com': ['192.0.2.10', '192.0.2.20'],
			'PTR 10.2.0.192.in-addr.arpa': ['mail.example.com.'],
			// 192.0.2.20 → PTR 20.2.0.192.in-addr.arpa has no answer
		});
		const { checkPtr } = await import('../src/tools/check-ptr');
		const result = await checkPtr('example.com', undefined, DNS);
		const low = result.findings.find((f) => f.severity === 'low');
		expect(low).toBeDefined();
		expect(low!.title).toMatch(/partial/i);
		expect(result.controlPresent).toBe(true);
	});

	it('returns a high missingControl finding on DNS failure (excluded from score)', async () => {
		// Real timeouts surface as a DOMException AbortError; the transport rethrows as
		// DnsQueryError("DNS query timed out after Nms"). A plain Error takes the generic
		// branch ("DNS query failed: ...") — so errorKind is asserted loosely.
		globalThis.fetch = vi.fn().mockRejectedValue(new DOMException('The operation timed out', 'AbortError'));
		const { checkPtr } = await import('../src/tools/check-ptr');
		const result = await checkPtr('example.com', undefined, { retries: 0, skipSecondaryConfirmation: true });
		expect(result.findings[0].severity).toBe('high');
		expect(result.findings[0].metadata?.missingControl).toBe(true);
		expect(['timeout', 'dns_error']).toContain(result.findings[0].metadata?.errorKind);
	});
});
