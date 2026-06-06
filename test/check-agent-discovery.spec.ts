// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';
import { RecordType } from '../src/lib/dns-types';

const { restore } = setupFetchMock();

afterEach(() => restore());

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Build a DoH response carrying SVCB (type 64) agent-discovery records.
 * `data` strings are in the draft-02 presentation form the tool parses, e.g.
 * `1 chat.example.com. alpn="mcp" key65400="https://example.com/cap.json"`.
 * (Real DoH rendering of unknown SvcParamKeys should be pinned by a dedicated
 * case once confirmed against live Cloudflare/Google DoH.)
 */
function svcbResponse(name: string, records: string[], ad = false) {
	return createDohResponse(
		[{ name, type: RecordType.SVCB }],
		records.map((data) => ({ name, type: RecordType.SVCB, TTL: 300, data })),
		{ ad },
	);
}

/** A mock capability-document HTTP Response with a real streaming body (.body.getReader()). */
function capDoc(body: string, status = 200) {
	return new Response(body, { status });
}

/** SHA-256 hex of a string (Workers runtime crypto.subtle — same path as the tool). */
async function sha256Hex(body: string): Promise<string> {
	const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(body));
	return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * SHA-256 as base64url with padding stripped — the canonical cap-sha256
 * encoding dns-aid publishes (cap_fetcher.py: urlsafe_b64encode(...).rstrip('=')).
 */
async function sha256B64Url(body: string): Promise<string> {
	const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(body));
	const view = new Uint8Array(digest);
	return btoa(String.fromCharCode(...view)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Route fetch: DoH queries (carry a ?name= param) resolve from `svcb` keyed by
 * owner name; everything else is treated as a capability-document fetch
 * resolved from `capDocs` keyed by URL.
 */
function mockAgentFetch(opts: { svcb: Record<string, string[]>; ad?: boolean; adByName?: Record<string, boolean>; capDocs?: Record<string, Response> }) {
	globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
		const href = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
		const u = new URL(href);
		const name = u.searchParams.get('name');
		if (name !== null) {
			const ad = opts.adByName?.[name] ?? opts.ad ?? false;
			return Promise.resolve(svcbResponse(name, opts.svcb[name] ?? [], ad));
		}
		return Promise.resolve(opts.capDocs?.[href] ?? capDoc('not found', 404));
	});
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('checkAgentDiscovery', () => {
	async function run(domain = 'example.com', options?: { protocol?: 'a2a' | 'mcp' | 'https'; name?: string; verifyCap?: boolean }) {
		const { checkAgentDiscovery } = await import('../src/tools/check-agent-discovery');
		return checkAgentDiscovery(domain, options);
	}

	it('reports an info finding and does not flag when no records are published', async () => {
		mockAgentFetch({ svcb: {} });
		const result = await run();

		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].severity).toBe('info');
		expect(result.findings[0].title).toMatch(/No BANDAID agent-discovery records/i);
		expect(result.passed).toBe(true);
	});

	it('flags HIGH when discovery records exist but the zone is NOT DNSSEC-anchored', async () => {
		mockAgentFetch({
			svcb: { '_agents.example.com': ['1 chat.example.com. alpn="mcp"'] },
			ad: false,
		});
		const result = await run();

		const high = result.findings.find((f) => f.severity === 'high');
		expect(high).toBeDefined();
		expect(high!.title).toMatch(/not DNSSEC-anchored/i);
		expect(high!.metadata?.adFlag).toBe(false);
	});

	it('does not flag DNSSEC when records ARE anchored (AD flag set)', async () => {
		mockAgentFetch({
			svcb: { '_agents.example.com': ['1 chat.example.com. alpn="mcp"'] },
			ad: true,
		});
		const result = await run();

		expect(result.findings.some((f) => f.severity === 'high')).toBe(false);
		expect(result.findings.some((f) => /are DNSSEC-anchored/i.test(f.title))).toBe(true);
	});

	it('flags LOW when a capability document is declared without a cap-sha256 pin (no fetch)', async () => {
		mockAgentFetch({
			svcb: { '_agents.example.com': ['1 chat.example.com. alpn="mcp" key65400="https://example.com/cap.json"'] },
			ad: true,
		});
		const result = await run();

		const low = result.findings.find((f) => /not integrity-pinned/i.test(f.title));
		expect(low).toBeDefined();
		expect(low!.severity).toBe('low');
	});

	it('verifies cap integrity (verifyCap=true) — info when the base64url pin matches (dns-aid canonical encoding)', async () => {
		const body = '{"capabilities":["mcp"]}';
		const pin = await sha256B64Url(body);
		mockAgentFetch({
			svcb: { '_agents.example.com': [`1 chat.example.com. alpn="mcp" key65400="https://example.com/cap.json" key65401="${pin}"`] },
			ad: true,
			capDocs: { 'https://example.com/cap.json': capDoc(body) },
		});
		const result = await run('example.com', { verifyCap: true });

		expect(result.findings.some((f) => /integrity verified/i.test(f.title) && f.severity === 'info')).toBe(true);
		expect(result.findings.some((f) => f.severity === 'high')).toBe(false);
	});

	it('verifies cap integrity (verifyCap=true) — also accepts a hex pin (defensive fallback)', async () => {
		const body = '{"capabilities":["mcp"]}';
		const pin = await sha256Hex(body);
		mockAgentFetch({
			svcb: { '_agents.example.com': [`1 chat.example.com. alpn="mcp" key65400="https://example.com/cap.json" key65401="${pin}"`] },
			ad: true,
			capDocs: { 'https://example.com/cap.json': capDoc(body) },
		});
		const result = await run('example.com', { verifyCap: true });

		expect(result.findings.some((f) => /integrity verified/i.test(f.title) && f.severity === 'info')).toBe(true);
		expect(result.findings.some((f) => f.severity === 'high')).toBe(false);
	});

	it('verifies cap integrity (verifyCap=true) — HIGH when the document hash does not match the pin', async () => {
		mockAgentFetch({
			svcb: { '_agents.example.com': ['1 chat.example.com. alpn="mcp" key65400="https://example.com/cap.json" key65401="deadbeefdeadbeef"'] },
			ad: true,
			capDocs: { 'https://example.com/cap.json': capDoc('{"capabilities":["tampered"]}') },
		});
		const result = await run('example.com', { verifyCap: true });

		const high = result.findings.find((f) => /hash mismatch/i.test(f.title));
		expect(high).toBeDefined();
		expect(high!.severity).toBe('high');
	});

	it('bounds the body read — flags LOW when the cap document exceeds the size cap', async () => {
		const huge = 'x'.repeat(256 * 1024 + 1); // > CAP_MAX_BYTES (256 KB)
		mockAgentFetch({
			svcb: { '_agents.example.com': ['1 chat.example.com. alpn="mcp" key65400="https://example.com/cap.json" key65401="abc123"'] },
			ad: true,
			capDocs: { 'https://example.com/cap.json': capDoc(huge) },
		});
		const result = await run('example.com', { verifyCap: true });

		const low = result.findings.find((f) => /too large/i.test(f.title));
		expect(low).toBeDefined();
		expect(low!.severity).toBe('low');
		// Not verified, not a false mismatch.
		expect(result.findings.some((f) => f.severity === 'high')).toBe(false);
	});

	it('flags LOW (descriptor_unreachable) when verifyCap=true but the cap document 404s', async () => {
		mockAgentFetch({
			svcb: { '_agents.example.com': ['1 chat.example.com. alpn="mcp" key65400="https://example.com/cap.json" key65401="abc123"'] },
			ad: true,
			capDocs: { 'https://example.com/cap.json': capDoc('nope', 404) },
		});
		const result = await run('example.com', { verifyCap: true });

		const low = result.findings.find((f) => /unreachable/i.test(f.title));
		expect(low).toBeDefined();
		expect(low!.severity).toBe('low');
	});

	it('reads the AD signal from the response that carried records, not a fixed name', async () => {
		// Records live under the protocol index (AD set there); the zone-apex
		// _agents name is empty and unsigned. The DNSSEC verdict must follow the
		// record-carrying response → anchored, no HIGH finding.
		mockAgentFetch({
			svcb: { '_index._mcp._agents.example.com': ['1 chat.example.com. alpn="mcp"'] },
			adByName: { '_index._mcp._agents.example.com': true, '_agents.example.com': false },
		});
		const result = await run('example.com', { protocol: 'mcp' });

		expect(result.findings.some((f) => /are DNSSEC-anchored/i.test(f.title))).toBe(true);
		expect(result.findings.some((f) => f.severity === 'high')).toBe(false);
	});

	it('scopes discovery to the per-protocol index when protocol is given', async () => {
		mockAgentFetch({
			svcb: { '_index._mcp._agents.example.com': ['1 chat.example.com. alpn="mcp"'] },
			ad: true,
		});
		const result = await run('example.com', { protocol: 'mcp' });

		expect(result.findings.some((f) => /record\(s\) published/i.test(f.title))).toBe(true);
		expect(result.findings.some((f) => /No BANDAID/i.test(f.title))).toBe(false);
	});
});
