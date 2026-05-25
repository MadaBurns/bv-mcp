// SPDX-License-Identifier: BUSL-1.1
import { describe, it, expect, vi, afterEach } from 'vitest';

afterEach(() => vi.restoreAllMocks());

async function fresh() {
	return import('../src/lib/recon-binding');
}

function bindingReturning(body: unknown, status = 200) {
	return {
		fetch: vi.fn(async () =>
			new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } }),
		),
	};
}

describe('callReconScan', () => {
	it('returns null when the binding is undefined (fail-soft)', async () => {
		const { callReconScan } = await fresh();
		const out = await callReconScan(undefined, 'tok', 'MALICIOUS_ASN', { domain: 'example.com' });
		expect(out).toBeNull();
	});

	it('forwards type + target as query params and a bearer token', async () => {
		const { callReconScan } = await fresh();
		const binding = bindingReturning({ checkType: 'CT_LOOKALIKE', status: 'info', details: 'ok' });
		await callReconScan(binding, 'secret-tok', 'CT_LOOKALIKE', { domain: 'example.com' });
		const [url, init] = binding.fetch.mock.calls[0];
		expect(String(url)).toContain('/osint/check?type=CT_LOOKALIKE');
		expect(String(url)).toContain('domain=example.com');
		expect((init as RequestInit).headers).toMatchObject({ Authorization: 'Bearer secret-tok' });
	});

	it('returns null when the response is not ok', async () => {
		const { callReconScan } = await fresh();
		const binding = bindingReturning({ error: 'nope' }, 503);
		const out = await callReconScan(binding, 'tok', 'MALICIOUS_ASN', { domain: 'x.com' });
		expect(out).toBeNull();
	});

	it('returns a benign info result on 404 (no threat-feed entry — not a failure)', async () => {
		const { callReconScan } = await fresh();
		const binding = bindingReturning({ error: 'not found' }, 404);
		const out = await callReconScan(binding, 'tok', 'REALTIME_THREAT_FEED', { domain: 'clean.example' });
		expect(out).not.toBeNull();
		expect(out?.status).toBe('info');
	});

	it('returns null when the body is not an object (non-parseable shape)', async () => {
		const { callReconScan } = await fresh();
		// A JSON array is not an object — Zod .object() rejects it
		const binding = { fetch: vi.fn(async () => new Response(JSON.stringify([1, 2, 3]), { status: 200, headers: { 'Content-Type': 'application/json' } })) };
		const out = await callReconScan(binding, 'tok', 'MALICIOUS_ASN', { domain: 'x.com' });
		expect(out).toBeNull();
	});

	it('parses a valid DNSCheckResult body', async () => {
		const { callReconScan } = await fresh();
		const binding = bindingReturning({ checkType: 'REALTIME_THREAT_FEED', status: 'info', details: 'Threat intelligence lookup returned status 404.', records: [], metadata: { domain: 'wikipedia.org', breachesFound: [] } });
		const out = await callReconScan(binding, 'tok', 'MALICIOUS_ASN', { domain: 'x.com' });
		expect(out?.status).toBe('info');
	});
});
