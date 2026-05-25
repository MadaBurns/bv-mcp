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
		const binding = bindingReturning({ findings: [] });
		await callReconScan(binding, 'secret-tok', 'CT_LOOKALIKE', { domain: 'example.com' });
		const [url, init] = binding.fetch.mock.calls[0];
		expect(String(url)).toContain('/osint/scan?type=CT_LOOKALIKE');
		expect(String(url)).toContain('domain=example.com');
		expect((init as RequestInit).headers).toMatchObject({ Authorization: 'Bearer secret-tok' });
	});

	it('returns null when the response is not ok', async () => {
		const { callReconScan } = await fresh();
		const binding = bindingReturning({ error: 'nope' }, 503);
		const out = await callReconScan(binding, 'tok', 'MALICIOUS_ASN', { domain: 'x.com' });
		expect(out).toBeNull();
	});

	it('returns null when the body fails schema validation', async () => {
		const { callReconScan } = await fresh();
		const binding = bindingReturning({ unexpected: true });
		const out = await callReconScan(binding, 'tok', 'MALICIOUS_ASN', { domain: 'x.com' });
		expect(out).toBeNull();
	});

	it('parses a valid scan body', async () => {
		const { callReconScan } = await fresh();
		const binding = bindingReturning({ findings: [{ severity: 'high', title: 'Malicious ASN', detail: 'AS9009' }] });
		const out = await callReconScan(binding, 'tok', 'MALICIOUS_ASN', { domain: 'x.com' });
		expect(out?.findings[0]?.severity).toBe('high');
	});
});
