// SPDX-License-Identifier: BUSL-1.1
import { describe, it, expect, vi, afterEach } from 'vitest';

afterEach(() => vi.restoreAllMocks());

async function fresh() {
	return import('../src/lib/recon-binding');
}

function bindingReturning(body: unknown, status = 200) {
	return {
		fetch: vi.fn(async () => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })),
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
		const binding = {
			fetch: vi.fn(async () => new Response(JSON.stringify([1, 2, 3]), { status: 200, headers: { 'Content-Type': 'application/json' } })),
		};
		const out = await callReconScan(binding, 'tok', 'MALICIOUS_ASN', { domain: 'x.com' });
		expect(out).toBeNull();
	});

	it('parses a valid DNSCheckResult body', async () => {
		const { callReconScan } = await fresh();
		const binding = bindingReturning({
			checkType: 'REALTIME_THREAT_FEED',
			status: 'info',
			details: 'Threat intelligence lookup returned status 404.',
			records: [],
			metadata: { domain: 'wikipedia.org', breachesFound: [] },
		});
		const out = await callReconScan(binding, 'tok', 'MALICIOUS_ASN', { domain: 'x.com' });
		expect(out?.status).toBe('info');
	});
});

// ---------------------------------------------------------------------------
// F1: binding-degradation telemetry (present-but-failing branches only)
// ---------------------------------------------------------------------------
describe('callReconScan degradation telemetry', () => {
	it('emits binding_5xx (sink + warn log) on a present-but-5xx response', async () => {
		const { callReconScan } = await fresh();
		const sink = vi.fn();
		const warn = vi.spyOn(console, 'log').mockImplementation(() => {});
		const binding = bindingReturning({ error: 'nope' }, 503);
		const out = await callReconScan(binding, 'tok', 'MALICIOUS_ASN', { domain: 'x.com' }, undefined, sink);
		expect(out).toBeNull();
		expect(sink).toHaveBeenCalledWith({ degradationType: 'binding_5xx', component: 'recon', domain: 'x.com' });
		const logged = warn.mock.calls.map((c) => String(c[0])).join('\n');
		expect(logged).toContain('binding_degradation');
		expect(logged).toContain('binding_5xx');
	});

	it('stays SILENT (no sink, no degradation log) when the binding is absent', async () => {
		const { callReconScan } = await fresh();
		const sink = vi.fn();
		const warn = vi.spyOn(console, 'log').mockImplementation(() => {});
		const out = await callReconScan(undefined, 'tok', 'MALICIOUS_ASN', { domain: 'x.com' }, undefined, sink);
		expect(out).toBeNull();
		expect(sink).not.toHaveBeenCalled();
		expect(warn.mock.calls.map((c) => String(c[0])).join('\n')).not.toContain('binding_degradation');
	});

	it('keeps the 404 benign branch SILENT (no degradation)', async () => {
		const { callReconScan } = await fresh();
		const sink = vi.fn();
		const warn = vi.spyOn(console, 'log').mockImplementation(() => {});
		const binding = bindingReturning({ error: 'not found' }, 404);
		const out = await callReconScan(binding, 'tok', 'REALTIME_THREAT_FEED', { domain: 'clean.example' }, undefined, sink);
		expect(out?.status).toBe('info');
		expect(sink).not.toHaveBeenCalled();
		expect(warn.mock.calls.map((c) => String(c[0])).join('\n')).not.toContain('binding_degradation');
	});

	it('emits binding_timeout when the fetch aborts with a TimeoutError', async () => {
		const { callReconScan } = await fresh();
		const sink = vi.fn();
		vi.spyOn(console, 'log').mockImplementation(() => {});
		const binding = {
			fetch: vi.fn(async () => {
				const e = new Error('The operation was aborted due to timeout');
				e.name = 'TimeoutError';
				throw e;
			}),
		};
		const out = await callReconScan(binding, 'tok', 'MALICIOUS_ASN', { domain: 'x.com' }, undefined, sink);
		expect(out).toBeNull();
		expect(sink).toHaveBeenCalledWith({ degradationType: 'binding_timeout', component: 'recon', domain: 'x.com' });
	});

	it('emits binding_unavailable on a generic network throw', async () => {
		const { callReconScan } = await fresh();
		const sink = vi.fn();
		vi.spyOn(console, 'log').mockImplementation(() => {});
		const binding = {
			fetch: vi.fn(async () => {
				throw new Error('connection refused');
			}),
		};
		const out = await callReconScan(binding, 'tok', 'MALICIOUS_ASN', { domain: 'x.com' }, undefined, sink);
		expect(out).toBeNull();
		expect(sink).toHaveBeenCalledWith({ degradationType: 'binding_unavailable', component: 'recon', domain: 'x.com' });
	});

	it('does not throw if the sink itself throws (fail-soft contract preserved)', async () => {
		const { callReconScan } = await fresh();
		vi.spyOn(console, 'log').mockImplementation(() => {});
		const sink = vi.fn(() => {
			throw new Error('sink boom');
		});
		const binding = bindingReturning({ error: 'nope' }, 500);
		const out = await callReconScan(binding, 'tok', 'MALICIOUS_ASN', { domain: 'x.com' }, undefined, sink);
		expect(out).toBeNull();
	});

	it('forwards the sink through reconJson-backed bucket calls on 5xx', async () => {
		const { callReconBucketScanStatus } = await fresh();
		const sink = vi.fn();
		vi.spyOn(console, 'log').mockImplementation(() => {});
		const binding = bindingReturning({ error: 'boom' }, 502);
		const out = await callReconBucketScanStatus(binding, 'tok', 'scan-123', undefined, sink);
		expect(out).toBeNull();
		expect(sink).toHaveBeenCalledWith(expect.objectContaining({ degradationType: 'binding_5xx', component: 'recon' }));
	});
});
