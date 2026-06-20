// SPDX-License-Identifier: BUSL-1.1
import { describe, it, expect, vi, afterEach } from 'vitest';

afterEach(() => vi.restoreAllMocks());

async function fresh() {
	return import('../src/lib/tls-probe-binding');
}

function bindingReturning(body: unknown, status = 200) {
	return {
		fetch: vi.fn(async () => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })),
	};
}

// ---------------------------------------------------------------------------
// callTlsProbe
// ---------------------------------------------------------------------------
describe('callTlsProbe', () => {
	it('returns null when the binding is undefined (fail-soft)', async () => {
		const { callTlsProbe } = await fresh();
		const out = await callTlsProbe(undefined, 'tok', 'example.com');
		expect(out).toBeNull();
	});

	it('forwards host + port=443 in query and a Bearer token header', async () => {
		const { callTlsProbe } = await fresh();
		const binding = bindingReturning({ reachable: true, minVersion: 'TLS1.2', maxVersion: 'TLS1.3' });
		await callTlsProbe(binding, 'secret-tok', 'example.com');
		const [url, init] = binding.fetch.mock.calls[0];
		expect(String(url)).toContain('host=example.com');
		expect(String(url)).toContain('port=443');
		expect((init as RequestInit).headers).toMatchObject({ Authorization: 'Bearer secret-tok' });
	});

	it('returns null on a non-ok response (503)', async () => {
		const { callTlsProbe } = await fresh();
		const binding = bindingReturning({ error: 'server error' }, 503);
		const out = await callTlsProbe(binding, 'tok', 'example.com');
		expect(out).toBeNull();
	});

	it('returns null on 404 (NOT benign, unlike recon)', async () => {
		const { callTlsProbe } = await fresh();
		const binding = bindingReturning({ error: 'not found' }, 404);
		const out = await callTlsProbe(binding, 'tok', 'example.com');
		expect(out).toBeNull();
	});

	it('returns null when the body is a JSON array (not an object)', async () => {
		const { callTlsProbe } = await fresh();
		const binding = {
			fetch: vi.fn(async () => new Response(JSON.stringify([1, 2, 3]), { status: 200, headers: { 'Content-Type': 'application/json' } })),
		};
		const out = await callTlsProbe(binding, 'tok', 'example.com');
		expect(out).toBeNull();
	});

	it('returns a parsed result for a valid body', async () => {
		const { callTlsProbe } = await fresh();
		const binding = bindingReturning({ reachable: true, minVersion: 'TLS1.2', maxVersion: 'TLS1.3' });
		const out = await callTlsProbe(binding, 'tok', 'example.com');
		expect(out).not.toBeNull();
		expect(out?.minVersion).toBe('TLS1.2');
	});

	it('returns null when binding.fetch throws (fail-soft)', async () => {
		const { callTlsProbe } = await fresh();
		const binding = {
			fetch: vi.fn(async () => {
				throw new Error('network failure');
			}),
		};
		const out = await callTlsProbe(binding, 'tok', 'example.com');
		expect(out).toBeNull();
	});
});

// ---------------------------------------------------------------------------
// F1: binding-degradation telemetry (present-but-failing branches only)
// ---------------------------------------------------------------------------
describe('callTlsProbe degradation telemetry', () => {
	it('emits binding_5xx (sink + warn log) on a present-but-503 response', async () => {
		const { callTlsProbe } = await fresh();
		const sink = vi.fn();
		const warn = vi.spyOn(console, 'log').mockImplementation(() => {});
		const binding = bindingReturning({ error: 'server error' }, 503);
		const out = await callTlsProbe(binding, 'tok', 'example.com', { telemetry: sink });
		expect(out).toBeNull();
		expect(sink).toHaveBeenCalledWith({ degradationType: 'binding_5xx', component: 'tls_probe', domain: 'example.com' });
		const logged = warn.mock.calls.map((c) => String(c[0])).join('\n');
		expect(logged).toContain('binding_degradation');
		expect(logged).toContain('tls_probe');
	});

	it('emits binding_5xx on a 404 (NOT benign for the probe, unlike recon)', async () => {
		const { callTlsProbe } = await fresh();
		const sink = vi.fn();
		vi.spyOn(console, 'log').mockImplementation(() => {});
		const binding = bindingReturning({ error: 'not found' }, 404);
		const out = await callTlsProbe(binding, 'tok', 'example.com', { telemetry: sink });
		expect(out).toBeNull();
		expect(sink).toHaveBeenCalledWith({ degradationType: 'binding_5xx', component: 'tls_probe', domain: 'example.com' });
	});

	it('stays SILENT (no sink, no degradation log) when the binding is absent', async () => {
		const { callTlsProbe } = await fresh();
		const sink = vi.fn();
		const warn = vi.spyOn(console, 'log').mockImplementation(() => {});
		const out = await callTlsProbe(undefined, 'tok', 'example.com', { telemetry: sink });
		expect(out).toBeNull();
		expect(sink).not.toHaveBeenCalled();
		expect(warn.mock.calls.map((c) => String(c[0])).join('\n')).not.toContain('binding_degradation');
	});

	it('emits binding_timeout when the fetch aborts with a TimeoutError', async () => {
		const { callTlsProbe } = await fresh();
		const sink = vi.fn();
		vi.spyOn(console, 'log').mockImplementation(() => {});
		const binding = {
			fetch: vi.fn(async () => {
				const e = new Error('timed out');
				e.name = 'TimeoutError';
				throw e;
			}),
		};
		const out = await callTlsProbe(binding, 'tok', 'example.com', { telemetry: sink });
		expect(out).toBeNull();
		expect(sink).toHaveBeenCalledWith({ degradationType: 'binding_timeout', component: 'tls_probe', domain: 'example.com' });
	});

	it('emits binding_unavailable on a generic network throw', async () => {
		const { callTlsProbe } = await fresh();
		const sink = vi.fn();
		vi.spyOn(console, 'log').mockImplementation(() => {});
		const binding = {
			fetch: vi.fn(async () => {
				throw new Error('network failure');
			}),
		};
		const out = await callTlsProbe(binding, 'tok', 'example.com', { telemetry: sink });
		expect(out).toBeNull();
		expect(sink).toHaveBeenCalledWith({ degradationType: 'binding_unavailable', component: 'tls_probe', domain: 'example.com' });
	});

	it('does not throw if the sink itself throws (fail-soft contract preserved)', async () => {
		const { callTlsProbe } = await fresh();
		vi.spyOn(console, 'log').mockImplementation(() => {});
		const sink = vi.fn(() => {
			throw new Error('sink boom');
		});
		const binding = bindingReturning({ error: 'x' }, 500);
		const out = await callTlsProbe(binding, 'tok', 'example.com', { telemetry: sink });
		expect(out).toBeNull();
	});
});

// ---------------------------------------------------------------------------
// mergeTlsFinding — pure unit tests
// ---------------------------------------------------------------------------
describe('mergeTlsFinding', () => {
	async function makeBase() {
		const { buildCheckResult, createFinding } = await import('../src/lib/scoring');
		return buildCheckResult('ssl', [createFinding('ssl', 'HTTPS ok', 'info', 'ok')]);
	}

	it('adds exactly one HIGH finding for minVersion TLS1.1', async () => {
		const { mergeTlsFinding } = await fresh();
		const base = await makeBase();
		const merged = mergeTlsFinding(base, { reachable: true, minVersion: 'TLS1.1' });
		expect(merged.findings.length).toBe(base.findings.length + 1);
		const high = merged.findings.find((f) => f.severity === 'high');
		expect(high).toBeDefined();
		expect(high?.metadata?.tlsProbeEnriched).toBe(true);
	});

	it('adds exactly one HIGH finding for minVersion TLS1.0', async () => {
		const { mergeTlsFinding } = await fresh();
		const base = await makeBase();
		const merged = mergeTlsFinding(base, { reachable: true, minVersion: 'TLS1.0' });
		expect(merged.findings.length).toBe(base.findings.length + 1);
		expect(merged.findings.some((f) => f.severity === 'high')).toBe(true);
	});

	it('leaves findings unchanged for minVersion TLS1.2', async () => {
		const { mergeTlsFinding } = await fresh();
		const base = await makeBase();
		const merged = mergeTlsFinding(base, { reachable: true, minVersion: 'TLS1.2' });
		expect(merged.findings.length).toBe(base.findings.length);
		expect(merged.findings.some((f) => f.severity === 'high')).toBe(false);
	});

	it('leaves findings unchanged for minVersion TLS1.3', async () => {
		const { mergeTlsFinding } = await fresh();
		const base = await makeBase();
		const merged = mergeTlsFinding(base, { reachable: true, minVersion: 'TLS1.3' });
		expect(merged.findings.length).toBe(base.findings.length);
		expect(merged.findings.some((f) => f.severity === 'high')).toBe(false);
	});

	it('leaves result unchanged when reachable is false (inconclusive)', async () => {
		const { mergeTlsFinding } = await fresh();
		const base = await makeBase();
		const merged = mergeTlsFinding(base, { reachable: false, minVersion: 'TLS1.0' });
		expect(merged.findings.length).toBe(base.findings.length);
		expect(merged.findings.some((f) => f.severity === 'high')).toBe(false);
	});

	it('leaves result unchanged when error is present, even if minVersion looks weak', async () => {
		const { mergeTlsFinding } = await fresh();
		const base = await makeBase();
		const merged = mergeTlsFinding(base, { error: 'handshake failed', minVersion: 'TLS1.0' });
		expect(merged.findings.length).toBe(base.findings.length);
		expect(merged.findings.some((f) => f.severity === 'high')).toBe(false);
	});

	it('leaves result unchanged when minVersion is absent', async () => {
		const { mergeTlsFinding } = await fresh();
		const base = await makeBase();
		const merged = mergeTlsFinding(base, {});
		expect(merged.findings.length).toBe(base.findings.length);
	});

	it('treats TLSv1.0 (with prefix) as weak (high finding added)', async () => {
		const { mergeTlsFinding } = await fresh();
		const base = await makeBase();
		const merged = mergeTlsFinding(base, { reachable: true, minVersion: 'TLSv1.0' });
		expect(merged.findings.length).toBe(base.findings.length + 1);
		expect(merged.findings.some((f) => f.severity === 'high')).toBe(true);
	});

	it('treats tls1.1 (lowercase) as weak (high finding added)', async () => {
		const { mergeTlsFinding } = await fresh();
		const base = await makeBase();
		const merged = mergeTlsFinding(base, { reachable: true, minVersion: 'tls1.1' });
		expect(merged.findings.length).toBe(base.findings.length + 1);
		expect(merged.findings.some((f) => f.severity === 'high')).toBe(true);
	});

	it('preserves controlPresent when adding a weak-TLS finding (profile detection depends on it)', async () => {
		const { mergeTlsFinding } = await fresh();
		const { buildCheckResult, createFinding } = await import('../src/lib/scoring');
		// HTTPS-reachable → controlPresent: true. The weak-TLS rebuild must NOT drop it,
		// or detectDomainContext sees sslPass=false and can misclassify the profile.
		const base = buildCheckResult('ssl', [createFinding('ssl', 'HTTPS ok', 'info', 'ok')], true);
		expect(base.controlPresent).toBe(true);
		const merged = mergeTlsFinding(base, { reachable: true, minVersion: 'TLS1.0' });
		expect(merged.controlPresent).toBe(true);
	});
});
