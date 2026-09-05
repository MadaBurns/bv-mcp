// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it, vi } from 'vitest';

const STRONG_KEY = 'smtp-starttls-probe-key-32-bytes-minimum';
const OBSERVED_AT = '2026-09-05T00:00:00.000Z';

function bindingReturning(body: unknown, status = 200) {
	return {
		fetch: vi.fn(
			async (_input: RequestInfo | URL, _init?: RequestInit) =>
				new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } }),
		),
	};
}

describe('fail-soft SMTP probe binding seam', () => {
	it('does not call an absent binding or send a weak capability', async () => {
		const { callSmtpStarttlsProbe } = await import('../src/lib/smtp-probe-binding');
		const binding = bindingReturning({});
		expect(await callSmtpStarttlsProbe(undefined, STRONG_KEY, 'example.com', { now: () => OBSERVED_AT })).toMatchObject({
			status: 'not-assessed',
			reason: 'probe_unprovisioned',
		});
		expect(await callSmtpStarttlsProbe(binding, 'short', 'example.com', { now: () => OBSERVED_AT })).toMatchObject({
			status: 'not-assessed',
			reason: 'probe_unprovisioned',
		});
		expect(binding.fetch).not.toHaveBeenCalled();
	});

	it('uses only the fixed service-binding endpoint and a domain-only request body', async () => {
		const { callSmtpStarttlsProbe } = await import('../src/lib/smtp-probe-binding');
		const body = {
			schemaVersion: '1.0',
			probe: 'smtp_starttls',
			domain: 'example.com',
			status: 'not-applicable',
			outcome: 'null_mx',
			observedAt: OBSERVED_AT,
			nonScoring: true,
			targets: [],
			reason: 'null_mx',
		};
		const binding = bindingReturning(body);
		expect(await callSmtpStarttlsProbe(binding, STRONG_KEY, 'example.com')).toEqual(body);
		const [url, init] = binding.fetch.mock.calls[0]!;
		expect(String(url)).toBe('https://bv-smtp-starttls-probe/v1/probe');
		expect(init).toMatchObject({ method: 'POST', redirect: 'manual', body: JSON.stringify({ domain: 'example.com' }) });
		expect((init as RequestInit).headers).toMatchObject({ Authorization: `Bearer ${STRONG_KEY}` });
	});

	it.each([
		['non-ok', bindingReturning({}, 503)],
		['malformed', bindingReturning({ status: 'measured', transcript: ['raw'] })],
		[
			'wrong-domain',
			bindingReturning({
				schemaVersion: '1.0',
				probe: 'smtp_starttls',
				domain: 'other.example',
				status: 'not-applicable',
				outcome: 'null_mx',
				observedAt: OBSERVED_AT,
				nonScoring: true,
				targets: [],
				reason: 'null_mx',
			}),
		],
	] as const)('returns explicit not-assessed for a %s response', async (_label, binding) => {
		const { callSmtpStarttlsProbe } = await import('../src/lib/smtp-probe-binding');
		const result = await callSmtpStarttlsProbe(binding, STRONG_KEY, 'example.com', { now: () => OBSERVED_AT });
		expect(result.status).toBe('not-assessed');
		expect(result.outcome).toBe('not_assessed');
	});

	it('returns explicit not-assessed when the binding throws', async () => {
		const { callSmtpStarttlsProbe } = await import('../src/lib/smtp-probe-binding');
		const binding = { fetch: vi.fn(async () => Promise.reject(new Error('offline'))) };
		const result = await callSmtpStarttlsProbe(binding, STRONG_KEY, 'example.com', { now: () => OBSERVED_AT });
		expect(result).toMatchObject({ status: 'not-assessed', reason: 'probe_failed', nonScoring: true });
	});
});

describe('unregistered SMTP beta wrapper', () => {
	it('returns invalid-domain without consulting a binding', async () => {
		const { inspectSmtpStarttls } = await import('../src/tools/inspect-smtp-starttls');
		const binding = bindingReturning({});
		const result = await inspectSmtpStarttls('127.0.0.1', { probeBinding: binding, probeAuthToken: STRONG_KEY, now: () => OBSERVED_AT });
		expect(result).toMatchObject({ status: 'not-assessed', reason: 'invalid_domain', nonScoring: true });
		expect(binding.fetch).not.toHaveBeenCalled();
	});
});
