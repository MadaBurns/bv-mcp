// SPDX-License-Identifier: BUSL-1.1

/**
 * Unit tests for src/tenants/alerts/webhook.ts.
 *
 * Webhook delivery is the last layer between the producer and the operator's
 * chat client; this is where fail-soft behaviour matters most. All tests use
 * the injected `fetchFn` seam — global fetch is never touched.
 */

import { describe, it, expect, vi } from 'vitest';
import { sendTenantAlert, type TenantAlertEnv } from '../../../src/tenants/alerts/webhook';
import type { TenantCycleAlert } from '../../../src/schemas/tenant-alerts';

const validPayload: TenantCycleAlert = {
	type: 'tenant_cycle_diff',
	emitted_at: 1_715_000_000_000,
	super_tenant_id: 'super-acme',
	sub_tenant_id: 'sub-prod',
	current_cycle_id: 'cyc-current',
	baseline_cycle_id: 'cyc-prior',
	totals: {
		domains_scanned: 1,
		deltas: 1,
		by_severity: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
	},
	highlights: [
		{
			domain: 'example.com',
			category: 'dmarc',
			severity: 'high',
			title: 'DMARC weakened',
			delta: 'severity_changed',
			previous_severity: 'medium',
			cycle_id: 'cyc-current',
			scan_at: 1_715_000_000_000,
		},
	],
	webhook_url_hash: 'a1b2c3d4e5f60718',
};

const env: TenantAlertEnv = { ALERT_WEBHOOK_URL: 'https://hooks.slack.com/services/T0/B0/secret' };

function okResponse(status = 200): Response {
	return new Response('', { status });
}

describe('sendTenantAlert', () => {
	it('happy path → delivered:true with the response status', async () => {
		const fetchFn = vi.fn().mockResolvedValue(okResponse(200));
		const out = await sendTenantAlert(validPayload, env, { fetchFn });
		expect(out).toEqual({ delivered: true, status: 200 });
		expect(fetchFn).toHaveBeenCalledTimes(1);
		const [, init] = fetchFn.mock.calls[0];
		expect(init.method).toBe('POST');
		expect(init.headers['Content-Type']).toBe('application/json');
		expect(init.headers['User-Agent']).toMatch(/^bv-mcp\/\d/);
	});

	it('ALERT_WEBHOOK_URL unset → delivered:false (fail-open)', async () => {
		const fetchFn = vi.fn();
		const out = await sendTenantAlert(validPayload, {}, { fetchFn });
		expect(out).toEqual({ delivered: false });
		expect(fetchFn).not.toHaveBeenCalled();
	});

	it('5xx then 5xx → retried once, then delivered:false', async () => {
		const fetchFn = vi
			.fn()
			.mockResolvedValueOnce(okResponse(503))
			.mockResolvedValueOnce(okResponse(502));
		const sleepFn = vi.fn().mockResolvedValue(undefined);
		const out = await sendTenantAlert(validPayload, env, { fetchFn, sleepFn, retryDelayMs: 5 });
		expect(out).toEqual({ delivered: false, status: 502 });
		expect(fetchFn).toHaveBeenCalledTimes(2);
		expect(sleepFn).toHaveBeenCalledOnce();
	});

	it('5xx then 200 → retry succeeds, delivered:true', async () => {
		const fetchFn = vi
			.fn()
			.mockResolvedValueOnce(okResponse(500))
			.mockResolvedValueOnce(okResponse(200));
		const sleepFn = vi.fn().mockResolvedValue(undefined);
		const out = await sendTenantAlert(validPayload, env, { fetchFn, sleepFn, retryDelayMs: 5 });
		expect(out).toEqual({ delivered: true, status: 200 });
		expect(fetchFn).toHaveBeenCalledTimes(2);
	});

	it('timeout > timeoutMs → delivered:false (no throw)', async () => {
		const fetchFn = vi.fn().mockImplementation(
			() => new Promise<Response>(() => {
				/* never resolves */
			}),
		);
		const out = await sendTenantAlert(validPayload, env, { fetchFn, timeoutMs: 25 });
		expect(out).toEqual({ delivered: false });
	});

	it('network error throw → delivered:false (no rethrow)', async () => {
		const fetchFn = vi.fn().mockRejectedValue(new Error('econnreset'));
		const out = await sendTenantAlert(validPayload, env, { fetchFn });
		expect(out).toEqual({ delivered: false });
	});

	it('4xx → delivered:false WITHOUT retry', async () => {
		const fetchFn = vi.fn().mockResolvedValue(okResponse(404));
		const sleepFn = vi.fn().mockResolvedValue(undefined);
		const out = await sendTenantAlert(validPayload, env, { fetchFn, sleepFn });
		expect(out).toEqual({ delivered: false, status: 404 });
		expect(fetchFn).toHaveBeenCalledTimes(1);
		expect(sleepFn).not.toHaveBeenCalled();
	});

	it('non-https webhook URL → delivered:false (refuses to leak over plaintext)', async () => {
		const fetchFn = vi.fn();
		const httpEnv: TenantAlertEnv = { ALERT_WEBHOOK_URL: 'http://insecure.example.com/hook' };
		const out = await sendTenantAlert(validPayload, httpEnv, { fetchFn });
		expect(out).toEqual({ delivered: false });
		expect(fetchFn).not.toHaveBeenCalled();
	});

	it('throws on invalid producer payload (defensive contract)', async () => {
		const fetchFn = vi.fn();
		const bad = { ...validPayload, webhook_url_hash: 'not-hex' } as TenantCycleAlert;
		await expect(sendTenantAlert(bad, env, { fetchFn })).rejects.toThrow();
		expect(fetchFn).not.toHaveBeenCalled();
	});
});
