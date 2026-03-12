// SPDX-License-Identifier: MIT

import { describe, expect, it } from 'vitest';
import { env } from 'cloudflare:test';
import type { ScanTelemetry } from '../src/lib/adaptive-weights';

function getStub(name: string): DurableObjectStub {
	return env.PROFILE_ACCUMULATOR.getByName(name);
}

async function ingest(stub: DurableObjectStub, telemetry: ScanTelemetry): Promise<Response> {
	return stub.fetch('https://accumulator.internal/ingest', {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify(telemetry),
	});
}

async function getWeights(stub: DurableObjectStub, profile: string, provider?: string): Promise<Response> {
	const url = new URL('https://accumulator.internal/weights');
	url.searchParams.set('profile', profile);
	if (provider) url.searchParams.set('provider', provider);
	return stub.fetch(url.toString(), { method: 'GET' });
}

describe('ProfileAccumulator', () => {
	it('returns empty weights for unknown profile', async () => {
		const stub = getStub('global');
		const res = await getWeights(stub, 'test_empty_unknown_profile');
		expect(res.status).toBe(200);
		const body = await res.json();
		expect(body.sampleCount).toBe(0);
		expect(body.blendFactor).toBe(0);
		expect(body.weights).toEqual({});
		expect(body.boundHits).toEqual([]);
	});

	it('ingests telemetry and updates profile stats', async () => {
		const stub = getStub('global');
		const profile = 'test_ingest_single';

		const telemetry: ScanTelemetry = {
			profile,
			provider: null,
			categoryFindings: [
				{ category: 'dmarc', score: 80, passed: true },
				{ category: 'spf', score: 60, passed: false },
			],
			timestamp: Date.now(),
		};

		const ingestRes = await ingest(stub, telemetry);
		expect(ingestRes.status).toBe(204);

		const res = await getWeights(stub, profile);
		expect(res.status).toBe(200);
		const body = await res.json();
		expect(body.sampleCount).toBe(1);
		expect(body.blendFactor).toBeGreaterThan(0);
		expect(Object.keys(body.weights).length).toBe(2);
	});

	it('accumulates multiple ingests with EMA', async () => {
		const stub = getStub('global');
		const profile = 'test_ema_accumulation';

		for (let i = 0; i < 5; i++) {
			const telemetry: ScanTelemetry = {
				profile,
				provider: null,
				categoryFindings: [{ category: 'dmarc', score: 70 + i, passed: i % 2 === 0 }],
				timestamp: Date.now(),
			};
			const res = await ingest(stub, telemetry);
			expect(res.status).toBe(204);
		}

		const res = await getWeights(stub, profile);
		expect(res.status).toBe(200);
		const body = await res.json();
		expect(body.sampleCount).toBe(5);
		// blendFactor = min(1.0, 5/200) = 0.025, rounded to 2 decimals = 0.03
		expect(body.blendFactor).toBeCloseTo(Math.min(1.0, 5 / 200), 1);
		expect(body.weights).toHaveProperty('dmarc');
	});

	it('applies provider overlay', async () => {
		const stub = getStub('global');
		const profile = 'test_provider_overlay';
		const provider = 'test-provider-overlay';

		// 10 profile-level ingests with NO provider: always pass (low failure rate)
		for (let i = 0; i < 10; i++) {
			const telemetry: ScanTelemetry = {
				profile,
				provider: null,
				categoryFindings: [{ category: 'dmarc', score: 90, passed: true }],
				timestamp: Date.now(),
			};
			await ingest(stub, telemetry);
		}

		// 10 provider-level ingests: always fail (high failure rate)
		// Note: these also update profile_stats, raising the profile failure EMA
		for (let i = 0; i < 10; i++) {
			const telemetry: ScanTelemetry = {
				profile,
				provider,
				categoryFindings: [{ category: 'dmarc', score: 30, passed: false }],
				timestamp: Date.now(),
			};
			await ingest(stub, telemetry);
		}

		const profileRes = await getWeights(stub, profile);
		const profileBody = await profileRes.json();

		const providerRes = await getWeights(stub, profile, provider);
		const providerBody = await providerRes.json();

		// Provider always-fail has higher failure EMA than profile (mixed pass/fail),
		// so the provider overlay modifier is positive, making provider weight >= profile weight
		expect(providerBody.weights.dmarc).toBeGreaterThanOrEqual(profileBody.weights.dmarc);
	});

	it('returns 400 for missing profile on GET /weights', async () => {
		const stub = getStub('global');
		const res = await stub.fetch('https://accumulator.internal/weights', { method: 'GET' });
		expect(res.status).toBe(400);
	});

	it('returns 400 for invalid ingest payload', async () => {
		const stub = getStub('global');

		// Missing profile
		const res1 = await stub.fetch('https://accumulator.internal/ingest', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({ categoryFindings: [] }),
		});
		expect(res1.status).toBe(400);

		// Missing categoryFindings
		const res2 = await stub.fetch('https://accumulator.internal/ingest', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({ profile: 'test' }),
		});
		expect(res2.status).toBe(400);

		// Invalid JSON
		const res3 = await stub.fetch('https://accumulator.internal/ingest', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: 'not json',
		});
		expect(res3.status).toBe(400);
	});

	it('returns 404 for unknown routes', async () => {
		const stub = getStub('global');
		const res = await stub.fetch('https://accumulator.internal/nonexistent', { method: 'GET' });
		expect(res.status).toBe(404);
	});
});
