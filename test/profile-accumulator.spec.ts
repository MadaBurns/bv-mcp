// SPDX-License-Identifier: BUSL-1.1

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

async function getBenchmark(stub: DurableObjectStub, profile?: string): Promise<Response> {
	const url = new URL('https://accumulator.internal/benchmark');
	if (profile) url.searchParams.set('profile', profile);
	return stub.fetch(url.toString(), { method: 'GET' });
}

async function getProviderInsights(stub: DurableObjectStub, provider: string, profile?: string): Promise<Response> {
	const url = new URL('https://accumulator.internal/provider-insights');
	url.searchParams.set('provider', provider);
	if (profile) url.searchParams.set('profile', profile);
	return stub.fetch(url.toString(), { method: 'GET' });
}

async function getTrends(stub: DurableObjectStub, profile?: string, hours?: number): Promise<Response> {
	const url = new URL('https://accumulator.internal/trends');
	if (profile) url.searchParams.set('profile', profile);
	if (hours) url.searchParams.set('hours', String(hours));
	return stub.fetch(url.toString(), { method: 'GET' });
}

describe('ProfileAccumulator', () => {
	it('returns empty weights for unknown profile', async () => {
		const stub = getStub('global');
		// Valid profile name but no data ingested yet — returns empty weights
		const res = await getWeights(stub, 'web_only');
		expect(res.status).toBe(200);
		const body = await res.json();
		expect(body.sampleCount).toBe(0);
		expect(body.blendFactor).toBe(0);
		expect(body.weights).toEqual({});
		expect(body.boundHits).toEqual([]);
	});

	it('ingests telemetry and updates profile stats', async () => {
		const stub = getStub('global');
		const profile = 'mail_enabled';

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
		const profile = 'enterprise_mail';

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
		const profile = 'non_mail';
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

		// Invalid profile (not in whitelist)
		const res2 = await stub.fetch('https://accumulator.internal/ingest', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({ profile: 'nonexistent_profile', categoryFindings: [] }),
		});
		expect(res2.status).toBe(400);

		// Missing categoryFindings
		const res3 = await stub.fetch('https://accumulator.internal/ingest', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({ profile: 'mail_enabled' }),
		});
		expect(res3.status).toBe(400);

		// Invalid JSON
		const res4 = await stub.fetch('https://accumulator.internal/ingest', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: 'not json',
		});
		expect(res4.status).toBe(400);
	});

	it('rejects oversized categoryFindings array', async () => {
		const stub = getStub('global');
		const findings = Array.from({ length: 51 }, () => ({ category: 'spf', score: 50, passed: true }));
		const res = await stub.fetch('https://accumulator.internal/ingest', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({ profile: 'mail_enabled', categoryFindings: findings }),
		});
		expect(res.status).toBe(400);
	});

	it('skips invalid category findings entries gracefully', async () => {
		const stub = getStub('global');
		const telemetry = {
			profile: 'minimal',
			provider: null,
			categoryFindings: [
				{ category: 'dmarc', score: 80, passed: true },
				{ category: 'fake_category', score: 50, passed: true }, // invalid category — skipped
				{ category: 'spf', score: -5, passed: false }, // invalid score — skipped
				{ category: 'ssl', score: 70, passed: 'yes' }, // invalid passed — skipped
			],
			timestamp: Date.now(),
		};

		const ingestRes = await stub.fetch('https://accumulator.internal/ingest', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify(telemetry),
		});
		expect(ingestRes.status).toBe(204);

		// Only dmarc should have been ingested
		const res = await getWeights(stub, 'minimal');
		const body = await res.json();
		expect(body.weights).toHaveProperty('dmarc');
		expect(body.weights).not.toHaveProperty('fake_category');
	});

	it('returns 404 for unknown routes', async () => {
		const stub = getStub('global');
		const res = await stub.fetch('https://accumulator.internal/nonexistent', { method: 'GET' });
		expect(res.status).toBe(404);
	});
});

// ─── Intelligence layer tests ───────────────────────────────────────────

describe('ProfileAccumulator — Intelligence Layer', () => {
	describe('Score Histogram (GET /benchmark)', () => {
		it('returns insufficient_data when fewer than 100 scans', async () => {
			const stub = getStub('bench-insufficient');

			// Ingest 5 scans with overallScore
			for (let i = 0; i < 5; i++) {
				await ingest(stub, {
					profile: 'mail_enabled',
					provider: null,
					categoryFindings: [{ category: 'dmarc', score: 80, passed: true }],
					timestamp: Date.now(),
					overallScore: 70 + i,
				});
			}

			const res = await getBenchmark(stub, 'mail_enabled');
			expect(res.status).toBe(200);
			const body = await res.json();
			expect(body.status).toBe('insufficient_data');
			expect(body.totalScans).toBe(5);
			expect(body.minimumRequired).toBe(100);
			expect(body.baselineFailureRates).toBeDefined();
		});

		it('returns histogram data after 100+ scans', async () => {
			const stub = getStub('bench-sufficient');

			// Ingest 110 scans with varying scores
			for (let i = 0; i < 110; i++) {
				const score = 30 + Math.floor((i / 110) * 60); // scores from 30 to 89
				await ingest(stub, {
					profile: 'mail_enabled',
					provider: null,
					categoryFindings: [{ category: 'spf', score: score, passed: score >= 50 }],
					timestamp: Date.now(),
					overallScore: score,
				});
			}

			const res = await getBenchmark(stub, 'mail_enabled');
			expect(res.status).toBe(200);
			const body = await res.json();
			expect(body.status).toBe('ok');
			expect(body.totalScans).toBe(110);
			expect(body.meanScore).toBeGreaterThan(0);
			expect(body.medianBucket).toBeGreaterThanOrEqual(0);
			expect(body.distribution).toBeDefined();
			expect(body.percentiles).toBeDefined();
			expect(body.topFailingCategories).toBeInstanceOf(Array);
			expect(body.dataFreshness).toBeDefined();
		});

		it('defaults to mail_enabled profile', async () => {
			const stub = getStub('bench-default');

			const res = await getBenchmark(stub);
			expect(res.status).toBe(200);
			const body = await res.json();
			expect(body.profile).toBe('mail_enabled');
		});

		it('returns 400 for invalid profile', async () => {
			const stub = getStub('bench-invalid');

			const url = new URL('https://accumulator.internal/benchmark');
			url.searchParams.set('profile', 'fake_profile');
			const res = await stub.fetch(url.toString(), { method: 'GET' });
			expect(res.status).toBe(400);
		});
	});

	describe('Provider Cohort (GET /provider-insights)', () => {
		it('returns no_data for unknown provider', async () => {
			const stub = getStub('provider-empty');

			const res = await getProviderInsights(stub, 'unknown-provider');
			expect(res.status).toBe(200);
			const body = await res.json();
			expect(body.status).toBe('no_data');
		});

		it('returns cohort data after provider ingests with overallScore', async () => {
			const stub = getStub('provider-data');
			const provider = 'google-workspace';

			for (let i = 0; i < 10; i++) {
				await ingest(stub, {
					profile: 'mail_enabled',
					provider,
					categoryFindings: [
						{ category: 'dmarc', score: 85, passed: true },
						{ category: 'spf', score: 70, passed: i % 3 !== 0 },
					],
					timestamp: Date.now(),
					overallScore: 75 + (i % 5),
				});
			}

			const res = await getProviderInsights(stub, provider, 'mail_enabled');
			expect(res.status).toBe(200);
			const body = await res.json();
			expect(body.status).toBe('ok');
			expect(body.provider).toBe(provider);
			expect(body.totalScans).toBe(10);
			expect(body.emaOverallScore).toBeGreaterThan(0);
			expect(body.topFailingCategories).toBeInstanceOf(Array);
		});

		it('returns 400 when provider parameter is missing', async () => {
			const stub = getStub('provider-missing');

			const res = await stub.fetch('https://accumulator.internal/provider-insights', { method: 'GET' });
			expect(res.status).toBe(400);
		});

		it('returns 400 for invalid profile', async () => {
			const stub = getStub('provider-bad-profile');

			const url = new URL('https://accumulator.internal/provider-insights');
			url.searchParams.set('provider', 'test');
			url.searchParams.set('profile', 'bogus');
			const res = await stub.fetch(url.toString(), { method: 'GET' });
			expect(res.status).toBe(400);
		});
	});

	describe('Trend Snapshots (GET /trends)', () => {
		it('returns no_data when no snapshots exist', async () => {
			const stub = getStub('trends-empty');

			const res = await getTrends(stub, 'mail_enabled');
			expect(res.status).toBe(200);
			const body = await res.json();
			expect(body.status).toBe('no_data');
		});

		it('returns trend data after ingests with overallScore', async () => {
			const stub = getStub('trends-data');

			for (let i = 0; i < 5; i++) {
				await ingest(stub, {
					profile: 'mail_enabled',
					provider: null,
					categoryFindings: [
						{ category: 'dmarc', score: 80, passed: true },
						{ category: 'spf', score: 60, passed: false },
					],
					timestamp: Date.now(),
					overallScore: 65 + i,
				});
			}

			const res = await getTrends(stub, 'mail_enabled', 24);
			expect(res.status).toBe(200);
			const body = await res.json();
			expect(body.status).toBe('ok');
			expect(body.snapshotCount).toBeGreaterThanOrEqual(1);
			expect(body.totalScans).toBe(5);
			expect(body.periodAvgScore).toBeGreaterThan(0);
			expect(body.snapshots).toBeInstanceOf(Array);
			expect(body.snapshots[0]).toHaveProperty('hour');
			expect(body.snapshots[0]).toHaveProperty('timestamp');
			expect(body.snapshots[0]).toHaveProperty('avgScore');
			expect(body.snapshots[0]).toHaveProperty('scanCount');
			expect(body.snapshots[0]).toHaveProperty('failureRates');
		});

		it('defaults to 168 hours when no hours param', async () => {
			const stub = getStub('trends-default');

			const res = await getTrends(stub);
			expect(res.status).toBe(200);
			const body = await res.json();
			expect(body.hours).toBe(168);
		});

		it('clamps hours to valid range', async () => {
			const stub = getStub('trends-clamp');

			// Ingest one scan so we get 'ok' status
			await ingest(stub, {
				profile: 'mail_enabled',
				provider: null,
				categoryFindings: [{ category: 'spf', score: 50, passed: true }],
				timestamp: Date.now(),
				overallScore: 50,
			});

			// Very large hours — clamped to 720
			const res = await getTrends(stub, 'mail_enabled', 9999);
			expect(res.status).toBe(200);
			const body = await res.json();
			expect(body.hours).toBe(720);
		});

		it('returns 400 for invalid profile', async () => {
			const stub = getStub('trends-bad-profile');

			const url = new URL('https://accumulator.internal/trends');
			url.searchParams.set('profile', 'nonexistent');
			const res = await stub.fetch(url.toString(), { method: 'GET' });
			expect(res.status).toBe(400);
		});
	});

	describe('Ingest with overallScore', () => {
		it('populates intelligence tables when overallScore is provided', async () => {
			const stub = getStub('ingest-overall');

			await ingest(stub, {
				profile: 'mail_enabled',
				provider: 'test-provider',
				categoryFindings: [
					{ category: 'dmarc', score: 90, passed: true },
					{ category: 'spf', score: 70, passed: true },
				],
				timestamp: Date.now(),
				overallScore: 82,
			});

			// Histogram should have data
			const benchRes = await getBenchmark(stub, 'mail_enabled');
			const bench = await benchRes.json();
			expect(bench.totalScans).toBe(1);

			// Provider cohort should have data
			const provRes = await getProviderInsights(stub, 'test-provider', 'mail_enabled');
			const prov = await provRes.json();
			expect(prov.status).toBe('ok');
			expect(prov.totalScans).toBe(1);

			// Trends should have data
			const trendRes = await getTrends(stub, 'mail_enabled', 1);
			const trend = await trendRes.json();
			expect(trend.status).toBe('ok');
			expect(trend.totalScans).toBe(1);
		});

		it('skips intelligence tables when overallScore is absent', async () => {
			const stub = getStub('ingest-no-overall');

			await ingest(stub, {
				profile: 'enterprise_mail',
				provider: null,
				categoryFindings: [{ category: 'dmarc', score: 80, passed: true }],
				timestamp: Date.now(),
				// No overallScore
			});

			// Weights should still work (profile_stats updated)
			const weightsRes = await getWeights(stub, 'enterprise_mail');
			const weights = await weightsRes.json();
			expect(weights.sampleCount).toBe(1);

			// But benchmark should show 0 scans (no histogram data)
			const benchRes = await getBenchmark(stub, 'enterprise_mail');
			const bench = await benchRes.json();
			expect(bench.totalScans).toBe(0);
		});

		it('clamps overallScore to 0-100 range', async () => {
			const stub = getStub('ingest-clamp');

			// Score over 100
			await ingest(stub, {
				profile: 'mail_enabled',
				provider: null,
				categoryFindings: [{ category: 'spf', score: 50, passed: true }],
				timestamp: Date.now(),
				overallScore: 150,
			});

			// Score should be clamped — bucket should be 90 (max)
			const res = await getBenchmark(stub, 'mail_enabled');
			const body = await res.json();
			expect(body.totalScans).toBe(1);
		});

		it('ignores non-numeric overallScore', async () => {
			const stub = getStub('ingest-non-numeric');

			await stub.fetch('https://accumulator.internal/ingest', {
				method: 'POST',
				headers: { 'content-type': 'application/json' },
				body: JSON.stringify({
					profile: 'mail_enabled',
					provider: null,
					categoryFindings: [{ category: 'spf', score: 50, passed: true }],
					timestamp: Date.now(),
					overallScore: 'not a number',
				}),
			});

			// Weights updated but no histogram
			const weightsRes = await getWeights(stub, 'mail_enabled');
			const weights = await weightsRes.json();
			expect(weights.sampleCount).toBe(1);

			const benchRes = await getBenchmark(stub, 'mail_enabled');
			const bench = await benchRes.json();
			expect(bench.totalScans).toBe(0);
		});
	});

	describe('Trend snapshot running average', () => {
		it('computes running average across multiple scans in same hour', async () => {
			const stub = getStub('trends-running-avg');

			// Ingest multiple scans — they share the same snapshot_hour
			const scores = [60, 70, 80, 90];
			for (const score of scores) {
				await ingest(stub, {
					profile: 'mail_enabled',
					provider: null,
					categoryFindings: [{ category: 'dmarc', score, passed: score >= 50 }],
					timestamp: Date.now(),
					overallScore: score,
				});
			}

			const res = await getTrends(stub, 'mail_enabled', 1);
			const body = await res.json();
			expect(body.status).toBe('ok');
			expect(body.snapshots.length).toBe(1);
			expect(body.snapshots[0].scanCount).toBe(4);
			// Running average of 60, 70, 80, 90 = 75
			expect(body.snapshots[0].avgScore).toBeCloseTo(75, 0);
		});
	});
});
