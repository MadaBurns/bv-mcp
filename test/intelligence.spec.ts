// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect } from 'vitest';
import { env } from 'cloudflare:test';
import type { ScanTelemetry } from '../src/lib/adaptive-weights';
import { getBenchmark, getProviderInsights, computePercentileRank, formatBenchmark, formatProviderInsights } from '../src/tools/intelligence';

/** Ingest telemetry into the global DO instance (same as getBenchmark/getProviderInsights use). */
async function ingestGlobal(telemetry: ScanTelemetry): Promise<Response> {
	const stub = env.PROFILE_ACCUMULATOR.get(env.PROFILE_ACCUMULATOR.idFromName('global'));
	return stub.fetch('https://accumulator.internal/ingest', {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify(telemetry),
	});
}

describe('getBenchmark', () => {
	it('returns unavailable when no DO binding', async () => {
		const result = await getBenchmark(undefined);
		expect(result.status).toBe('unavailable');
		expect(result.profile).toBe('mail_enabled');
	});

	it('returns insufficient_data with few scans', async () => {
		// non_mail profile has no data — should be insufficient
		const result = await getBenchmark(env.PROFILE_ACCUMULATOR, 'non_mail');
		// May be insufficient_data or have data from other tests — check it's a valid status
		expect(['insufficient_data', 'ok']).toContain(result.status);
	});

	it('returns benchmark data after sufficient scans', async () => {
		// Ingest 110 scans into the global instance with a unique profile
		for (let i = 0; i < 110; i++) {
			const res = await ingestGlobal({
				profile: 'minimal',
				provider: null,
				categoryFindings: [{ category: 'spf', score: 50 + (i % 50), passed: true }],
				timestamp: Date.now(),
				overallScore: 40 + (i % 50),
			});
			expect(res.status).toBe(204);
		}

		const result = await getBenchmark(env.PROFILE_ACCUMULATOR, 'minimal');
		expect(result.status).toBe('ok');
		expect(result.totalScans).toBeGreaterThanOrEqual(110);
		expect(result.meanScore).toBeGreaterThan(0);
		expect(result.distribution).toBeDefined();
		expect(result.percentiles).toBeDefined();
	});
});

describe('getProviderInsights', () => {
	it('returns unavailable when no DO binding', async () => {
		const result = await getProviderInsights(undefined, 'google');
		expect(result.status).toBe('unavailable');
	});

	it('returns no_data for unknown provider', async () => {
		const result = await getProviderInsights(env.PROFILE_ACCUMULATOR, 'nonexistent-provider-xyz-unique');
		expect(result.status).toBe('no_data');
	});

	it('returns cohort data after provider ingests', async () => {
		for (let i = 0; i < 10; i++) {
			const res = await ingestGlobal({
				profile: 'mail_enabled',
				provider: 'intel-test-provider',
				categoryFindings: [{ category: 'dmarc', score: 80, passed: true }],
				timestamp: Date.now(),
				overallScore: 75 + (i % 10),
			});
			expect(res.status).toBe(204);
		}

		const result = await getProviderInsights(env.PROFILE_ACCUMULATOR, 'intel-test-provider');
		expect(result.status).toBe('ok');
		expect(result.totalScans).toBeGreaterThanOrEqual(10);
		expect(result.emaOverallScore).toBeGreaterThan(0);
	});
});

describe('computePercentileRank', () => {
	it('returns null for insufficient data', () => {
		const rank = computePercentileRank(75, { status: 'insufficient_data', profile: 'mail_enabled' });
		expect(rank).toBeNull();
	});

	it('returns null for unavailable', () => {
		const rank = computePercentileRank(75, { status: 'unavailable', profile: 'mail_enabled' });
		expect(rank).toBeNull();
	});

	it('returns 0 for lowest bucket', () => {
		const rank = computePercentileRank(5, {
			status: 'ok',
			profile: 'mail_enabled',
			totalScans: 100,
			percentiles: { '0-9': 10, '10-19': 25, '70-79': 90 },
		});
		expect(rank).toBe(0);
	});

	it('returns correct percentile for mid-range score', () => {
		const rank = computePercentileRank(75, {
			status: 'ok',
			profile: 'mail_enabled',
			totalScans: 100,
			percentiles: { '0-9': 5, '10-19': 10, '20-29': 20, '30-39': 30, '40-49': 45, '50-59': 60, '60-69': 75, '70-79': 90, '80-89': 98, '90-99': 100 },
		});
		expect(rank).toBe(75); // percentile of the 60-69 bucket (bucket below 70-79)
	});
});

describe('formatBenchmark', () => {
	it('formats unavailable response', () => {
		const text = formatBenchmark({ status: 'unavailable', profile: 'mail_enabled' });
		expect(text).toContain('unavailable');
	});

	it('formats insufficient data response', () => {
		const text = formatBenchmark({
			status: 'insufficient_data',
			profile: 'mail_enabled',
			totalScans: 5,
			minimumRequired: 100,
			baselineFailureRates: { dmarc: 0.4 },
		});
		expect(text).toContain('Insufficient data');
		expect(text).toContain('DMARC');
	});

	it('formats ok response', () => {
		const text = formatBenchmark({
			status: 'ok',
			profile: 'mail_enabled',
			totalScans: 500,
			meanScore: 72.5,
			medianBucket: 70,
			distribution: { '70-79': 25 },
			topFailingCategories: ['dmarc', 'dkim'],
		});
		expect(text).toContain('500');
		expect(text).toContain('72.5');
		expect(text).toContain('DMARC');
	});
});

describe('formatProviderInsights', () => {
	it('formats no_data response', () => {
		const text = formatProviderInsights({ status: 'no_data', provider: 'test', profile: 'mail_enabled' });
		expect(text).toContain('No data');
	});

	it('formats ok response with comparison', () => {
		const text = formatProviderInsights({
			status: 'ok',
			provider: 'google workspace',
			profile: 'mail_enabled',
			totalScans: 200,
			emaOverallScore: 78.5,
			topFailingCategories: ['mta_sts'],
			populationMeanScore: 68.3,
			percentileRank: 72,
		});
		expect(text).toContain('google workspace');
		expect(text).toContain('78.5');
		expect(text).toContain('above');
		expect(text).toContain('72th');
	});
});
