// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import { extractEmbeddedBrandAuditResult, fetchBrandAuditReportWithRetry } from './helpers/brand-audit-report-fetch';
import type { BrandAuditReportEnvelope } from './helpers/mcp-http-client';

const fakeResult = { category: 'brand_discovery', passed: true, score: 100, findings: [] };

describe('brand audit report fetch helper', () => {
	it('extracts the embedded target result from get-report envelopes', () => {
		const envelope = {
			findings: [{ metadata: { summary: true, result: fakeResult } }],
		} as BrandAuditReportEnvelope;

		expect(extractEmbeddedBrandAuditResult(envelope)).toBe(fakeResult);
	});

	it('retries completed envelopes that are missing the embedded result', async () => {
		let calls = 0;
		const waits: number[] = [];
		const report = await fetchBrandAuditReportWithRetry({
			auditId: 'aud-1',
			target: 'example.com',
			attempts: 3,
			delayMs: 25,
			wait: async (ms) => {
				waits.push(ms);
			},
			callTool: async () => {
				calls++;
				return {
					findings: [
						{
							metadata: calls === 1 ? { summary: true, status: 'completed' } : { summary: true, status: 'completed', result: fakeResult },
						},
					],
				} as BrandAuditReportEnvelope;
			},
		});

		expect(calls).toBe(2);
		expect(waits).toEqual([25]);
		expect(report.result).toBe(fakeResult);
	});
});
