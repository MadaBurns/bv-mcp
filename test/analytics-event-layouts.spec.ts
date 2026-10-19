// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, vi } from 'vitest';
import { createAnalyticsClient, hashDomain } from '../src/lib/analytics';

// Analytics Engine consumers read blobs/doubles POSITIONALLY (see bv-mcp-operations, analytics blob
// layouts). These specs pin the complete layout of the two event types whose builders were split into
// field-derivation helpers, so a reorder or rename of any single slot fails here.

function mockDataset() {
	return { writeDataPoint: vi.fn() };
}

describe('emitDohPrimarySummary (doh_primary layout)', () => {
	it('writes outcome, domain fingerprint and context blobs plus the four counters in order', () => {
		const ds = mockDataset();
		createAnalyticsClient(ds).emitDohPrimarySummary({
			attempts: 12,
			http5xx: 1,
			network: 2,
			timeout: 3,
			domain: 'example.com',
			country: 'NZ',
			clientType: 'claude_code',
			authTier: 'agent',
		});
		expect(ds.writeDataPoint).toHaveBeenCalledOnce();
		expect(ds.writeDataPoint).toHaveBeenCalledWith({
			indexes: ['doh_primary'],
			blobs: ['failures', hashDomain('example.com'), 'NZ', 'claude_code', 'agent'],
			doubles: [12, 1, 2, 3],
		});
	});

	it('reports a clean scan with no domain and defaults every absent context dimension', () => {
		const ds = mockDataset();
		createAnalyticsClient(ds).emitDohPrimarySummary({ attempts: 7, http5xx: 0, network: 0, timeout: 0 });
		expect(ds.writeDataPoint).toHaveBeenCalledWith({
			indexes: ['doh_primary'],
			blobs: ['clean', 'none', 'unknown', 'unknown', 'anon'],
			doubles: [7, 0, 0, 0],
		});
	});

	it.each([
		['http5xx', { http5xx: 1, network: 0, timeout: 0 }],
		['network', { http5xx: 0, network: 1, timeout: 0 }],
		['timeout', { http5xx: 0, network: 0, timeout: 1 }],
	])('flags failures when only %s is non-zero', (_label, counts) => {
		const ds = mockDataset();
		createAnalyticsClient(ds).emitDohPrimarySummary({ attempts: 1, ...counts });
		expect(ds.writeDataPoint.mock.calls[0][0].blobs[0]).toBe('failures');
	});

	it('clamps non-finite and negative counters to 0', () => {
		const ds = mockDataset();
		createAnalyticsClient(ds).emitDohPrimarySummary({ attempts: Number.NaN, http5xx: -3, network: 0, timeout: 0 });
		const point = ds.writeDataPoint.mock.calls[0][0];
		expect(point.doubles).toEqual([0, 0, 0, 0]);
		// The failure-class decision uses the raw (unclamped) sum: -3 is not > 0.
		expect(point.blobs[0]).toBe('clean');
	});

	it('is a no-op on the disabled client', () => {
		expect(() => createAnalyticsClient().emitDohPrimarySummary({ attempts: 1, http5xx: 0, network: 0, timeout: 0 })).not.toThrow();
	});
});

describe('emitToolEvent (tool_call layout)', () => {
	it('writes all sixteen blobs and four doubles in positional order', () => {
		const ds = mockDataset();
		createAnalyticsClient(ds).emitToolEvent({
			toolName: 'Check_SPF',
			status: 'pass',
			durationMs: 120,
			domain: 'example.com',
			isError: false,
			score: 85,
			cacheStatus: 'hit',
			priorTool: 'check_dmarc',
			outcomeReason: 'completed',
			unitsAttempted: 5,
			unitsCompleted: 4,
			country: 'NZ',
			clientType: 'claude_code',
			authTier: 'agent',
			keyHash: 'k_1234',
			ipHash: 'i_5678',
			colo: 'AKL',
			region: ' Auckland ',
			city: 'Auckland',
			asn: 9500,
		});
		expect(ds.writeDataPoint).toHaveBeenCalledWith({
			indexes: ['tool_call'],
			blobs: [
				'check_spf', // 1 toolName (normalized)
				'pass', // 2 status
				'ok', // 3 isError
				hashDomain('example.com'), // 4 domain fingerprint
				'NZ', // 5 country
				'claude_code', // 6 clientType
				'agent', // 7 authTier
				'hit', // 8 cacheStatus
				'k_1234', // 9 keyHash
				'i_5678', // 10 ipHash
				'AKL', // 11 colo
				'check_dmarc', // 12 priorTool
				'auckland', // 13 region (normalized)
				'auckland', // 14 city
				'9500', // 15 asn
				'completed', // 16 outcomeReason
			],
			doubles: [120, 85, 5, 4],
		});
	});

	it('defaults every optional dimension when only the required fields are present', () => {
		const ds = mockDataset();
		createAnalyticsClient(ds).emitToolEvent({ toolName: 'scan_domain', status: 'unknown', durationMs: 5, isError: false });
		expect(ds.writeDataPoint).toHaveBeenCalledWith({
			indexes: ['tool_call'],
			blobs: [
				'scan_domain',
				'unknown',
				'ok',
				'none',
				'unknown',
				'unknown',
				'anon',
				'n/a',
				'none',
				'none',
				'unknown',
				'unknown',
				'unknown',
				'unknown',
				'unknown',
				'completed',
			],
			doubles: [5, 0, 0, 0],
		});
	});

	it('derives outcomeReason internal_error for an errored call without an explicit reason', () => {
		const ds = mockDataset();
		createAnalyticsClient(ds).emitToolEvent({ toolName: 'x', status: 'error', durationMs: 1, isError: true });
		const blobs = ds.writeDataPoint.mock.calls[0][0].blobs;
		expect(blobs[2]).toBe('error');
		expect(blobs[15]).toBe('internal_error');
	});

	it('prefers an explicit outcomeReason over the isError default', () => {
		const ds = mockDataset();
		createAnalyticsClient(ds).emitToolEvent({
			toolName: 'x',
			status: 'error',
			durationMs: 1,
			isError: true,
			outcomeReason: 'scan_timeout',
		});
		expect(ds.writeDataPoint.mock.calls[0][0].blobs[15]).toBe('scan_timeout');
	});

	it('stringifies a zero asn rather than treating it as absent', () => {
		const ds = mockDataset();
		createAnalyticsClient(ds).emitToolEvent({ toolName: 'x', status: 'pass', durationMs: 1, isError: false, asn: 0 });
		expect(ds.writeDataPoint.mock.calls[0][0].blobs[14]).toBe('0');
	});

	it('clamps negative and non-finite doubles to 0', () => {
		const ds = mockDataset();
		createAnalyticsClient(ds).emitToolEvent({
			toolName: 'x',
			status: 'pass',
			durationMs: -1,
			isError: false,
			score: Number.NaN,
			unitsAttempted: -2,
			unitsCompleted: Number.POSITIVE_INFINITY,
		});
		expect(ds.writeDataPoint.mock.calls[0][0].doubles).toEqual([0, 0, 0, 0]);
	});
});
