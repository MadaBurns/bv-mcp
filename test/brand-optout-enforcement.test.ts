/**
 * Unit tests for the consumer-side opt-out enforcement filter.
 *
 * Layer: Unit (pure logic, no bindings).
 *
 * The filter is the third defensive layer behind `bv-infrastructure-graph`
 * and `bv-intel-gateway` source-side filters. Even if both upstream layers
 * miss an opted-out apex, bv-mcp must redact it before surfacing.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { __resetOptoutCacheForTests, applyOptoutFilter } from '../src/lib/brand-optout-enforcement';

describe('applyOptoutFilter', () => {
	beforeEach(() => {
		__resetOptoutCacheForTests();
		vi.useRealTimers();
	});

	afterEach(() => {
		vi.useRealTimers();
		__resetOptoutCacheForTests();
	});

	it('filters opted-out domains from a candidate list', async () => {
		const candidates = ['ok.com', 'opted-out.com', 'also-ok.com'];
		const mockOptoutFetcher = vi.fn().mockResolvedValue(new Set(['opted-out.com']));
		const result = await applyOptoutFilter(candidates, mockOptoutFetcher);
		expect(result.filtered).toEqual(['ok.com', 'also-ok.com']);
		expect(result.redactedCount).toBe(1);
	});

	it('caches the opt-out list for 5 minutes', async () => {
		const mockOptoutFetcher = vi.fn().mockResolvedValue(new Set(['x.com']));
		await applyOptoutFilter(['x.com'], mockOptoutFetcher);
		await applyOptoutFilter(['y.com'], mockOptoutFetcher);
		expect(mockOptoutFetcher).toHaveBeenCalledTimes(1);
	});

	it('refetches the opt-out list after the 5-minute TTL expires', async () => {
		vi.useFakeTimers();
		vi.setSystemTime(new Date('2026-01-01T00:00:00Z'));

		const mockOptoutFetcher = vi
			.fn<() => Promise<Set<string>>>()
			.mockResolvedValueOnce(new Set(['first.com']))
			.mockResolvedValueOnce(new Set(['second.com']));

		const first = await applyOptoutFilter(['first.com', 'keep.com'], mockOptoutFetcher);
		expect(first.filtered).toEqual(['keep.com']);
		expect(mockOptoutFetcher).toHaveBeenCalledTimes(1);

		// Advance past the 5-minute TTL.
		vi.setSystemTime(new Date('2026-01-01T00:05:01Z'));

		const second = await applyOptoutFilter(['first.com', 'second.com'], mockOptoutFetcher);
		// `first.com` is no longer opted out; `second.com` now is.
		expect(second.filtered).toEqual(['first.com']);
		expect(mockOptoutFetcher).toHaveBeenCalledTimes(2);
	});

	it('returns candidates unchanged when the opt-out set is empty', async () => {
		const candidates = ['a.com', 'b.com', 'c.com'];
		const mockOptoutFetcher = vi.fn().mockResolvedValue(new Set<string>());
		const result = await applyOptoutFilter(candidates, mockOptoutFetcher);
		expect(result.filtered).toEqual(candidates);
		expect(result.redactedCount).toBe(0);
	});

	it('returns an empty result when candidates is empty', async () => {
		const mockOptoutFetcher = vi.fn().mockResolvedValue(new Set(['anything.com']));
		const result = await applyOptoutFilter([], mockOptoutFetcher);
		expect(result.filtered).toEqual([]);
		expect(result.redactedCount).toBe(0);
	});

	it('matches the apex case-insensitively and after trimming whitespace', async () => {
		const candidates = ['Opted-Out.COM', '  also-out.com  ', 'kept.com'];
		const mockOptoutFetcher = vi.fn().mockResolvedValue(new Set(['opted-out.com', 'ALSO-OUT.com']));
		const result = await applyOptoutFilter(candidates, mockOptoutFetcher);
		// Filtered output preserves the original candidate strings for non-redacted entries.
		expect(result.filtered).toEqual(['kept.com']);
		expect(result.redactedCount).toBe(2);
	});

	it('normalises FQDN trailing-dot drift symmetrically', async () => {
		// Candidate has trailing dot, opt-out set does not
		const a = await applyOptoutFilter(['opted-out.com.', 'ok.com'], async () => new Set(['opted-out.com']));
		expect(a.filtered).toEqual(['ok.com']);
		expect(a.redactedCount).toBe(1);

		__resetOptoutCacheForTests();

		// Opt-out set has trailing dot, candidate does not
		const b = await applyOptoutFilter(['opted-out.com', 'ok.com'], async () => new Set(['opted-out.com.']));
		expect(b.filtered).toEqual(['ok.com']);
		expect(b.redactedCount).toBe(1);
	});
});
